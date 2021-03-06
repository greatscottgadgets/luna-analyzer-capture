#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/mman.h>

#include "library.h"

#define MAX_DEVICES 128
#define MAX_ENDPOINTS 16

// A virtual file used for capture data.
struct virtual_file {
	// Filename
	char *name;
	// Pointer to count that should be increased when items are written.
	uint64_t *count_ptr;
	// Size of an item.
	size_t item_size;
	// File descriptor.
	int fd;
	// Buffered stream.
	FILE *file;
};

// Per-endpoint state.
struct endpoint_state {
	// The current transfer on this endpoint.
	struct transfer current_transfer;
	// Output stream for transfers on this endpoint.
	struct virtual_file transfers;
	// Output stream for indices of transactions on this endpoint.
	struct virtual_file transaction_ids;
	// Index of this endpoint in the endpoint stream.
	uint16_t endpoint_id;
	// PID that began the last transaction in the current transfer.
	enum pid last;
};

// Transaction decoder state.
struct transaction_state {
	// PID of the first packet in the current transaction.
	enum pid first;
	// PID of the last packet in the current transaction.
	enum pid last;
	// Bus address of the current transaction.
	uint8_t address;
	// Endpoint number of the current transaction.
	uint8_t endpoint_num;
};

// Context structure for shared variables needed during decoding.
struct context {
	// Capture which we are decoding.
	struct capture *capture;
	// Main output streams.
	struct virtual_file events, packets, transactions, endpoints, transfer_index, data;
	// Array of pointers to to per-endpoint states.
	struct endpoint_state *endpoint_states[MAX_DEVICES][MAX_ENDPOINTS];
	// Transaction decoder state.
	struct transaction_state transaction_state;
	// The current transaction on the bus.
	struct transaction current_transaction;
	// The current packet on the bus.
	struct packet current_packet;
};

// Open a virtual file for open-ended capture data.
static inline void file_open(struct virtual_file *file)
{
	file->fd = memfd_create(file->name, 0);
	file->file = fdopen(file->fd, "r+");
}

// Create a new virtual file with a name in the format 'foo_0'.
static inline void file_create(
	struct virtual_file *file,
	const char *name,
	uint16_t index,
	uint64_t *count_ptr,
	size_t item_size)
{
	file->count_ptr = count_ptr;
	file->item_size = item_size;
	// Construct and set filename.
	const char *name_fmt = "%s_%u";
	size_t name_len = snprintf(NULL, 0, name_fmt, name, index) + 1;
	file->name = malloc(name_len);
	snprintf(file->name, name_len, name_fmt, name, index);
	// Open file.
	file_open(file);
}

// Write items to virtual file.
static inline void file_write(struct virtual_file *file, void *src, uint64_t num_items)
{
	fwrite(src, num_items, file->item_size, file->file);
	*file->count_ptr += num_items;
}

// Map completed virtual file into address space.
static inline void * file_map(struct virtual_file *file)
{
	// Flush buffered writes.
	fflush(file->file);
	// Calculate mapping size.
	size_t map_length = *file->count_ptr * file->item_size;
	// Create mapping.
	void *map = mmap(NULL, map_length, PROT_READ, MAP_SHARED, file->fd, 0);
	// Close file.
	fclose(file->file);
	// Return mapping.
	return map;
}

// Time as nanoseconds since Unix epoch (good for next 500 years).
static inline uint64_t nanotime(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

// Create an event in the timeline.
static inline void event_create(struct context *context, enum event_type type)
{
	struct capture *cap = context->capture;
	struct event evt;
	evt.type = type;
	switch (type)
	{
		case PACKET:
			evt.id = cap->num_packets;
			break;
		case TRANSACTION:
			evt.id = cap->num_transactions;
			break;
		case TRANSFER:
			evt.id = cap->num_transfers;
			break;
	}
	file_write(&context->events, &evt, 1);
}

// Get endpoint state for current transaction.
static inline struct endpoint_state *endpoint_state(struct context *context)
{
	struct capture *cap = context->capture;
	uint8_t address = context->transaction_state.address;
	uint8_t endpoint_num = context->transaction_state.endpoint_num;
	struct endpoint_state *ep_state = context->endpoint_states[address][endpoint_num];

	if (ep_state)
		return ep_state;

	// Allocate and store new endpoint state.
	ep_state = malloc(sizeof(struct endpoint_state));
	context->endpoint_states[address][endpoint_num] = ep_state;

	// Initialise endpoint state.
	uint16_t endpoint_id = ep_state->endpoint_id = cap->num_endpoints;
	ep_state->current_transfer.num_transactions = 0;
	ep_state->last = 0;

	// Write a new endpoint entry.
	struct endpoint ep = { .address = address, .endpoint_num = endpoint_num };
	file_write(&context->endpoints, &ep, 1);

	// Reallocate endpoint traffic pointer array to add an entry.
	size_t entry_size = sizeof(struct endpoint_traffic);
	size_t ptr_size = sizeof(struct endpoint_traffic *);
	size_t new_size = cap->num_endpoints * ptr_size;
	cap->endpoint_traffic = realloc(cap->endpoint_traffic, new_size);
	cap->endpoint_traffic[endpoint_id] = malloc(entry_size);
	struct endpoint_traffic *ep_traf = cap->endpoint_traffic[endpoint_id];

	// Initialise endpoint traffic data.
	ep_traf->num_transfers = 0;
	ep_traf->num_transaction_ids = 0;

	// Set up files for endpoint traffic data.
	file_create(&ep_state->transfers,
		"transfers", endpoint_id,
		&ep_traf->num_transfers, sizeof(struct transfer));
	file_create(&ep_state->transaction_ids,
		"transaction_ids", endpoint_id,
		&ep_traf->num_transaction_ids, sizeof(uint64_t));

	return ep_state;
}

// Possible transfer statuses after each new transaction.
enum transfer_status {
	// Transaction begins a new transfer.
	TRANSFER_NEW,
	// Transaction continues the current transfer, with more expected.
	TRANSFER_CONT,
	// Transaction completes the current transfer.
	TRANSFER_DONE,
	// Transaction not valid in any current transfer.
	TRANSFER_INVALID,
};

// Get transfer status based on next transaction for its endpoint.
static inline enum transfer_status
transfer_status(bool control, enum pid last, enum pid next)
{
	// A SETUP transaction on a control endpoint always starts
	// a new control transfer.
	if (control && next == SETUP)
		return TRANSFER_NEW;

	// Otherwise, result depends on last transaction.
	switch (last)
	{
	case NONE:
		// An IN or OUT transaction on a non-control endpoint with
		// no transfer in progress, starts a new bulk transfer.
		switch (next)
		{
		case IN:
		case OUT:
			if (!control)
				return TRANSFER_NEW;
		default:
			break;
		}
		break;
	case SETUP:
		// SETUP stage must be followed by IN or OUT at data
		// stage, which will be followed by the status stage.
		switch (next)
		{
		case IN:
		case OUT:
			return TRANSFER_CONT;
		default:
			break;
		}
		break;
	case IN:
		switch (next)
		{
		case IN:
			// In control transfers, IN at data stage may be repeated.
			// In bulk transfers, IN may be repeated.
			return TRANSFER_CONT;
		case OUT:
			// In control transfers, IN at data stage may be followed
			// by OUT at status stage, completing the transfer.
			if (control)
				return TRANSFER_DONE;
		default:
			break;
		}
		break;
	case OUT:
		switch (next)
		{
		case OUT:
			// In control transfers, OUT at data stage may be repeated.
			// In bulk transfers, OUT may be repeated.
			return TRANSFER_CONT;
		case IN:
			// In control transfers, OUT at data stage may be followed
			// by IN at status stage, completing the transfer.
			if (control)
				return TRANSFER_DONE;
		default:
			break;
		}
		break;
	default:
		break;
	}

	// Any other transaction on the same endpoint is invalid.
	return TRANSFER_INVALID;
}

// Append a transaction to the current transfer.
static inline void transfer_append(struct context *context, bool success)
{
	uint8_t address = context->transaction_state.address;
	uint8_t endpoint_num = context->transaction_state.endpoint_num;
	struct endpoint_state *ep_state = context->endpoint_states[address][endpoint_num];
	struct transfer *xfer = &ep_state->current_transfer;

	uint64_t tran_idx = context->capture->num_transactions;
	file_write(&ep_state->transaction_ids, &tran_idx, 1);
	xfer->num_transactions++;
	if (success)
		ep_state->last = context->transaction_state.first;
}

// Start a new transfer with the current transaction.
static inline void transfer_start(struct context *context)
{
	struct capture *cap = context->capture;
	uint8_t address = context->transaction_state.address;
	uint8_t endpoint_num = context->transaction_state.endpoint_num;
	struct endpoint_state *ep_state = context->endpoint_states[address][endpoint_num];
	struct endpoint_traffic *ep_traf = cap->endpoint_traffic[ep_state->endpoint_id];
	struct transfer *xfer = &ep_state->current_transfer;

	// Write out a transfer index entry.
	struct transfer_index_entry entry = {
		.endpoint_id = ep_state->endpoint_id,
		.transfer_id = ep_traf->num_transfers,
	};
	file_write(&context->transfer_index, &entry, 1);

	// Transaction is first of the new transfer.
	xfer->ep_tran_offset = ep_traf->num_transaction_ids;
	xfer->num_transactions = 0;
	transfer_append(context, true);
}

// End a transfer if it was ongoing.
static inline void transfer_end(struct context *context, struct endpoint_state *ep_state, bool complete)
{
	struct transfer *xfer = &ep_state->current_transfer;
	if (xfer->num_transactions > 0) {
		// A transfer was in progress, write it out.
		xfer->complete = complete;
		file_write(&ep_state->transfers, xfer, 1);
	}

	// No transfer is now in progress.
	xfer->num_transactions = 0;
	ep_state->last = 0;
}

// Update transfer state based on new transaction on its endpoint.
static inline void transfer_update(struct context *context)
{
	struct transaction *tran = &context->current_transaction;
	enum pid transaction_type = context->transaction_state.first;

	// A transaction consisting of consecutive SOF packets
	// is placed in the top level event stream directly rather
	// than being assigned to a transfer.
	if (transaction_type == SOF) {
		event_create(context, TRANSACTION);
		return;
	}

	// Get endpoint state.
	struct endpoint_state *ep_state = endpoint_state(context);

	// Whether this transaction is on the control endpoint.
	uint8_t endpoint_num = context->transaction_state.endpoint_num;
	bool control = (endpoint_num == 0);

	// Check effect of this transaction on the transfer state.
	enum transfer_status status = transfer_status(control, ep_state->last, transaction_type);

	// A transaction is successful if it has three packets and completed with ACK.
	bool success =
		tran->num_packets == 3 &&
		tran->complete &&
		context->transaction_state.last == ACK;

	// If a transfer is in progress, and the transaction would have been valid
	// but was not successful, append it to the transfer without changing state.
	struct transfer *xfer = &ep_state->current_transfer;
	if (xfer->num_transactions > 0 && status != TRANSFER_INVALID && !success)
	{
		transfer_append(context, false);
		return;
	}

	switch (status)
	{
	case TRANSFER_NEW:
		// New transfer. End any previous one as incomplete.
		transfer_end(context, ep_state, false);
		event_create(context, TRANSFER);
		transfer_start(context);
		break;
	case TRANSFER_CONT:
		// Transaction is added to the current transfer.
		transfer_append(context, true);
		break;
	case TRANSFER_DONE:
		// Transaction completes current transfer.
		transfer_append(context, true);
		transfer_end(context, ep_state, true);
		break;
	case TRANSFER_INVALID:
		// Transaction not valid as part of any current transfer.
		transfer_end(context, ep_state, false);
		event_create(context, TRANSACTION);
		break;
	}
}

// Possible transaction statuses after each new packet.
enum transaction_status {
	// Packet begins a new transaction.
	TRANSACTION_NEW,
	// Packet continues the current transaction, with more expected.
	TRANSACTION_CONT,
	// Packet completes the current transaction.
	TRANSACTION_DONE,
	// Packet not valid in any current transaction.
	TRANSACTION_INVALID,
};

// Get transaction status based on next packet
static inline enum transaction_status
transaction_status(enum pid first, enum pid last, enum pid next)
{
	// SETUP, IN and OUT always start a new transaction.
	switch (next)
	{
	case SETUP:
	case IN:
	case OUT:
		return TRANSACTION_NEW;
	default:
		break;
	}

	// Otherwise, result depends on last PID.
	switch (last)
	{
	case NONE:
		// Treat SOF as the start a "transaction" which can
		// consist of multiple consecutive SOF packets during
		// an idle period on the bus.
		if (next == SOF)
			return TRANSACTION_NEW;
		break;
	case SOF:
		// Additional SOFs extend the same transaction, any
		// other PID ends it.
		if (next == SOF)
			return TRANSACTION_CONT;
		break;
	case SETUP:
		// SETUP must be followed by DATA0.
		if (next == DATA0)
			return TRANSACTION_CONT;
		break;
	case IN:
		// IN may be followed by DATA0/1, STALL or NAK.
		switch (next)
		{
		case DATA0:
		case DATA1:
			// Should be followed by ACK.
			return TRANSACTION_CONT;
		case STALL:
		case NAK:
			// Transaction complete - no data.
			return TRANSACTION_DONE;
		default:
			break;
		}
		break;
	case OUT:
		// Must be followed by DATA0/1.
		switch (next)
		{
		case DATA0:
		case DATA1:
			// Should be followed by ACK/NAK/STALL.
			return TRANSACTION_CONT;
		default:
			break;
		}
		break;
	case DATA0:
	case DATA1:
		// What's valid after DATAx depends what came before it.
		switch (first)
		{
		case SETUP:
			// Only SETUP + DATA0 + ACK is valid.
			if (last == DATA0 && next == ACK)
				return TRANSACTION_DONE;
			break;
		case IN:
			// After IN + DATAx, next must be ACK.
			if (next == ACK)
				return TRANSACTION_DONE;
			break;
		case OUT:
			// After OUT + DATAx, next may be ACK/NAK/STALL.
			switch (next)
			{
			case ACK:
			case NAK:
			case STALL:
				return TRANSACTION_DONE;
			default:
				break;
			}
		default:
			break;
		}
		break;
	default:
		break;
	}

	// Any other case is not a valid part of a transaction.
	return TRANSACTION_INVALID;
}

// Start a new transaction with the current packet.
static inline void transaction_start(struct context *context)
{
	struct transaction_state *state = &context->transaction_state;
	struct transaction *tran = &context->current_transaction;
	struct packet *pkt = &context->current_packet;

	tran->first_packet_id = context->capture->num_packets;
	tran->num_packets = 1;
	state->first = pkt->pid;
	state->last = pkt->pid;
	if (pkt->pid != SOF) {
		state->address = pkt->fields.token.address;
		state->endpoint_num = pkt->fields.token.endpoint_num;
	};
}

// Append packet to the current transaction.
static inline void transaction_append(struct context *context)
{
	struct transaction_state *state = &context->transaction_state;
	struct transaction *tran = &context->current_transaction;
	struct packet *pkt = &context->current_packet;

	tran->num_packets++;
	state->last = pkt->pid;
}

// End a transaction if it was ongoing.
static inline void transaction_end(struct context *context, bool complete)
{
	struct transaction_state *state = &context->transaction_state;
	struct transaction *tran = &context->current_transaction;
	if (tran->num_packets > 0) {
		// Don't bother creating a "transaction" for a single SOF.
		if (!(state->first == SOF && tran->num_packets == 1))
		{
			// A transaction was in progress.
			tran->complete = complete;
			// Update transfer state.
			transfer_update(context);
			// Write out transaction.
			file_write(&context->transactions, tran, 1);
		}
	}

	// No transaction is now in progress.
	tran->num_packets = 0;
	state->first = 0;
	state->last = 0;
}

// Update transaction state based on new packet.
static inline void transaction_update(struct context *context)
{
	struct packet *pkt = &context->current_packet;
	struct transaction_state *state = &context->transaction_state;

	switch (transaction_status(state->first, state->last, pkt->pid))
	{
	case TRANSACTION_NEW:
		// New transaction. End any previous one as incomplete.
		transaction_end(context, false);
		transaction_start(context);
		break;
	case TRANSACTION_CONT:
		// Packet is added to the current transaction.
		transaction_append(context);
		break;
	case TRANSACTION_DONE:
		// Packet completes current transaction.
		transaction_append(context);
		transaction_end(context, true);
		break;
	case TRANSACTION_INVALID:
		// Packet not valid as part of any current transaction.
		transaction_end(context, false);
		event_create(context, PACKET);
		break;
	}
}

struct capture* convert_capture(const char *filename)
{
	// Allocate new capture
	struct capture *cap = malloc(sizeof(struct capture));
	memset(cap, 0, sizeof(struct capture));

	// Set up context structure.
	struct context context = {
		.capture = cap,
		.events = {
			"events",
			&cap->num_events,
			sizeof(struct event),
		},
		.packets = {
			"packets",
			&cap->num_packets,
			sizeof(struct packet),
		},
		.transactions = {
			"transactions",
			&cap->num_transactions,
			sizeof(struct transaction),
		},
		.endpoints = {
			"endpoints",
			&cap->num_endpoints,
			sizeof(struct endpoint),
		},
		.transfer_index = {
			"transfer_index",
			&cap->num_transfers,
			sizeof(struct transfer_index_entry),
		},
		.data = {
			"data",
			&cap->data_size,
			sizeof(uint8_t),
		},
		.transaction_state = {
			.first = 0,
			.last = 0,
		},
	};

	// Open virtual files for capture data.
	file_open(&context.events);
	file_open(&context.packets);
	file_open(&context.transactions);
	file_open(&context.endpoints);
	file_open(&context.transfer_index);
	file_open(&context.data);

	// Open input file
	FILE* input_file = fopen(filename, "r");

	while (1)
	{
		struct packet *pkt = &context.current_packet;
		uint8_t buf[0x10000];

		// Read packet length.
		uint16_t len;
		if (fread(&len, 1, sizeof(len), input_file) < sizeof(len))
			break;

		// Generate timestamp.
		pkt->timestamp_ns = nanotime();

		// Convert packet length to host format.
		pkt->length = ntohs(len);

		// Read remaining packet bytes.
		if (fread(buf, 1, pkt->length, input_file) < pkt->length)
			break;

		// Is this a data packet?
		bool pkt_is_data = (buf[0] & PID_TYPE_MASK) == DATA;

		if (pkt_is_data) {
			// Store PID in packet
			pkt->pid = buf[0];
			// Store CRC in packet
			memcpy(&pkt->fields.data.crc, &buf[pkt->length - 2], 2);
			// Store data bytes in separate file, noting offset in packet.
			pkt->data_offset = cap->data_size;
			file_write(&context.data, &buf[1], pkt->length - 3);
		} else {
			// Store all fields in packet
			memcpy(&pkt->pid, buf, pkt->length);
		}

		// Update transaction state.
		transaction_update(&context);

		// Write out packet.
		file_write(&context.packets, pkt, 1);
	}

	// Close input file.
	fclose(input_file);

	// End any ongoing transaction.
	transaction_end(&context, false);

	// Map completed files as capture arrays.
	cap->events = file_map(&context.events);
	cap->packets = file_map(&context.packets);
	cap->transactions = file_map(&context.transactions);
	cap->data = file_map(&context.data);
	cap->endpoints = file_map(&context.endpoints);

	// Deal with per-endpoint data.
	for (int i = 0; i < cap->num_endpoints; i++)
	{
		struct endpoint *ep = &cap->endpoints[i];
		struct endpoint_state *ep_state = context.endpoint_states[ep->address][ep->endpoint_num];
		struct endpoint_traffic *ep_traf = cap->endpoint_traffic[i];

		// End any transfer still ongoing on this endpoint as incomplete.
		transfer_end(&context, ep_state, false);

		// Map completed files as endpoint traffic arrays.
		ep_traf->transfers = file_map(&ep_state->transfers);
		ep_traf->transaction_ids = file_map(&ep_state->transaction_ids);

		// Free memory allocated for this endpoint.
		free(ep_state->transfers.name);
		free(ep_state->transaction_ids.name);
		free(ep_state);
	}

	// Map transfer index last, since we may have added pending transfers.
	cap->transfer_index = file_map(&context.transfer_index);

	return cap;
}

void close_capture(struct capture *cap)
{
	for (int i = 0; i < cap->num_endpoints; i++) {
		struct endpoint_traffic *ep_traf = cap->endpoint_traffic[i];
		munmap(ep_traf->transfers, sizeof(struct transfer) * ep_traf->num_transfers);
		munmap(ep_traf->transaction_ids, sizeof(uint64_t) * ep_traf->num_transaction_ids);
		free(ep_traf);
	}
	munmap(cap->events, sizeof(struct event) * cap->num_events);
	munmap(cap->packets, sizeof(struct packet) * cap->num_packets);
	munmap(cap->transactions, sizeof(struct transaction) * cap->num_transactions);
	munmap(cap->endpoints, sizeof(struct endpoint) * cap->num_endpoints);
	munmap(cap->transfer_index, sizeof(struct transfer_index_entry) * cap->num_transfers);
	munmap(cap->data, cap->data_size);
	free(cap->endpoint_traffic);
	free(cap);
}
