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

// A virtual file used for capture data.
struct virtual_file {
	const char *name;
	uint64_t *count_ptr;
	size_t item_size;
	int fd;
	FILE *file;
	void *map;
};

// Transfer decoder state.
struct transfer_state {
	enum pid last;
};

// Transaction decoder state.
struct transaction_state {
	enum pid first;
	enum pid last;
	uint8_t address;
	uint8_t endpoint;
};

// Context structure for shared variables needed during decoding.
struct context {
	struct virtual_file packets, transactions, transfers, mappings, data;
	struct transfer_state transfer_state;
	struct transaction_state transaction_state;
};

// Time as nanoseconds since Unix epoch (good for next 500 years).
static inline uint64_t nanotime(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000 + ts.tv_nsec;
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
transfer_status(enum pid last, enum pid next)
{
	// A SETUP transaction starts a new transfer.
	if (next == SETUP)
		return TRANSFER_NEW;

	// Otherwise, result depends on last transaction.
	switch (last)
	{
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
			// IN at data stage may be repeated.
			return TRANSFER_CONT;
		case OUT:
			// IN at data stage may be followed by OUT
			// at status stage, completing the transfer.
			return TRANSFER_DONE;
		default:
			break;
		}
		break;
	case OUT:
		switch (next)
		{
		case OUT:
			// OUT at data stage may be repeated.
			return TRANSFER_CONT;
		case IN:
			// OUT at data stage may be followed by IN
			// at status stage, completing the transfer.
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

// Append a transaction to a transfer.
static inline void transfer_append(
	struct context *context,
	struct capture *cap,
	struct transfer *xfer,
	struct transaction *tran)
{
	uint64_t tran_idx = cap->num_transactions;
	fwrite(&tran_idx, 1, sizeof(uint64_t), context->mappings.file);
	xfer->num_transactions++;
	cap->num_mappings++;
}

// End a transfer if it was ongoing.
static inline void transfer_end(
	struct context *context,
	struct capture *cap,
	struct transfer *xfer,
	bool complete)
{
	if (xfer->num_transactions > 0) {
		// A transfer was in progress, write it out.
		xfer->complete = complete;
		fwrite(xfer, 1, sizeof(struct transfer), context->transfers.file);
		xfer->mapping_offset += xfer->num_transactions;
		cap->num_transfers++;
	}
}

// Update transfer state based on new transaction on its endpoint.
static inline void transfer_update(
	struct context *context,
	struct capture *cap,
	struct transfer *xfer,
	struct transaction *tran)
{
	struct transfer_state *state = &context->transfer_state;
	enum pid transaction_type = context->transaction_state.first;

	// Check effect of this transaction on the transfer state.
	enum transfer_status status = transfer_status(state->last, transaction_type);

	// A transaction is successful if it has three packets and completed with ACK.
	bool success =
		tran->num_packets == 3 &&
		tran->complete &&
		context->transaction_state.last == ACK;

	// If a transfer is in progress, and the transaction would have been valid
	// but was not successful, append it to the transfer without changing state.
	if (xfer->num_transactions > 0 && status != TRANSFER_INVALID && !success)
	{
		transfer_append(context, cap, xfer, tran);
		return;
	}

	switch (transfer_status(state->last, transaction_type))
	{
	case TRANSFER_NEW:
		// New transfer. End any previous one as incomplete.
		transfer_end(context, cap, xfer, false);
		// Transaction is first of the new transfer.
		xfer->num_transactions = 0;
		transfer_append(context, cap, xfer, tran);
		state->last = transaction_type;
		break;
	case TRANSFER_CONT:
		// Transaction is added to the current transfer.
		transfer_append(context, cap, xfer, tran);
		state->last = transaction_type;
		break;
	case TRANSFER_DONE:
		// Transaction completes current transfer.
		transfer_append(context, cap, xfer, tran);
		transfer_end(context, cap, xfer, true);
		// No transfer is now in progress.
		xfer->num_transactions = 0;
		state->last = 0;
		break;
	case TRANSFER_INVALID:
		// Transaction not valid as part of any current transfer.
		transfer_end(context, cap, xfer, false);
		// No transfer is now in progress.
		xfer->num_transactions = 0;
		state->last = 0;
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

// End a transaction if it was ongoing.
static inline void transaction_end(
	struct context *context,
	struct capture *cap,
	struct transfer *xfer,
	struct transaction *tran,
	struct packet *pkt,
	bool complete)
{
	if (tran->num_packets > 0) {
		// A transaction was in progress, write it out.
		tran->complete = complete;
		fwrite(tran, 1, sizeof(struct transaction), context->transactions.file);
		// Update transaction state.
		context->transaction_state.last = pkt->pid;
		// Update transfer state.
		transfer_update(context, cap, xfer, tran);
		cap->num_transactions++;
	}
}

// Update transaction state based on new packet.
static inline void transaction_update(
	struct context *context,
	struct capture *cap,
	struct transfer *xfer,
	struct transaction *tran,
	struct packet *pkt)
{
	struct transaction_state *state = &context->transaction_state;

	switch (transaction_status(state->first, state->last, pkt->pid))
	{
	case TRANSACTION_NEW:
		// New transaction. End any previous one as incomplete.
		transaction_end(context, cap, xfer, tran, pkt, false);
		// Packet is first of the new transaction.
		tran->first_packet_index = cap->num_packets;
		tran->num_packets = 1;
		state->first = pkt->pid;
		state->last = pkt->pid;
		state->address = pkt->fields.token.address;
		state->endpoint = pkt->fields.token.endpoint;
		break;
	case TRANSACTION_CONT:
		// Packet is added to the current transaction.
		tran->num_packets++;
		state->last = pkt->pid;
		break;
	case TRANSACTION_DONE:
		// Packet completes current transaction.
		tran->num_packets++;
		transaction_end(context, cap, xfer, tran, pkt, true);
		// No transaction is now in progress.
		tran->num_packets = 0;
		state->first = 0;
		state->last = 0;
		break;
	case TRANSACTION_INVALID:
		// Packet not valid as part of any current transaction.
		transaction_end(context, cap, xfer, tran, pkt, false);
		// No transaction is now in progress.
		tran->num_packets = 0;
		state->first = 0;
		state->last = 0;
		break;
	}
}

struct capture* convert_capture(const char *filename)
{
	// Allocate new capture
	struct capture *cap = malloc(sizeof(struct capture));
	memset(cap, 0, sizeof(struct capture));

	// Metadata structs reused for each packet, transaction & transfer.
	struct packet pkt;
	struct transaction tran;
	struct transfer xfer;

	// Offsets start at zero
	pkt.data_offset = 0;
	xfer.mapping_offset = 0;

	// Buffer for packet data
	uint8_t buf[0x10000];

	// Open input file
	FILE* input_file = fopen(filename, "r");

	// Set up context structure.
	struct context context = {
		.packets = {"packets", &cap->num_packets, sizeof(pkt)},
		.transactions = {"transactions", &cap->num_transactions, sizeof(tran)},
		.transfers = {"transfers", &cap->num_transfers, sizeof(xfer)},
		.mappings = {"mapping", &cap->num_mappings, sizeof(uint64_t)},
		.data = {"data", &pkt.data_offset, 1},
		.transaction_state = {
			.first = 0,
			.last = 0,
		},
		.transfer_state = {
			.last = 0,
		},
	};

	// Used to iterate over all virtual files
	struct virtual_file *files[] = {
		&context.packets,
		&context.transactions,
		&context.transfers,
		&context.mappings,
		&context.data};
	int num_files = 5;

	// Open all virtual files.
	for (int i = 0; i < num_files; i++) {
		files[i]->fd = memfd_create(files[i]->name, 0);
		files[i]->file = fdopen(files[i]->fd, "r+");
	}

	while (1)
	{
		// Read packet length.
		uint16_t len;
		if (fread(&len, 1, sizeof(len), input_file) < sizeof(len))
			break;

		// Generate timestamp.
		pkt.timestamp_ns = nanotime();

		// Convert packet length to host format.
		pkt.length = ntohs(len);

		// Read remaining packet bytes.
		if (fread(buf, 1, pkt.length, input_file) < pkt.length)
			break;

		// Is this a data packet?
		bool pkt_is_data = (buf[0] & PID_TYPE_MASK) == DATA;

		if (pkt_is_data) {
			// Store PID in packet
			pkt.pid = buf[0];
			// Store CRC in packet
			memcpy(&pkt.fields.data.crc, &buf[pkt.length - 2], 2);
			// Store data bytes in separate file
			fwrite(&buf[1], 1, pkt.length - 3, context.data.file);
		} else {
			// Store all fields in packet
			memcpy(&pkt.pid, buf, pkt.length);
		}

		// Write out packet
		fwrite(&pkt, 1, sizeof(pkt), context.packets.file);

		// If packet contained data, update offset.
		if (pkt_is_data)
			pkt.data_offset += pkt.length - 3;

		// Update transaction state.
		transaction_update(&context, cap, &xfer, &tran, &pkt);

		// Increment packet count.
		cap->num_packets++;
	}

	// Map completed virtual files into address space.
	for (int i = 0; i < num_files; i++)
	{
		// Flush buffered writes.
		fflush(files[i]->file);
		// Calculate mapping size.
		size_t num_bytes = *files[i]->count_ptr * files[i]->item_size;
		// Create mapping.
		files[i]->map = mmap(NULL, num_bytes, PROT_READ, MAP_SHARED, files[i]->fd, 0);
	}

	// Assign mappings to capture.
	cap->packets = context.packets.map;
	cap->transactions = context.transactions.map;
	cap->transfers = context.transfers.map;
	cap->mappings = context.mappings.map;
	cap->data = context.data.map;

	return cap;
}
