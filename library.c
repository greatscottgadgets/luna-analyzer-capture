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

// Time as nanoseconds since Unix epoch (good for next 500 years).
static inline uint64_t nanotime(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000 + ts.tv_nsec;
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

// Update transaction state based on last three packets.
static inline enum transaction_status
transaction_update(enum pid first, enum pid last, enum pid next)
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

struct capture* convert_capture(const char *filename)
{
	// Allocate new capture
	struct capture *cap = malloc(sizeof(struct capture));
	cap->num_packets = 0;
	cap->num_transactions = 0;

	// Metadata structs reused for each packet & transaction
	struct packet pkt;
	struct transaction tran;

	// Data offset starts at zero
	pkt.data_offset = 0;

	// Buffer for packet data
	uint8_t buf[0x10000];

	// Open input file
	FILE* input_file = fopen(filename, "r");

	// File for packets
	FILE* packet_file = fdopen(memfd_create("luna_packet", 0), "r+");

	// File for transactions
	FILE* transaction_file = fdopen(memfd_create("luna_transaction", 0), "r+");

	// File for data
	FILE* data_file = fdopen(memfd_create("luna_data", 0), "r+");

	// Used to track transaction state.
	enum pid first = 0;
	enum pid last = 0;

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
			fwrite(&buf[1], 1, pkt.length - 3, data_file);
		} else {
			// Store all fields in packet
			memcpy(&pkt.pid, buf, pkt.length);
		}

		// Write out packet
		fwrite(&pkt, 1, sizeof(pkt), packet_file);

		// If packet contained data, update offset.
		if (pkt_is_data)
			pkt.data_offset += pkt.length - 3;

		// Update transaction state.
		switch (transaction_update(first, last, pkt.pid))
		{
		case TRANSACTION_NEW:
			// New transaction. Check if one was in progress.
			if (tran.num_packets > 0) {
				// A transaction was in progress.
				// Write it out as incomplete.
				tran.complete = false;
				fwrite(&tran, 1, sizeof(tran), transaction_file);
				cap->num_transactions++;
			}
			// Packet is first of the new transaction.
			tran.first_packet_index = cap->num_packets;
			tran.num_packets = 1;
			first = pkt.pid;
			last = pkt.pid;
			break;
		case TRANSACTION_CONT:
			// Packet is added to the current transaction.
			tran.num_packets++;
			last = pkt.pid;
			break;
		case TRANSACTION_DONE:
			// Packet completes current transaction.
			tran.num_packets++;
			tran.complete = true;
			fwrite(&tran, 1, sizeof(tran), transaction_file);
			cap->num_transactions++;
			// No transaction is now in progress.
			tran.num_packets = 0;
			first = 0;
			last = 0;
			break;
		case TRANSACTION_INVALID:
			// Packet not valid as part of any current transaction.
			if (tran.num_packets > 0) {
				// A transaction was in progress.
				// Write it out as incomplete.
				tran.complete = false;
				fwrite(&tran, 1, sizeof(tran), transaction_file);
				cap->num_transactions++;
			}
			// No transaction is now in progress.
			tran.num_packets = 0;
			first = 0;
			last = 0;
			break;
		}

		// Increment packet count.
		cap->num_packets++;

	}

	// Flush buffered writes.
	fflush(packet_file);
	fflush(transaction_file);
	fflush(data_file);

	// Map packets
	int packet_fd = fileno(packet_file);
	size_t packet_bytes = cap->num_packets * sizeof(struct packet);
	cap->packets = mmap(NULL, packet_bytes, PROT_READ, MAP_SHARED, packet_fd, 0);

	// Map transactions
	int transaction_fd = fileno(transaction_file);
	size_t transaction_bytes = cap->num_transactions * sizeof(struct transaction);
	cap->transactions = mmap(NULL, transaction_bytes, PROT_READ, MAP_SHARED, transaction_fd, 0);

	// Map data
	int data_fd = fileno(data_file);
	size_t data_bytes = pkt.data_offset;
	cap->data = mmap(NULL, data_bytes, PROT_READ, MAP_SHARED, data_fd, 0);

	return cap;
}
