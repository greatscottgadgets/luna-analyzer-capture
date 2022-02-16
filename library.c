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

struct capture* convert_capture(const char *filename)
{
	// Allocate new capture
	struct capture *cap = malloc(sizeof(struct capture));
	cap->num_packets = 0;

	// Metadata struct reused for each packet
	struct packet pkt;

	// Data offset starts at zero
	pkt.data_offset = 0;

	// Buffer for packet data
	uint8_t buf[0x10000];

	// Open input file
	FILE* input_file = fopen(filename, "r");

	// File for packets
	FILE* packet_file = fdopen(memfd_create("luna_packet", 0), "r+");

	// File for data
	FILE* data_file = fdopen(memfd_create("luna_data", 0), "r+");

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

		// Increment packet count.
		cap->num_packets++;
	}

	// Flush buffered writes.
	fflush(packet_file);
	fflush(data_file);

	// Map packets
	int packet_fd = fileno(packet_file);
	size_t packet_bytes = cap->num_packets * sizeof(struct packet);
	cap->packets = mmap(NULL, packet_bytes, PROT_READ, MAP_SHARED, packet_fd, 0);

	// Map data
	int data_fd = fileno(data_file);
	size_t data_bytes = pkt.data_offset;
	cap->data = mmap(NULL, data_bytes, PROT_READ, MAP_SHARED, data_fd, 0);

	return cap;
}
