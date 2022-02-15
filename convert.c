#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "packet.h"

// Time as nanoseconds since Unix epoch (good for next 500 years).
static inline uint64_t nanotime(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

int main(int argc, char* argv[])
{
	// Metadata struct reused for each packet
	struct packet pkt;

	// Data offset starts at zero
	pkt.data_offset = 0;

	// Buffer for packet data
	uint8_t buf[0x10000];

	// File for packet metadata
	FILE* metadata_file = fopen("luna_metadata.dat", "w");

	// File for packet data
	FILE* data_file = fopen("luna_data.dat", "w");

	while (1)
	{
		// Read packet length.
		uint16_t len;
		if (fread(&len, 1, sizeof(len), stdin) < sizeof(len))
			break;

		// Generate timestamp.
		pkt.timestamp_ns = nanotime();

		// Convert packet length to host format.
		pkt.length = ntohs(len);

		// Read remaining packet bytes.
		if (fread(buf, 1, pkt.length, stdin) < pkt.length)
			break;

		// Is this a data packet?
		bool pkt_is_data = (buf[0] & PID_TYPE_MASK) == DATA;

		if (pkt_is_data) {
			// Store PID in metadata
			pkt.pid = buf[0];
			// Store CRC in metadata
			memcpy(&pkt.fields.data.crc, &buf[pkt.length - 2], 2);
			// Store data bytes in separate file
			fwrite(&buf[1], 1, pkt.length - 3, data_file);
		} else {
			// Store all packet fields as metadata
			memcpy(&pkt.pid, buf, pkt.length);
		}

		// Write out metadata
		fwrite(&pkt, 1, sizeof(pkt), metadata_file);

		// If packet contained data, update offset.
		if (pkt_is_data)
			pkt.data_offset += pkt.length - 3;
	}

	return 0;
}
