#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>

#include "library.h"

struct capture* load_capture(void)
{
	// Allocate new capture
	struct capture *cap = malloc(sizeof(struct capture));

	// File for packet metadata
	FILE* metadata_file = fopen("luna_metadata.dat", "r");

	// Get packet count
	fseek(metadata_file, 0, SEEK_END);
	long metadata_bytes = ftell(metadata_file);
	cap->num_packets = metadata_bytes / sizeof(struct packet);

	// Map packet metadata
	int metadata_fd = fileno(metadata_file);
	cap->packets = mmap(NULL, metadata_bytes, PROT_READ, MAP_SHARED, metadata_fd, 0);

	// File for data
	FILE* data_file = fopen("luna_data.dat", "r");

	// Get data size 
	fseek(data_file, 0, SEEK_END);
	long data_bytes = ftell(data_file);

	// Map data
	int data_fd = fileno(data_file);
	cap->data = mmap(NULL, data_bytes, PROT_READ, MAP_SHARED, data_fd, 0);

	return cap;
}
