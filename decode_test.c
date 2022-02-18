#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#include "library.h"

int main(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Usage: %s <filename>\n", argv[0]);
		return -1;
	}

	char *filename = argv[1];

	struct capture *capture = convert_capture(filename);

	printf("%s: %lu events, %lu packets, %lu transactions, %lu endpoints, %lu transfers\n",
		filename,
		capture->num_events,
		capture->num_packets,
		capture->num_transactions,
		capture->num_endpoints,
		capture->num_transfers);

	for (int i = 0; i < capture->num_endpoints; i++) {
		struct endpoint *ep = &capture->endpoints[i];
		struct endpoint_traffic *traf = capture->endpoint_traffic[i];
		printf("%u.%u: %lu transfers, %lu transactions\n",
			ep->address, ep->endpoint,
			traf->num_transfers, traf->num_transaction_ids);
	}

	close_capture(capture);

	return 0;
}
