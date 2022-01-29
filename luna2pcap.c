#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <sys/time.h>
#include <arpa/inet.h>

#define MAX_PACKET_SIZE 0xFFFF

int main(int argc, char* argv[])
{
	pcap_t *pcap;
	pcap_dumper_t *dump;

	if (!(pcap = pcap_open_dead(DLT_USB_2_0, MAX_PACKET_SIZE)))
		exit(-1);
	
	if (!(dump = pcap_dump_fopen(pcap, stdout)))
		exit(-2);

	while (1)
	{
		uint16_t len;
		struct pcap_pkthdr hdr;
		uint8_t buf[MAX_PACKET_SIZE];

		if (fread(&len, 1, sizeof(len), stdin) < sizeof(len))
			break;

		len = ntohs(len);

		if (fread(buf, 1, len, stdin) < len)
			break;

		if (gettimeofday(&hdr.ts, NULL) != 0)
			exit(-3);

		hdr.caplen = len;
		hdr.len = len;

		pcap_dump((u_char*) dump, &hdr, buf);
	}

	pcap_dump_close(dump);
	pcap_close(pcap);

	exit(0);
}
