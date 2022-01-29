DEPS = libusb-1.0 libpcap
CFLAGS = -g -Wall $(shell pkg-config --cflags $(DEPS))
LIBS = $(shell pkg-config --libs $(DEPS))

all: capture luna2pcap

%: %.c Makefile
	gcc $(CFLAGS) $< $(LIBS) -o $@
