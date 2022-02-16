DEPS = libusb-1.0 libpcap
CFLAGS = -g -Wall $(shell pkg-config --cflags $(DEPS))
LIBS = $(shell pkg-config --libs $(DEPS))

all: capture luna2pcap library.so

library.so: library.h

%: %.c Makefile
	gcc $(CFLAGS) $< $(LIBS) -o $@

%.so: %.c Makefile
	gcc -shared $(CFLAGS) $< $(LIBS) -o $@
