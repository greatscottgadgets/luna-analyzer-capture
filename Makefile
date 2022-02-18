DEPS = libusb-1.0 libpcap
CFLAGS = -g -Wall $(shell pkg-config --cflags $(DEPS))
LIBS = $(shell pkg-config --libs $(DEPS))

all: capture luna2pcap decode_test library.so

library.so: library.h
library.o: library.h

decode_test: decode_test.o library.o
	gcc $(CFLAGS) $^ -o $@

%: %.c Makefile
	gcc $(CFLAGS) $< $(LIBS) -o $@

%.so: %.c Makefile
	gcc -shared $(CFLAGS) $< $(LIBS) -o $@

%.o: %.c Makefile
	gcc -c $(CFLAGS) $< $(LIBS) -o $@
