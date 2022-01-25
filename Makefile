DEPS = libusb-1.0
CFLAGS = -Wall $(shell pkg-config --cflags $(DEPS))
LIBS = $(shell pkg-config --libs $(DEPS))

all: capture

%: %.c Makefile
	gcc $(CFLAGS) $< $(LIBS) -o $@
