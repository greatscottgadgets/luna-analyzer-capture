#include <stdlib.h>
#include <stdio.h>
#include <libusb.h>

#define VID 0x1d50
#define PID 0x615b
#define ENDPOINT 1

#define NUM_TRANSFERS 4
#define TRANSFER_SIZE 256*1024
#define TIMEOUT_MS 100

#define TO_STDERR(fmt, ...) fprintf(stderr, fmt "\n", __VA_ARGS__)

#define CHECK(operation) { \
	int result = operation; \
	if (result != 0) { \
		TO_STDERR("ERROR: %s failed: %s", #operation, \
			libusb_strerror(result)); \
		exit(result); \
	} \
}

#define SET(var, operation) { \
	var = operation; \
	if (var == NULL) { \
		TO_STDERR("ERROR: %s failed", #operation); \
		exit(-1); \
	} \
}	

static libusb_context* usb_context;
static libusb_device_handle* usb_device;
static struct libusb_transfer* usb_transfers[NUM_TRANSFERS];
static uint8_t usb_buffers[NUM_TRANSFERS][TRANSFER_SIZE];

void usb_callback(struct libusb_transfer* transfer)
{
	switch (transfer->status)
	{
		case LIBUSB_TRANSFER_COMPLETED:
		case LIBUSB_TRANSFER_TIMED_OUT:
			// Write received data to stdout.
			fwrite(transfer->buffer,
				transfer->actual_length,
				1, stdout);
			// Resubmit transfer.
			CHECK(libusb_submit_transfer(transfer));
			TO_STDERR("Received %u bytes", transfer->actual_length);
			break;
		default:
			break;
	}
}

int main(int argc, char *argv[])
{
	// Set up libusb context.
	CHECK(libusb_init(&usb_context));

	// Open device.
	SET(usb_device, libusb_open_device_with_vid_pid(usb_context, VID, PID));

	// Claim interface 0.
	CHECK(libusb_claim_interface(usb_device, 0));

	// Prepare transfers.
	for (int i = 0; i < NUM_TRANSFERS; i++) {
		SET(usb_transfers[i], libusb_alloc_transfer(0));
		libusb_fill_bulk_transfer(
			usb_transfers[i],
			usb_device,
			ENDPOINT | LIBUSB_ENDPOINT_IN,
			&usb_buffers[i][0],
			TRANSFER_SIZE,
			usb_callback,
			NULL,
			TIMEOUT_MS);
	}

	// Submit transfers.
	for (int i = 0; i < NUM_TRANSFERS; i++)
		CHECK(libusb_submit_transfer(usb_transfers[i]));

	// Handle libusb events.
	while (1)
		CHECK(libusb_handle_events(usb_context));

	return 0;
}
