#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <signal.h>
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
	if (result != 0 && result != LIBUSB_ERROR_INTERRUPTED) { \
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
static int interrupted = 0;
static bool capture_stopped = false;
static int transfers_stopped = 0;

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
			if (capture_stopped) {
				transfers_stopped++;
			} else {
				// Resubmit transfer.
				CHECK(libusb_submit_transfer(transfer));
			}
			TO_STDERR("Received %u bytes", transfer->actual_length);
			break;
		default:
			break;
	}
}

void interrupt(int signum)
{
	interrupted = 1;
	libusb_interrupt_event_handler(usb_context);
}

int main(int argc, char *argv[])
{
	// Set up libusb context.
	CHECK(libusb_init(&usb_context));

	// Set signal handler.
	signal(SIGINT, interrupt);

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

	// Enable capture.
	CHECK(libusb_control_transfer(usb_device,
		LIBUSB_ENDPOINT_OUT
			| LIBUSB_REQUEST_TYPE_VENDOR
			| LIBUSB_RECIPIENT_DEVICE,
		1, // Set state
		1, // Capture enabled
		0, // No index
		NULL, // No data
		0, // Zero length
		0 // No timeout
	));

	// Handle libusb events until stopped by Ctrl-C.
	while (!interrupted)
		CHECK(libusb_handle_events_completed(usb_context, &interrupted));

	// Disable capture.
	CHECK(libusb_control_transfer(usb_device,
		LIBUSB_ENDPOINT_OUT
			| LIBUSB_REQUEST_TYPE_VENDOR
			| LIBUSB_RECIPIENT_DEVICE,
		1, // Set state
		0, // Capture disabled
		0, // No index
		NULL, // No data
		0, // Zero length
		0 // No timeout
	));

	capture_stopped = true;

	// Handle libusb events until all transfers have completed.
	while (transfers_stopped < NUM_TRANSFERS)
		CHECK(libusb_handle_events(usb_context));

	return 0;
}
