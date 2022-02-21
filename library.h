#pragma pack(1)

#define PID_MASK	0x0F
#define PID_TYPE_MASK	0x03

// Categories of USB protocol packet IDs
enum pid_type {
	SPECIAL		= 0,
	TOKEN		= 1,
	HANDSHAKE	= 2,
	DATA		= 3,
};

// USB protocol packet IDs
enum pid {
	NONE    = 0x00,
	RSVD	= 0xF0,
	OUT	= 0xE1,
	ACK	= 0xD2,
	DATA0	= 0xC3,
	PING	= 0xB4,
	SOF	= 0xA5,
	NYET	= 0x96,
	DATA2	= 0x87,
	SPLIT	= 0x78,
	IN	= 0x69,
	NAK	= 0x5A,
	DATA1	= 0x4B,
	ERR	= 0x3C,
	SETUP	= 0x2D,
	STALL	= 0x1E,
	MDATA	= 0x0F,
};

// Representation of a USB packet.
struct packet {
	// Timestamp in ns since Unix epoch
	uint64_t timestamp_ns;
	// Offset where this packet's data payload can be found in the data array.
	uint64_t data_offset;
	// Length of this packet on the wire.
	uint16_t length;
	// Packet ID field.
	uint8_t pid;
	// PID-specific fields as per protocol spec.
	union {
		struct {
			unsigned int framenumber :11;
			unsigned int crc :5;
		} sof;
		struct {
			unsigned int address :7;
			unsigned int endpoint_num :4;
			unsigned int crc :5;
		} token;
		struct {
			uint16_t crc;
		} data;
	} fields;
};

// Representation of a USB transaction.
//
// A transaction may consist of up to three packets, that must
// be consecutive on the wire.
struct transaction {
	// Index of this transaction's first packet in the packet array.
	uint64_t first_packet_id;
	// Number of packets in this transaction (may be up to 3).
	uint8_t num_packets;
	// Whether this transaction was completed.
	bool complete;
};

// Representation of a USB endpoint.
//
// An endpoint is defined by a device address and an endpoint number.
struct endpoint {
	// Device address (0-127).
	uint8_t address;
	// Endpoint number (0-15).
	uint8_t endpoint_num;
};

// Representation of a USB transfer.
//
// A transfer consists of a sequence of consecutive transactions on the same endpoint.
// The transactions may not be consecutive on the wire.
struct transfer {
	// Offset of this transfer's transactions within its endpoint's transaction ID array.
	uint64_t ep_tran_offset;
	// Number of transactions in this transfer.
	uint64_t num_transactions;
	// Whether this transfer was completed.
	bool complete;
};

// Representation of traffic on a specific USB endpoint.
struct endpoint_traffic {
	// Number of transfers on this endpoint.
	uint64_t num_transfers;
	// Number of transactions on this endpoint.
	uint64_t num_transaction_ids;
	// Array of transfers on this endpoint.
	struct transfer *transfers;
	// Array of IDs of transactions on this endpoint.
	uint64_t *transaction_ids;
};

// An entry in the index of all transfers.
struct transfer_index_entry {
	// Index into the endpoints array.
	uint16_t endpoint_id;
	// Index into the transfers on the given endpoint.
	uint64_t transfer_id;
};

// Types of events in the top level event array.
enum event_type {
	// A stray packet (not part of any transaction).
	PACKET,
	// A stray transaction (not part of any transfer), containing packets.
	TRANSACTION,
	// A transfer, containing transactions.
	TRANSFER,
};

// An event in the top level event array.
struct event {
	// Packet, transaction or transfer ID.
	uint64_t id;
	// Event type.
	uint8_t type;
};

// Representation of a USB capture.
struct capture {
	// Number of events in the top-level event array.
	uint64_t num_events;
	// Number of endpoints seen in the capture.
	uint64_t num_endpoints;
	// Total number of transfers in the capture.
	uint64_t num_transfers;
	// Number of transactions in the capture.
	uint64_t num_transactions;
	// Number of packets in the capture.
	uint64_t num_packets;
	// Total size of all packet payload data in the capture.
	uint64_t data_size;
	// Array of top-level events.
	struct event *events;
	// Array of endpoints seen in the capture.
	struct endpoint *endpoints;
	// Array of pointers to per-endpoint traffic records.
	struct endpoint_traffic **endpoint_traffic;
	// Index of all transfers in the capture.
	struct transfer_index_entry *transfer_index;
	// Array of transactions in the capture.
	struct transaction *transactions;
	// Array of packets in the capture.
	struct packet *packets;
	// Array of payload data from packets in the capture.
	uint8_t *data;
};

// Open a capture from a file in raw LUNA capture format.
struct capture* convert_capture(const char *filename);

// Close capture and free all resources used.
void close_capture(struct capture *capture);
