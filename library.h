#define PID_TYPE_MASK	3

enum pid_type {
	SPECIAL		= 0,
	TOKEN		= 1,
	HANDSHAKE	= 2,
	DATA		= 3,
};

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

#pragma pack(1)
struct packet {
	uint64_t timestamp_ns;
	uint64_t data_offset;
	uint16_t length;
	uint8_t pid;
	union {
		struct {
			unsigned int framenumber :11;
			unsigned int crc :5;
		} sof;
		struct {
			unsigned int address :7;
			unsigned int endpoint :4;
			unsigned int crc :5;
		} token;
		struct {
			uint16_t crc;
		} data;
	} fields;
};

struct transaction {
	uint64_t first_packet_index;
	uint8_t num_packets;
	bool complete;
};

struct transfer {
	uint64_t id_offset;
	uint64_t num_transactions;
	bool complete;
};

struct endpoint {
	uint8_t address;
	uint8_t endpoint;
};

struct endpoint_traffic {
	uint64_t num_transfers;
	uint64_t num_transaction_ids;
	struct transfer *transfers;
	uint64_t *transaction_ids;
};

struct transfer_index_entry {
	uint16_t endpoint_id;
	uint64_t transfer_id;
};

struct capture {
	uint64_t num_endpoints;
	uint64_t num_transfers;
	uint64_t num_transactions;
	uint64_t num_packets;
	uint64_t data_size;
	struct endpoint *endpoints;
	struct endpoint_traffic **endpoint_traffic;
	struct transfer_index_entry *transfer_index;
	struct transaction *transactions;
	struct packet *packets;
	uint8_t *data;
};

struct capture* convert_capture(const char *filename);
