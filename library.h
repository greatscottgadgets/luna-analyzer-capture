#define PID_TYPE_MASK	3

enum pid_type {
	SPECIAL		= 0,
	TOKEN		= 1,
	HANDSHAKE	= 2,
	DATA		= 3,
};

enum pid {
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

struct capture {
	uint64_t num_packets;
	struct packet *packets;
	uint8_t *data;
};

struct capture* load_capture(void);
struct capture* convert_capture(const char *filename);
