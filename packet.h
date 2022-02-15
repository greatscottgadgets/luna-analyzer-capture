#define PID_TYPE_MASK	0b0011

enum pid_type {
	SPECIAL		= 0b00,
	TOKEN		= 0b01,
	HANDSHAKE	= 0b10,
	DATA		= 0b11,
};

enum pid {
	RSVD	= 0b11110000,
	OUT	= 0b11100001,
	ACK	= 0b11010010,
	DATA0	= 0b11000011,
	PING	= 0b10110100,
	SOF	= 0b10100101,
	NYET	= 0b10010110,
	DATA2	= 0b10000111,
	SPLIT	= 0b01111000,
	IN	= 0b01101001,
	NAK	= 0b01011010,
	DATA1	= 0b01001011,
	ERR	= 0b00111100,
	SETUP	= 0b00101101,
	STALL	= 0b00011110,
	MDATA	= 0b00001111,
};

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
