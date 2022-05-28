#include "utils.h"

int arrayToMac(const uint8_t* array, char* macaddr) {

	sprintf(macaddr, "%02x-%02x-%02x-%02x-%02x-%02x\0",
		array[0], array[1], array[2], array[3], array[4], array[5]);

	return 0;
}

uint16_t bswap_16(uint16_t x){

	return (((uint16_t)(x) & 0x00ff) << 8) | \
		(((uint16_t)(x) & 0xff00) >> 8);

}

uint32_t bswap_32(uint32_t x) {
	return ((x >> 24) & 0xff) |
		((x << 8) & 0xff0000) |
		((x >> 8) & 0xff00) |
		((x << 24) & 0xff000000);
}

void ip_int_to_str(uint32_t ip, char* ip_str)
{
	unsigned char bytes[4];
	bytes[0] = ip & 0xFF;
	bytes[1] = (ip >> 8) & 0xFF;
	bytes[2] = (ip >> 16) & 0xFF;
	bytes[3] = (ip >> 24) & 0xFF;
	sprintf(ip_str, "%d.%d.%d.%d\0", bytes[3], bytes[2], bytes[1], bytes[0]);

}