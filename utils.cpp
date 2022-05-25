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

IPVersion ip_version_len_swap(uint8_t version_ihl) {

	IPVersion ip_version;
	ip_version.IHL = 4 * (version_ihl & 0x0f);
	ip_version.Version = (version_ihl >> 4) & 0x0f;

	return ip_version;

}