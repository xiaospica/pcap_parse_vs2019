#include "utils.h"

int arrayToMac(const uint8_t* array, char* macaddr) {

	sprintf(macaddr, "%2x-%2x-%2x-%2x-%2x-%2x\0",
		array[0], array[1], array[2], array[3], array[4], array[5]);

	return 0;
}

uint16_t bswap_16(uint16_t x){

	return (((uint16_t)(x) & 0x00ff) << 8) | \
		(((uint16_t)(x) & 0xff00) >> 8);

}