#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdint.h>
#include <stdio.h>

int arrayToMac(const uint8_t* array, char* macaddr);

uint16_t bswap_16(uint16_t x);

#endif
