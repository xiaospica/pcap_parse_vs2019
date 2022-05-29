#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdint.h>
#include <stdio.h>

int arrayToMac(const uint8_t* array, char* macaddr);

uint16_t bswap_16(uint16_t x);

uint32_t bswap_32(uint32_t x);

void ip_int_to_str(uint32_t ip, char* ip_str);

uint8_t bit_reverse(uint8_t b);

#endif
