#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdint.h>
#include <stdio.h>
#include "pcap_parser.h"

int arrayToMac(const uint8_t* array, char* macaddr);

uint16_t bswap_16(uint16_t x);

IPVersion ip_version_len_swap(uint8_t version_ihl);

#endif
