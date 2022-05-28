/*
 * @Author: richard.xiao richardshawxw@gmail.com
 * @Date: 2022-05-21 17:36:49
 * @LastEditors: richard.xiao richardshawxw@gmail.com
 * @LastEditTime: 2022-05-21 17:58:59
 * @FilePath: \day06\pcap_format.h
 * @Description: defile pcap file format data structure
 *
 * Copyright (c) 2022 by richard.xiao richardshawxw@gmail.com, All Rights Reserved.
 */

#ifndef _PCAP_FORMAT_H_
#define _PCAP_FORMAT_H_

#include <stdio.h>
#include <iostream>
#include <stdint.h>
#include <map>
#include <string>
#include "utils.h"

#define BIG_ENDIAN 0xa1b2c3d4
#define LEN_PCAP_HEADER 24
#define LEN_PCAP_PACKET_HEADER 16
#define LEN_ETHER_FRAME_HEADER 14
#define LEN_IP_PACKET_HEADER 20

enum PcapParserErr {
    kPcapParserSucc = 0,
};

#pragma pack(1)
// define pcap header
struct PcapHeader {
    uint32_t Magic; // big endian: 0xa1b2c3d4, little endian: 0xd4c3b2a1
    uint16_t Major; // usually is 0x0200
    uint16_t Minor; // usually is 0x0400
    uint32_t ThisZone; // usually is 0
    uint32_t SigFigs; // timestamp accuracy, usually is o
    uint32_t SnapLen; // captured packet maxium len, 0xffff for all
    uint32_t LinkType;

    void swap(bool is_big_endian)
    {
        if (!is_big_endian)
        {
            Major = bswap_16(Major);
            Minor = bswap_16(Minor);
            ThisZone = bswap_32(ThisZone);
            SigFigs = bswap_32(SigFigs);
            SnapLen = bswap_32(SnapLen);
            LinkType = bswap_32(LinkType);
        }
    }
};

// define pcap packet header
struct PcapPacketHeader {
    uint32_t Timestamp_H; // senconds
    uint32_t Timestamp_L; // microseconds
    uint32_t Caplen; // current data length
    uint32_t Len; // actual ethernet data length, usually bigger than Caplen

    void swap(bool is_big_endian)
    {
        if (!is_big_endian)
        {
            Timestamp_H = bswap_32(Timestamp_H);
            Timestamp_L = bswap_32(Timestamp_L);
            Caplen = bswap_32(Caplen);
            Len = bswap_32(Len);
        }
    }
};

// define ether frame header
struct EtherFrameHeader {
    uint8_t DstMac[6];
    uint8_t SrcMac[6];
    uint16_t Type;

    void swap(bool is_big_endian)
    {
        if (is_big_endian) // TODO why no swap
        {
            Type = bswap_16(Type);
        }
    }
};

// define IP header
struct IPPacketHeader {
    uint8_t Version_IHL;
    uint8_t TypeofService;
    uint16_t TotalLength;
    uint16_t Identification;
    uint16_t Flags_FragmentOffset;
    uint8_t TimetoLive;
    uint8_t Protocol;
    uint16_t HeaderChecksum;
    uint32_t SourceAddress;
    uint32_t DestinationAddress;

    void swap(bool is_big_endian)
    {
        if (is_big_endian) // TODO why no swap
        {
            TotalLength = bswap_16(TotalLength);
            Identification = bswap_16(Identification);
            Flags_FragmentOffset = bswap_16(Flags_FragmentOffset);
            HeaderChecksum = bswap_16(HeaderChecksum);
            SourceAddress = bswap_32(SourceAddress);
            DestinationAddress = bswap_32(DestinationAddress);
        }
    }
};

struct _IPPacketHeader {
    IPPacketHeader header;
    uint8_t Version;
    uint8_t IHL;
    uint8_t* Options;
    uint8_t* Padding;
    uint8_t* Data;

    void ip_version_len_swap(void) {
        IHL = 4 * (header.Version_IHL & 0x0f);
        Version = (header.Version_IHL >> 4) & 0x0f;
    }
};

#pragma pack()

#endif