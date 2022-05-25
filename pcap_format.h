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

#pragma pack(1)
 // define pcap header
struct PcapHeader {
    uint32_t Magic; // bigedian: 0xa1b2c3d4, littleedian: 0xd4c3b2a1
    uint16_t Major; // usually is 0x0200
    uint16_t Minor; // usually is 0x0400
    uint32_t ThisZone; // usually is 0
    uint32_t SigFigs; // timestamp accuracy, usually is o
    uint32_t SnapLen; // captured packet maxium len, 0xffff for all
    uint32_t LinkType;
};

// define packet header
struct PacketHeader {
    uint32_t Timestamp_H; // senconds
    uint32_t Timestamp_L; // microseconds
    uint32_t Caplen; // current data length
    uint32_t Len; // actual ethernet data length, usually bigger than Caplen
};

// define packet
struct Packet {
    PacketHeader header; // packet header
    char* data; // packet data
};

// define ether header
struct EtherHeader {
    uint8_t DstMac[6];
    uint8_t SrcMac[6];
    uint16_t Type;
};

// define network layer packet
struct IPVersion {
    uint8_t Version;
    uint8_t IHL;
};

struct IPFixedHeader {
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
};

struct IPPacket {
    IPFixedHeader fixed_header;
    uint8_t* Options;
    uint8_t* Padding;
    uint8_t* Data;
};

#pragma pack()

#endif