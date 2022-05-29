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

#define ARP_REQUEST 1
#define ARP_RESPONSE 2

#define LEN_UDP_HEADER 8

#define DNS_PORT 53
#define MULTI_DNS_PORT 5353
#define LEN_DNS_HEADER 12
#define DNS_QUERY 0
#define DNS_RESPONSE 1
#define DNS_QUERY_TYPE_A 1 // query ip from domain
#define DNS_QUERY_TYPE_CNAME 5 // query domain from domain
#define DNS_QUERY_TYPE_PTR 12 // query
#define LEN_DNS_POINTER 2
#define DOT 46




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

// define ARP header
struct ARPHeader
{
    uint16_t Hardware_Type;
    uint16_t Protocol_Type;
    uint8_t Hardware_Size;
    uint8_t Protocol_Size;
    uint16_t Opcode;
    uint8_t S_Mac[6];
    uint32_t S_IP;
    uint8_t T_Mac[6];
    uint32_t T_IP;

    void swap(bool is_big_endian)
    {
        if (is_big_endian) // TODO why no swap
        {
            Hardware_Type = bswap_16(Hardware_Type);
            Protocol_Type = bswap_16(Protocol_Type);
            Opcode = bswap_16(Opcode);
            S_IP = bswap_32(S_IP);
            T_IP = bswap_32(T_IP);
        }
    }
};

//define UDP header
struct UDPHeader
{
    uint16_t Src_Port;
    uint16_t Dst_Port;
    uint16_t Length;
    uint16_t Checksum;

    void swap(bool is_big_endian)
    {
        if (is_big_endian) // TODO why no swap
        {
            Src_Port = bswap_16(Src_Port);
            Dst_Port = bswap_16(Dst_Port);
            Length = bswap_16(Length);
            Checksum = bswap_32(Checksum);
        }
    }
};

// define DNS header
struct DNSHeader
{
    uint16_t ID;
    uint16_t Flags;
    uint16_t QDCOUNT;
    uint16_t ANCOUNT;
    uint16_t NSCOUNT;
    uint16_t ARCOUNT;

    void swap(bool is_big_endian)
    {
        if (is_big_endian) // TODO why no swap
        {
            ID = bswap_16(ID);
            Flags = bswap_16(Flags);
            QDCOUNT = bswap_16(QDCOUNT);
            ANCOUNT = bswap_16(ANCOUNT);
            NSCOUNT = bswap_16(NSCOUNT);
            ARCOUNT = bswap_16(ARCOUNT);
        }
    }
};

struct _DNSHeader
{
    DNSHeader header;
    uint8_t QR;
    uint8_t OPCODE;
    uint8_t AA;
    uint8_t TC;
    uint8_t RD;
    uint8_t RA;
    uint8_t Z;
    uint8_t RCODE;

    void flag_swap(void)
    {
        QR = (header.Flags & 0x8000) >> 15;
        OPCODE = (header.Flags & 0x7800) >> 11;
        AA = (header.Flags & 0x0400) >> 10;
        TC = (header.Flags & 0x0200) >> 9;
        RD = (header.Flags & 0x0100) >> 8;
        RA = (header.Flags & 0x0080) >> 7;
        Z = (header.Flags & 0x0070) >> 4;
        RCODE = (header.Flags & 0x000F);
    }

};

struct DNSQuery
{
    uint16_t Query_Type;
    uint16_t Query_Class;
    char Domain_Name[100];

    void swap(bool is_big_endian)
    {
        if (is_big_endian) // TODO why no swap
        {
            Query_Type = bswap_16(Query_Type);
            Query_Class = bswap_16(Query_Class);
        }
    }

};

struct DNSAnswer
{
    uint32_t Time_to_Live;
    uint16_t Data_Len;

    void swap(bool is_big_endian)
    {
        if (is_big_endian) // TODO why no swap
        {
            Time_to_Live = bswap_32(Time_to_Live);
            Data_Len = bswap_16(Data_Len);
        }
    }
};

#pragma pack()

#endif