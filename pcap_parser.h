#ifndef _PCAP_PARSER_H_
#define _PCAP_PARSER_H_

#include "pcap_format.h"
#include "utils.h"
#include <spdlog/spdlog.h>
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")

enum PcapParserErr {
	kPcapParserSucc = 0,
};

class PcapParser {
	private:
		uint32_t file_size = 0; // file length
		char* file_pointer = NULL;
	public:
		spdlog::logger logger = *(spdlog::get("pcap-parse"));

	    // define variables
		char pcap_data_buffer[2000]= {""};
		PcapHeader pcap_header;
		Packet packet;
		char timestrbuf[128] = { "" }; // buffer for timestamp in packet header
		// ether layer header
		EtherHeader ether_header;
		std::map<uint16_t, std::string> EtherProto;
		std::string type; // ether layer proto type
		char mac_dst[18] = { "" };
		char mac_src[18] = { "" };
		// network layer
		std::map<uint16_t, std::string> IPProto;
		IPVersion ip_version;
		IPPacket ip_packet;
		char* ip_src = NULL;
		char* ip_dst = NULL;
		struct in_addr ip_addr_src;
		struct in_addr ip_addr_dst;
		std::string ip_proto_type;

		PcapParser(char*, uint32_t);
		~PcapParser();

		// define pcap header parse func
		PcapParserErr parse_pcap_header(void);
		// define packet header parse func
		PcapParserErr parse_packet_header(void);
		PcapParserErr run(std::string);

		// define ether parse func
		PcapParserErr parse_ether_header(void);

		// define ip layer segment process func map
		typedef PcapParserErr (PcapParser::*packet_parse_cb)();
		std::map<std::string, packet_parse_cb> IPLayerHanlder;
		
		// define ether frame payload process func
		PcapParserErr ether_payload_process(PcapParserErr*);
		// define ip layer process callback function
		PcapParserErr ipv4_segment_hanlde_callback(void);
		PcapParserErr ipv6_segment_hanlde_callback(void);
		// define arp protocol process callback function
		PcapParserErr arp_hanlde_callback(void);
		PcapParserErr rarp_hanlde_callback(void);

};

#endif
