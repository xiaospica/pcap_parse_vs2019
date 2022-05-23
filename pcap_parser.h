#ifndef _PCAP_PARSER_H_
#define _PCAP_PARSER_H_

#include "pcap_format.h"
#include "utils.h"
#include <spdlog/spdlog.h>

enum PcapParserErr {
	kPcapParserSucc = 0,
};

class PcapParser {
	private:
		uint32_t file_size = 0; // file length
		char* file_pointer = NULL;
	public:
		spdlog::logger logger = *(spdlog::get("pcap-parse"));
		PcapParser(char*, uint32_t);
		~PcapParser();
		char pcap_data_buffer[2000]= {""};
		PcapHeader pcap_header;
		Packet packet;
		EtherHeader ether_header;
		PcapParserErr run(std::string);
		PcapParserErr parse_pcap_header(void);

		// define ether proto map
		std::map<uint16_t, std::string> EtherProto;

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
