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
		PcapParserErr run(void);
		PcapParserErr parse_pcap_header(void);
		std::map<uint16_t, std::string> EtherProto;

};

#endif
