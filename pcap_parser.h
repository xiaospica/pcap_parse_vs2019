#ifndef _PCAP_PARSER_H_
#define _PCAP_PARSER_H_

#include "protocol_format.h"
#include "data_link_layer.h"
#include "utils.h"
#include <spdlog/spdlog.h>
#include <sys/timeb.h>



class PcapParser {
	private:
		uint32_t file_size = 0; // file length
		char* file_pointer = nullptr;
	public:
		spdlog::logger logger = *(spdlog::get("pcap-parse"));

	    // define variables
		PcapHeader pcap_header;
		PcapPacketHeader pcap_packet_header;
		char timestrbuf[128] = { "" }; // buffer for timestamp in packet header
		bool is_big_endian = true;



		PcapParser(char*, uint32_t);
		~PcapParser();

		// define pcap header parse func
		PcapParserErr parse_pcap_header(void);
		// define packet header parse func
		PcapParserErr parse_packet_header(void);
		PcapParserErr run(std::string);
		void output(uint32_t, DataLinkLayer);




};

#endif
