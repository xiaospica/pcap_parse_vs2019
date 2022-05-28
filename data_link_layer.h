#ifndef _DATA_LINK_LAYER_H_
#define _DATA_LINK_LAYER_H_

#include "protocol_format.h"
#include "network_layer.h"
#include <spdlog/spdlog.h>

class DataLinkLayer
{
	private:
		char* file_ptr = nullptr;
	public:
		spdlog::logger logger = *(spdlog::get("pcap-parse"));

		// define variables
		bool is_big_endian = true;
		EtherFrameHeader ether_frame_header;
		// ether layer header
		std::map<uint16_t, std::string> EtherProto;
		std::string type; // ether layer proto type
		char mac_dst[18] = { "" };
		char mac_src[18] = { "" };

		NetworkLayer network_layer = NetworkLayer(is_big_endian);
		
		DataLinkLayer(bool);
		~DataLinkLayer();
		PcapParserErr parse_ether_header(char*);


		// define ether frame payload process func
		PcapParserErr ether_payload_process(PcapParserErr*);
};

#endif

