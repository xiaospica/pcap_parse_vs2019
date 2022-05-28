#ifndef _NETWORK_LAYER_H_
#define _NETWORK_LAYER_H_

#include "protocol_format.h"
#include <spdlog/spdlog.h>

class NetworkLayer {
	private:
		char* file_ptr = nullptr;
	public:
		spdlog::logger logger = *(spdlog::get("pcap-parse"));

		// define variables
		bool is_big_endian = true;
		_IPPacketHeader _ip_packet_header;
		std::map<uint16_t, std::string> IPProto;
		char ip_src[16] = {};
		char ip_dst[16] = {};
		std::string type;

		// define ip layer segment process func map
		typedef PcapParserErr (NetworkLayer::* network_layer_cb)(char*);
		std::map<std::string, network_layer_cb> NetworkLayerHanlder;


		NetworkLayer(bool);
		~NetworkLayer();
		// define ip layer process callback function
		PcapParserErr ipv4_segment_hanlde_callback(char*);
		PcapParserErr ipv6_segment_hanlde_callback(char*);
		// define arp protocol process callback function
		PcapParserErr arp_hanlde_callback(char*);
		PcapParserErr rarp_hanlde_callback(char*);
};

#endif

