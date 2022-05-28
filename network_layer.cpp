#include "network_layer.h"
#include "utils.h"

NetworkLayer::NetworkLayer(bool _is_big_endian) {

	is_big_endian = _is_big_endian;
	// init ether proto map
	IPProto.insert(std::pair<uint8_t, std::string>(0x11, "UDP"));
	IPProto.insert(std::pair<uint8_t, std::string>(0x06, "TCP"));

	// init ip layer hanlder map
	NetworkLayerHanlder["IPv4"] = &NetworkLayer::ipv4_segment_hanlde_callback;
	NetworkLayerHanlder["ARP"] = &NetworkLayer::arp_hanlde_callback;
	NetworkLayerHanlder["RARP"] = &NetworkLayer::rarp_hanlde_callback;
	NetworkLayerHanlder["IPv6"] = &NetworkLayer::ipv6_segment_hanlde_callback;
}

NetworkLayer::~NetworkLayer() {

}

PcapParserErr NetworkLayer::ipv4_segment_hanlde_callback(char* file_ptr) {
	//logger.info("ipv4 processing ...");

	_ip_packet_header.header = *(IPPacketHeader*)file_ptr;
	_ip_packet_header.header.swap(is_big_endian);
	//_ip_packet_header.ip_packet_header = ip_packet_header;
	_ip_packet_header.ip_version_len_swap();
	if (_ip_packet_header.IHL == LEN_IP_PACKET_HEADER) {
		ip_int_to_str(_ip_packet_header.header.SourceAddress, ip_src);
		ip_int_to_str(_ip_packet_header.header.DestinationAddress, ip_dst);

		auto ip_type_pair = IPProto.find(_ip_packet_header.header.Protocol);
		if (ip_type_pair != IPProto.end()) {
			type = ip_type_pair->second;
		}
		else {
			type = "unkown type";
			logger.error("ip proto type not found {0:x}", type);
		}

	}
	else {

	}

	return kPcapParserSucc;
}

PcapParserErr NetworkLayer::ipv6_segment_hanlde_callback(char* file_ptr) {
	logger.info("ipv6 processing ...");
	return kPcapParserSucc;
}

PcapParserErr NetworkLayer::arp_hanlde_callback(char* file_ptr) {
	logger.info("arp processing ...");
	return kPcapParserSucc;
}

PcapParserErr NetworkLayer::rarp_hanlde_callback(char* file_ptr) {
	logger.info("rarp processing ...");
	return kPcapParserSucc;
}
