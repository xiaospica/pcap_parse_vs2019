#include "data_link_layer.h"
#include "utils.h"

DataLinkLayer::DataLinkLayer(bool _is_big_endian) {

	is_big_endian = _is_big_endian;
	// init ether proto map
	EtherProto.insert(std::pair<uint16_t, std::string>(0x0008, "LLC"));
	EtherProto.insert(std::pair<uint16_t, std::string>(0x0800, "IPv4"));
	EtherProto.insert(std::pair<uint16_t, std::string>(0x0806, "ARP"));
	EtherProto.insert(std::pair<uint16_t, std::string>(0x0835, "RARP"));
	EtherProto.insert(std::pair<uint16_t, std::string>(0x86DD, "IPv6"));
	EtherProto.insert(std::pair<uint16_t, std::string>(0x88CC, "LLDP"));

	//NetworkLayer network_layer = NetworkLayer(file_ptr + LEN_ETHER_FRAME_HEADER);

}

DataLinkLayer::~DataLinkLayer() {

}

PcapParserErr DataLinkLayer::parse_ether_header(char* file_ptr) {

	ether_frame_header = *(EtherFrameHeader*)file_ptr;
	ether_frame_header.swap(is_big_endian);
	arrayToMac(ether_frame_header.DstMac, mac_dst);
	arrayToMac(ether_frame_header.SrcMac, mac_src);

	auto ether_proto_pair = EtherProto.find(ether_frame_header.Type);
	if (ether_proto_pair != EtherProto.end()) {
		type = ether_proto_pair->second;
		auto network_layer_cb_pair = network_layer.NetworkLayerHanlder.find(type);
		if (network_layer_cb_pair != network_layer.NetworkLayerHanlder.end())
		{
			(network_layer.*network_layer.NetworkLayerHanlder[type])(file_ptr + LEN_ETHER_FRAME_HEADER);
			//(network_layer.*NetworkLayer::NetworkLayerHanlder[type])();			
		}
	}
	else {
		std::stringstream stream;
		stream << "0x" << std::setfill('0') << std::setw(sizeof(uint16_t) * 2) << std::hex << ether_frame_header.Type;
		type = stream.str();
		logger.error("ether proto type not found 0x{:04x}", ether_frame_header.Type);
	}
	return kPcapParserSucc;

}
