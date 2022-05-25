# include "pcap_parser.h"

PcapParser::PcapParser(char* file_s, uint32_t file_len) {

	this->file_pointer = file_s;
	this->file_size = file_len;

	// init ether proto map
	EtherProto.insert(std::pair<uint16_t, std::string>(0x0800, "IPv4"));
	EtherProto.insert(std::pair<uint16_t, std::string>(0x0806, "ARP"));
	EtherProto.insert(std::pair<uint16_t, std::string>(0x0835, "RARP"));
	EtherProto.insert(std::pair<uint16_t, std::string>(0x86DD, "IPv6"));

	// init ether proto map
	IPProto.insert(std::pair<uint8_t, std::string>(0x11, "UDP"));
	IPProto.insert(std::pair<uint8_t, std::string>(0x06, "TCP"));

	// init ip layer hanlder map
	IPLayerHanlder["IPv4"] = &PcapParser::ipv4_segment_hanlde_callback;
	IPLayerHanlder["ARP"] = &PcapParser::arp_hanlde_callback;
	IPLayerHanlder["RARP"] = &PcapParser::rarp_hanlde_callback;
	IPLayerHanlder["IPv6"] = &PcapParser::ipv6_segment_hanlde_callback;

}

PcapParser::~PcapParser() {

}

PcapParserErr PcapParser::ipv4_segment_hanlde_callback() {
	logger.info("ipv4 processing ...");
	return kPcapParserSucc;
}

PcapParserErr PcapParser::ipv6_segment_hanlde_callback() {
	logger.info("ipv6 processing ...");
	return kPcapParserSucc;
}

PcapParserErr PcapParser::arp_hanlde_callback() {
	logger.info("arp processing ...");
	return kPcapParserSucc;
}

PcapParserErr PcapParser::rarp_hanlde_callback() {
	logger.info("rarp processing ...");
	return kPcapParserSucc;
}

PcapParserErr PcapParser::parse_pcap_header() {

	memcpy(&pcap_header, file_pointer, sizeof(PcapHeader));
	file_pointer += sizeof(PcapHeader);
	return kPcapParserSucc;
}

PcapParserErr PcapParser::parse_ether_header() {

	memcpy(&ether_header, packet.data, sizeof(EtherHeader));
	uint16_t ether_proto_type = bswap_16(ether_header.Type);
	arrayToMac(ether_header.DstMac, mac_dst);
	arrayToMac(ether_header.SrcMac, mac_src);
	
	memcpy(&ip_packet.fixed_header, packet.data + (sizeof(EtherHeader)), sizeof(IPFixedHeader));
	ip_version = ip_version_len_swap(ip_packet.fixed_header.Version_IHL);
	if (ip_version.IHL == 20) {
		ip_addr_src.s_addr = ip_packet.fixed_header.SourceAddress;
		ip_addr_dst.s_addr = ip_packet.fixed_header.DestinationAddress;
		ip_src = inet_ntoa(ip_addr_src);
		ip_dst = inet_ntoa(ip_addr_dst);

		auto ip_type_pair = IPProto.find(ip_packet.fixed_header.Protocol);
		if (ip_type_pair != IPProto.end()) {
			ip_proto_type = ip_type_pair->second;

		}
		else {
			type = "ip unkown type";
			logger.error("ip proto type not found {0:x}", ether_proto_type);
		}

	}
	else {
		
	}

	auto ether_proto_pair = EtherProto.find(ether_proto_type);
	if (ether_proto_pair != EtherProto.end()) {
		type = ether_proto_pair->second;
		(this->*IPLayerHanlder[type])();
	}
	else {
		type = "unkown type";
		logger.error("ether proto type not found {0:x}", ether_proto_type);
	}
	return kPcapParserSucc;

}

PcapParserErr PcapParser::parse_packet_header() {

	memcpy(&packet.header, file_pointer, sizeof(PacketHeader));
	// process packet header timestamp
	time_t packet_time_s = (time_t)packet.header.Timestamp_H;
	struct tm* info = localtime(&packet_time_s);
	strftime(timestrbuf, sizeof(timestrbuf), "[%Y/%m/%d %H:%M:%S]", info);
	return kPcapParserSucc;

}

PcapParserErr PcapParser::run(std::string _filter) {

	// process pcap header
	this->parse_pcap_header();
	
	uint32_t idx = sizeof(PcapHeader);

	while (idx < (this->file_size- sizeof(PcapHeader))) {

		// process packet header
		this->parse_packet_header();

		file_pointer += sizeof(PacketHeader);
		packet.data = file_pointer ;
		// process ether header
		this->parse_ether_header();

		// next ether pakcet
		file_pointer += packet.header.Caplen;
		idx += sizeof(PacketHeader) + packet.header.Caplen;

		logger.info("{} {} Bytes {} {} {} {} {} {} {}", timestrbuf, packet.header.Caplen, mac_dst, mac_src, type, ip_src, ip_dst, ip_packet.fixed_header.TimetoLive, ip_proto_type);

	}
	return kPcapParserSucc;

}