# include "pcap_parser.h"

PcapParser::PcapParser(char* file_s, uint32_t file_len) {

	this->file_pointer = file_s;
	this->file_size = file_len;

}

PcapParser::~PcapParser() {

}

PcapParserErr PcapParser::parse_pcap_header() {

	memcpy(&pcap_header, file_pointer, sizeof(PcapHeader));
	file_pointer += sizeof(PcapHeader);
	return kPcapParserSucc;
}

PcapParserErr PcapParser::run() {

	// process pcap header
	this->parse_pcap_header();
	
	EtherProto.insert(std::pair<uint16_t, std::string>(0x0800, "IPv4"));
	EtherProto.insert(std::pair<uint16_t, std::string>(0x0806, "ARP"));
	EtherProto.insert(std::pair<uint16_t, std::string>(0x0835, "RARP"));
	EtherProto.insert(std::pair<uint16_t, std::string>(0x86DD, "IPv6"));
	uint32_t idx = sizeof(PcapHeader);
	std::string type;

	while (idx < (this->file_size- sizeof(PcapHeader))) {
		char buf[128] = { "" };
		memcpy(&packet.header, file_pointer, sizeof(PacketHeader));
		file_pointer += sizeof(PacketHeader);
		packet.data = file_pointer ;
		
		// process ether header
		memcpy(&ether_header, packet.data, sizeof(EtherHeader));
		char mac_dst[18] = { "" };
		char mac_src[18] = { "" };
		arrayToMac(ether_header.DstMac, mac_dst);
		arrayToMac(ether_header.SrcMac, mac_src);
		uint16_t ether_proto_type = bswap_16(ether_header.Type);
		auto ether_proto_pair = EtherProto.find(ether_proto_type);
		if (ether_proto_pair != EtherProto.end()) {
			type = ether_proto_pair->second;
		}
		else {
			type = "unkown type";
			logger.error("ether proto type not found {0:x}", ether_proto_type);
		}
		
		file_pointer += packet.header.Caplen;
		idx += sizeof(PacketHeader) + packet.header.Caplen;

		// process packet header timestamp
		time_t packet_time_s = (time_t)packet.header.Timestamp_H;
		struct tm* info = localtime(&packet_time_s);
		strftime(buf, sizeof(buf), "[%Y/%m/%d %H:%M:%S]", info);

		logger.info("{} {} bytes {} {} {}", buf, packet.header.Caplen, mac_dst, mac_src, type);
	}
	return kPcapParserSucc;

}