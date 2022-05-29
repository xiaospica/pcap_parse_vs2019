# include "pcap_parser.h"

PcapParser::PcapParser(char* file_s, uint32_t file_len) {

	this->file_pointer = file_s;
	this->file_size = file_len;

}

PcapParser::~PcapParser() {

}



PcapParserErr PcapParser::parse_pcap_header() {

	pcap_header = *(PcapHeader*)file_pointer;
	is_big_endian = (pcap_header.Magic == BIG_ENDIAN) ? true : false;
	pcap_header.swap(is_big_endian);
	file_pointer += LEN_PCAP_HEADER;
	return kPcapParserSucc;
}

PcapParserErr PcapParser::parse_packet_header() {

	pcap_packet_header = *(PcapPacketHeader*)file_pointer;
	pcap_packet_header.swap(is_big_endian);
	file_pointer += LEN_PCAP_PACKET_HEADER;
	// process packet header timestamp
	time_t packet_time_s = (time_t)pcap_packet_header.Timestamp_H;
	struct tm* info = localtime(&packet_time_s);
	strftime(timestrbuf, sizeof(timestrbuf), "[%Y/%m/%d %H:%M:%S]", info);
	return kPcapParserSucc;

}

PcapParserErr PcapParser::run(std::string _filter) {

	// process pcap header
	this->parse_pcap_header();

	DataLinkLayer data_link_layer = DataLinkLayer(is_big_endian);
	uint32_t idx = LEN_PCAP_HEADER;
	uint32_t cnt = 1;
	while (idx < (this->file_size- LEN_PCAP_HEADER)) {

		// process packet header
		this->parse_packet_header();

		// process ether header
		data_link_layer.parse_ether_header(file_pointer);

		// next ether pakcet
		file_pointer += pcap_packet_header.Caplen;
		idx += LEN_PCAP_PACKET_HEADER + pcap_packet_header.Caplen;

		logger.info("[{:05}] {} {:4} Bytes {} -> {} [{:6}] {:15} -> {:15} {:3} [{:6}] {:5} -> {:5} {:5} Bytes",
						cnt,
						timestrbuf,
						pcap_packet_header.Caplen,
						data_link_layer.mac_src, 
						data_link_layer.mac_dst, 
						data_link_layer.type, 
						data_link_layer.network_layer.ip_src,
						data_link_layer.network_layer.ip_dst, 
						data_link_layer.network_layer._ip_packet_header.header.TimetoLive,
						data_link_layer.network_layer.type,
						data_link_layer.network_layer.transport_layer.udp_header.Src_Port,
						data_link_layer.network_layer.transport_layer.udp_header.Dst_Port,
						data_link_layer.network_layer.transport_layer.udp_header.Length);
		cnt += 1;
	}
	logger.info("total cnt is: {}", cnt);
	logger.info("IP��ַ\tMAC��ַ");
	for (auto item = data_link_layer.network_layer.arp_table.cbegin(); item != data_link_layer.network_layer.arp_table.cend(); ++item) {
		logger.info("{}\t{}", item->first, item->second);
	}
	return kPcapParserSucc;

}