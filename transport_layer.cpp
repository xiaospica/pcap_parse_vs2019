#include "transport_layer.h"


TransportLayer::TransportLayer(bool _is_big_endian)
{
	// init ip layer hanlder map
	TransportLayerHanlder["UDP"] = &TransportLayer::udp_hanlde_callback;
	TransportLayerHanlder["TCP"] = &TransportLayer::tcp_hanlde_callback;
	TransportLayerHanlder["ICMP"] = &TransportLayer::icmp_hanlde_callback;
}

TransportLayer::~TransportLayer()
{
	
}

PcapParserErr TransportLayer::udp_hanlde_callback(char* file_ptr)
{
	udp_header = *(UDPHeader*)file_ptr;
	udp_header.swap(is_big_endian);

	if (udp_header.Src_Port == DNS_PORT || udp_header.Src_Port == MULTI_DNS_PORT || 
		udp_header.Dst_Port == DNS_PORT || udp_header.Dst_Port == MULTI_DNS_PORT)
	//if (udp_header.Src_Port == DNS_PORT||
	//	udp_header.Dst_Port == DNS_PORT)
	{
		//(application_layer.*application_layer.ApplicationLayerHanlder["DNS"])(file_ptr + LEN_UDP_HEADER, udp_header.Length- LEN_UDP_HEADER);
	}
	return kPcapParserSucc;
}

PcapParserErr TransportLayer::tcp_hanlde_callback(char* file_ptr)
{
	return kPcapParserSucc;
}

PcapParserErr TransportLayer::icmp_hanlde_callback(char* file_ptr)
{

	return kPcapParserSucc;
}