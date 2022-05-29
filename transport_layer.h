#ifndef _TRANSPORT_LAYER_H_
#define _TRANSPORT_LAYER_H_

#include "protocol_format.h"
#include "application_layer.h"
#include <spdlog/spdlog.h>

class TransportLayer
{
private:
	char* file_ptr = nullptr;
public:
	spdlog::logger logger = *(spdlog::get("pcap-parse"));

	// define variables
	bool is_big_endian = true;
	UDPHeader udp_header;


	// define ip layer segment process func map
	typedef PcapParserErr(TransportLayer::* transport_layer_cb)(char*);
	std::map<std::string, transport_layer_cb> TransportLayerHanlder;

	ApplicationLayer application_layer = ApplicationLayer(is_big_endian);

	// define func
	TransportLayer(bool);
	~TransportLayer();

	PcapParserErr udp_hanlde_callback(char*);
	PcapParserErr tcp_hanlde_callback(char*);
	PcapParserErr icmp_hanlde_callback(char*);


};

#endif

