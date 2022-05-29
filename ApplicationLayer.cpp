#include "application_layer.h"


ApplicationLayer::ApplicationLayer(bool _is_big_endian)
{
	// init ip layer hanlder map
	ApplicationLayerHanlder["DNS"] = &ApplicationLayer::dns_hanlde_callback;
}

ApplicationLayer::~ApplicationLayer()
{

}

PcapParserErr ApplicationLayer::dns_hanlde_callback(char* file_ptr)
{
	_dns_header.header = *(DNSHeader*)file_ptr;
	_dns_header.header.swap(is_big_endian);
	_dns_header.flag_swap();
	logger.info("processing dns... {}", _dns_header.QR);
	return kPcapParserSucc;
}
