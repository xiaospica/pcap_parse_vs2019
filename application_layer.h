#ifndef _APPLICATION_LAYER_H_
#define _APPLICATION_LAYER_H_

#include "protocol_format.h"
#include <spdlog/spdlog.h>

class ApplicationLayer
{
private:
	char* file_ptr = nullptr;
public:
	spdlog::logger logger = *(spdlog::get("pcap-parse"));

	// define variables
	bool is_big_endian = true;
	_DNSHeader _dns_header;
	DNSQuery dns_query;
	DNSAnswer dns_answer;


	// define ip layer segment process func map
	typedef PcapParserErr(ApplicationLayer::* application_layer_cb)(char*, uint16_t);
	std::map<std::string, application_layer_cb> ApplicationLayerHanlder;

	// define func
	ApplicationLayer(bool);
	~ApplicationLayer();

	PcapParserErr dns_hanlde_callback(char*, uint16_t);
	uint16_t dns_queries_parse(char*, char*, uint16_t, uint16_t);
	uint16_t dns_answers_parse(char*, char*, uint16_t, uint16_t);
	uint16_t dns_authority_parse(char*, char*, uint16_t);
	uint16_t dns_addtional_parse(char*, char*, uint16_t);
	uint16_t domain_process(uint16_t, char*, char*, char*);


};

#endif

