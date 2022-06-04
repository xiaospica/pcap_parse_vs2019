#include "application_layer.h"


ApplicationLayer::ApplicationLayer(bool _is_big_endian)
{
	// init ip layer hanlder map
	ApplicationLayerHanlder["DNS"] = &ApplicationLayer::dns_hanlde_callback;
}

ApplicationLayer::~ApplicationLayer()
{

}

PcapParserErr ApplicationLayer::dns_hanlde_callback(char* file_ptr, uint16_t len)
{
	_dns_header.header = *(DNSHeader*)file_ptr;
	_dns_header.header.swap(is_big_endian);
	_dns_header.flag_swap();
	char* file_ptr_cpy = file_ptr;
	file_ptr += LEN_DNS_HEADER;
	uint16_t offset = 0;

	switch (_dns_header.QR)
	{
		case DNS_QUERY:

			if (_dns_header.header.QDCOUNT)
			{

				offset = this->dns_queries_parse(file_ptr, file_ptr_cpy, _dns_header.header.QDCOUNT, len - LEN_DNS_HEADER);
			}
			break;
		case DNS_RESPONSE:
			if (_dns_header.header.ANCOUNT)
			{
				offset = this->dns_queries_parse(file_ptr, file_ptr_cpy, _dns_header.header.QDCOUNT, len - LEN_DNS_HEADER);

				offset = this->dns_answers_parse(file_ptr+ offset, file_ptr_cpy, _dns_header.header.ANCOUNT, len - LEN_DNS_HEADER- offset);
			}
			break;
		default:
			logger.info("unknow dns QR type");
	}
	return kPcapParserSucc;
}

uint16_t ApplicationLayer::dns_answers_parse(char* file_ptr, char* ptr_cpy, uint16_t acount, uint16_t len)
{
	uint16_t dns_offset = 0;
	uint16_t acnt = 0;
	uint16_t domain_addr_offset = 0;
	
	char ip_str[16] = {};

	while (dns_offset < (len))
	{
		logger.info("dns answer processing ...");
		if (acnt < acount)
		{
			memset(dns_query.Domain_Name, DOT, sizeof(dns_query.Domain_Name));
			domain_addr_offset = this->domain_process(0, file_ptr, ptr_cpy, dns_query.Domain_Name);


			logger.info("DNS响应: {}", dns_query.Domain_Name);
			if (!domain_addr_offset) // end with '\0'
			{
				file_ptr += 1; // skip '\0'
				dns_query.Query_Type = *(uint16_t*)file_ptr;
				dns_query.Query_Class = *(uint16_t*)(file_ptr + sizeof(dns_query.Query_Type));
				dns_query.swap(is_big_endian);
				file_ptr += 4 + strlen(dns_query.Domain_Name) + 1; // plus first dot(fragment len) len
				dns_offset += 5 + (uint16_t)strlen(dns_query.Domain_Name) + 1; // plus first dot(fragment len) len
			}
			else { // end with dns pointer
				dns_query.Query_Type = *(uint16_t*)(file_ptr + domain_addr_offset);
				dns_query.Query_Class = *(uint16_t*)(file_ptr + domain_addr_offset + sizeof(dns_query.Query_Type));
				dns_query.swap(is_big_endian);
				file_ptr += 4 + domain_addr_offset;
				dns_offset += 4 + domain_addr_offset;
			}

			dns_answer.Time_to_Live = *(uint32_t*)file_ptr;
			dns_answer.Data_Len = *(uint16_t*)(file_ptr + sizeof(dns_answer.Time_to_Live));
			file_ptr += sizeof(dns_answer.Time_to_Live) + sizeof(dns_answer.Data_Len);
			dns_offset += sizeof(dns_answer.Time_to_Live) + sizeof(dns_answer.Data_Len);

			// parse CNAME/IP Address
			if (dns_query.Query_Type == DNS_QUERY_TYPE_CNAME)
			{
				memset(dns_query.Domain_Name, DOT, sizeof(dns_query.Domain_Name));
				domain_addr_offset = this->domain_process(0, file_ptr, ptr_cpy, dns_query.Domain_Name);
				if (!domain_addr_offset)
				{
					file_ptr += strlen(dns_query.Domain_Name)+2; // plus first dot(fragment len) len and '\0'
					dns_offset += (uint16_t)strlen(dns_query.Domain_Name)+2; // plus first dot(fragment len) len and '\0'
				}else
				{
					file_ptr += domain_addr_offset;
					dns_offset += domain_addr_offset;
				}
				logger.info("DNS响应CNAME: {}", dns_query.Domain_Name);
			}
			else if (dns_query.Query_Type == DNS_QUERY_TYPE_A)
			{
				ip_int_to_str(*(uint32_t*)file_ptr, ip_str);
				file_ptr += sizeof(uint32_t); // size of ip address
				dns_offset += sizeof(uint32_t);
				logger.info("DNS响应IP: {}", ip_str);
			}
			else // currently skip other type
			{
				file_ptr += dns_answer.Data_Len;
				dns_offset += dns_answer.Data_Len;
			}

			acnt += 1;
		}
		else
		{
			return dns_offset;
		}

	}
	return 0;
}

uint16_t ApplicationLayer::dns_queries_parse(char* file_ptr, char* ptr_cpy, uint16_t qcount, uint16_t len)
{

	uint16_t dns_offset = 0;
	uint16_t qcnt = 0;
	uint16_t domain_addr_offset = 0;

	while (dns_offset < (len))
	{
		//logger.info("dns query processing ...");
		if (qcnt < qcount)
		{
			memset(dns_query.Domain_Name, DOT, sizeof(dns_query.Domain_Name));
			domain_addr_offset = this->domain_process(0, file_ptr, ptr_cpy, dns_query.Domain_Name);


			logger.info("DNS请求: {}", dns_query.Domain_Name);
			if (!domain_addr_offset) // end with '\0'
			{
				file_ptr += 1; // skip '\0'
				dns_query.Query_Type = *(uint16_t*)file_ptr;
				dns_query.Query_Class = *(uint16_t*)(file_ptr+sizeof(dns_query.Query_Type));
				dns_query.swap(is_big_endian);
				file_ptr += 4 + strlen(dns_query.Domain_Name) + 1; // plus first dot(fragment len) len
				dns_offset += 5 + (uint16_t)strlen(dns_query.Domain_Name) + 1; // plus first dot(fragment len) len
			}
			else { // end with dns pointer
				dns_query.Query_Type = *(uint16_t*)(file_ptr+domain_addr_offset);
				dns_query.Query_Class = *(uint16_t*)(file_ptr+domain_addr_offset+sizeof(dns_query.Query_Type));
				dns_query.swap(is_big_endian);
				file_ptr += 4 + domain_addr_offset;
				dns_offset += 4 + domain_addr_offset;
			}
			qcnt += 1;
		}else
		{
			return dns_offset;
		}

	}
	return 0;
}

uint16_t ApplicationLayer::domain_process(uint16_t offset, char* ptr, char* ptr_cpy, char* domain)
{
	uint8_t domain_len = 0;
	while (1)
	{

		domain_len = *(uint8_t*)ptr;
		if (!domain_len)
		{
			domain[offset-1] = '\0';
			return 0;
		}
		if ((domain_len & 0xC0) == 0xC0)
		{
			this->domain_process(offset, ptr_cpy + (bswap_16(*(uint16_t*)ptr) & 0x3FFF), ptr_cpy, domain);
			return offset+ LEN_DNS_POINTER;
		}

		memcpy(domain + offset, ptr + 1, domain_len);
		ptr += domain_len+1;
		offset += domain_len + 1;
	}
	return 0;
}


uint16_t ApplicationLayer::dns_authority_parse(char* file_ptr, char* ptr_cpy, uint16_t len)
{

	return 0;
}

uint16_t ApplicationLayer::dns_addtional_parse(char* file_ptr, char* ptr_cpy, uint16_t len)
{

	return 0;
}