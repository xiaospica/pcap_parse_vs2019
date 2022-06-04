#include "utils.h"
#include <fmt/core.h>

int arrayToMac(const uint8_t* array, char* macaddr) {

	//sprintf(macaddr, "%02x-%02x-%02x-%02x-%02x-%02x\0",
	//	array[0], array[1], array[2], array[3], array[4], array[5]);
	//fmt::format_to(macaddr, "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}\0}", 
	//	array[0], array[1], array[2], array[3], array[4], array[5]);
	
	int j = 0;
	for (int i = 5; i >= 0; i--)
	{
		int val = array[i];
		while (val)
		{
			if ((j+1)%3 == 0)
			{
				macaddr[j++] = '-';
			}
			else
			{
				uint8_t k = val & 0x0F;
				macaddr[j++] = mac_table[k];
				val >>= 4;
			}
		}
	}
	macaddr[17] = '\0';

	return 0;
}

uint16_t bswap_16(uint16_t x){

	return (((uint16_t)(x) & 0x00ff) << 8) | \
		(((uint16_t)(x) & 0xff00) >> 8);

}

uint32_t bswap_32(uint32_t x) {
	return ((x >> 24) & 0xff) |
		((x << 8) & 0xff0000) |
		((x >> 8) & 0xff00) |
		((x << 24) & 0xff000000);
}

void ip_int_to_str(uint32_t ip, char* ip_str)
{
	unsigned char bytes[4];
	bytes[0] = ip & 0xFF;
	bytes[1] = (ip >> 8) & 0xFF;
	bytes[2] = (ip >> 16) & 0xFF;
	bytes[3] = (ip >> 24) & 0xFF;
	//sprintf(ip_str, "%d.%d.%d.%d\0", bytes[3], bytes[2], bytes[1], bytes[0]);
	
	memset(ip_str, 0, 16);
	size_t l_len = 0;
	for (int8_t i=3;i>=0;i--)
	{
		//strcat(ip_str, _table[bytes[i]]);

		size_t s_len = strlen(ip_table[bytes[i]]);
		memcpy(ip_str+l_len, ip_table[bytes[i]], s_len);
		l_len += s_len;
	}
}

uint8_t bit_reverse(uint8_t b) {
	b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
	b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
	b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
	return b;
}

void to_date(time_t n, char* timestrbuf)
{
	long y, m, d, HH, MM, SS;
	y = n / years + 1970;
	m = n % years / months + 1;
	d = n % years % months / days + 1;
	HH = n % years % months % days / 3600;
	MM = n % years % months % days % 3600 / 60;
	SS = n % years % months % days % 3600 % 60;

	//sprintf(timestrbuf, "[%d/%d/%d %d:%d:%d]", y, m, d, HH, MM, SS);
	const char* y_str = year_table[y-2019];
	const char* m_str = month_table[m-1];
	const char* d_str = day_table[d-1];
	const char* HH_str = hour_table[HH];
	const char* MM_str = min_table[MM];
	const char* SS_str = min_table[SS];
	size_t offset = 0;
	memcpy(timestrbuf, y_str, strlen(y_str));
	offset = strlen(y_str);
	memcpy(timestrbuf+offset, m_str, strlen(m_str));
	offset += strlen(m_str);
	memcpy(timestrbuf + offset, d_str, strlen(d_str));
	offset += strlen(d_str);
	memcpy(timestrbuf + offset, HH_str, strlen(HH_str));
	offset += strlen(HH_str);
	memcpy(timestrbuf + offset, MM_str, strlen(MM_str));
	offset += strlen(MM_str);
	memcpy(timestrbuf + offset, SS_str, strlen(SS_str));
	//offset += strlen(SS_str);
}