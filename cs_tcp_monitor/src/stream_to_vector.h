/*
 * stream_to_vector.h
 *
 *  Created on: Apr 9, 2018
 */

#ifndef STREAM_TO_VECTOR_H_
#define STREAM_TO_VECTOR_H_
#include <sys/types.h>
#include <string>
#include <string.h>
#define PKT_NUM 320

struct dns_vector {
	int port;
	int domain_num;
	int onedot_num;
	double time;
	int pkt_num;
	int txt_num;
	int mail_num;
	std::string name;
	long long upload;
	int upload_num;
	long long download;
	int download_num;
	int malformed_num;
	int transaction_num;
	int max_host_name_num;

};

struct dnshdr {
	u_int16_t id;
	u_int16_t flags;
	u_int16_t qsnum;
	u_int16_t anrnum;
	u_int16_t aurnum;
	u_int16_t adrnum;
};

struct tcp_vector {
	std::string name;
	double pkt_time[PKT_NUM];
	unsigned short pkt_size[PKT_NUM];
	bool pkt_tag[PKT_NUM];
	int pkt_num;
};

struct cluster_vector {
	int pkt_num;
	double pkt_time[PKT_NUM];
	unsigned int pkt_size[PKT_NUM];
	bool pkt_tag[PKT_NUM];
};

struct tid_vector {
	int tid_size;
	int tid_item[PKT_NUM][4];
};

struct flow_vector {
	dns_vector dns;
	tcp_vector tcp;
//	u_int32_t ip_big;
//	u_int32_t ip_small;
//	int
};

void tcp_stream_to_vector(const u_char*packet, struct pcap_pkthdr hdr);

void dns_stream_to_vector(const u_char*packet, struct pcap_pkthdr hdr);

#endif /* STREAM_TO_VECTOR_H_ */
