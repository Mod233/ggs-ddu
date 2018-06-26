/*
 * stream_to_vector.cpp
 *
 *  Created on: Apr 9, 2018
 *      Author: csober
 */

#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <math.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "judge_out_control.h"
#include <pcap.h>
#include <string>
#include <iostream>
#include "debug.h"
#include "init.h"
#define KNOW_INTRANET 1
#define KNOW_EXTRANET 0
#define HOLE_SIZE 600
#define MAX(a,b) ((a)>(b)?(a):(b))
#define MIN(a,b) ((a)>(b)?(b):(a))
//unsigned int subnet_intranet = ntohl(inet_addr("10.0.0.0")); //存储子网ip，用于区分内部IP地址和外部IP地址
//unsigned int subnet_extranet = ntohl(inet_addr("108.0.0.0")); //存储子网ip，用于区分内部IP地址和外部IP地址
//unsigned int subnet_mask = ntohl(inet_addr("255.0.0.0"));  //设定子网掩码，用于区获取子网号

flow_vector all_flow[IP_SIZE]; //when to init??
bool warn[IP_SIZE];
bool vis_domain[IP_SIZE][HOLE_SIZE]; //ip_num-topdomain-hostname
bool white_list[HOLE_SIZE];
int host_name_num[IP_SIZE][HOLE_SIZE];

void dns_stream_to_vector(const u_char*packet, struct pcap_pkthdr hdr) {
	struct iphdr *ipptr;
	struct udphdr *udpptr;
	struct dnshdr *dnsptr;
	char dnsbuf[1 << 12];
	struct in_addr srcip, dstip;
	char domain[200];
	char topdomain[100];
	char hostname[100];
	ipptr = (struct iphdr*) (packet + sizeof(ether_header));
	udpptr =
			(struct udphdr*) (packet + sizeof(ether_header) + (ipptr->ihl) * 4);
	dnsptr = (struct dnshdr*) (packet + sizeof(ether_header) + (ipptr->ihl) * 4
			+ 8);
	memset(dnsbuf, 0, sizeof(dnsbuf));
	srcip.s_addr = in_addr_t(ipptr->saddr);
	dstip.s_addr = in_addr_t(ipptr->daddr);
	uint16_t sport = ntohs(udpptr->source);
	uint16_t dport = ntohs(udpptr->dest);
	int dnslen = ntohs(udpptr->len) - 8;

	if (dnslen < 1)
		return;
	int ip_num = ip_mkhash(ipptr->saddr, ipptr->daddr);
	if (warn[ip_num])
		return;
	// new add
#if(0)
	if (all_flow[ip_num].tcp.pkt_num + all_flow[ip_num].dns.pkt_num) {
		if (MAX(ipptr->saddr, ipptr->daddr) != all_flow[ip_num].ip_big
				&& MIN(ipptr->saddr, ipptr->daddr)
				!= all_flow[ip_num].ip_small) {
			if (all_flow[ip_num].crash_num > 90)
			memset(&all_flow[ip_num], 0, sizeof(flow_vector));
			else {
				all_flow[ip_num].crash_num++;
				return;
			}
		} else {
			all_flow[ip_num].crash_num = 0;
		}
	} else {
		all_flow[ip_num].ip_big = MAX(ipptr->saddr, ipptr->daddr);
		all_flow[ip_num].ip_small = MIN(ipptr->saddr, ipptr->daddr);
	}
	// finish
#endif
	if (dport == uint16_t(53)) {
		all_flow[ip_num].dns.upload_num++;
		all_flow[ip_num].dns.upload += dnslen;
	} else {
		all_flow[ip_num].dns.download_num++;
		all_flow[ip_num].dns.download += dnslen;
	}
	if (dnslen < 10)
		return;
	int cnt = all_flow[ip_num].dns.pkt_num; //++;
	memcpy(dnsbuf, (packet + sizeof(ether_header) + (ipptr->ihl) * 4 + 8 + 12),
			dnslen);
	if ((ntohs(dnsptr->qsnum) > u_int16_t(5))
			|| (ntohs(dnsptr->anrnum) > u_int16_t(100))
			|| (ntohs(dnsptr->aurnum) > u_int16_t(100))
			|| (ntohs(dnsptr->adrnum) > u_int16_t(100))) {
		all_flow[ip_num].dns.malformed_num++;
	}
	if (dnslen != ntohs(udpptr->len) - 8) {
		all_flow[ip_num].dns.malformed_num++;
	}
	memset(hostname, 0, sizeof(hostname));
	memset(topdomain, 0, sizeof(topdomain));
	for (int i = 0; i < ntohs(dnsptr->qsnum); i++) {
		int pos = 0;
		int cnt = 0;
		memset(domain, 0, sizeof(domain));
		int domain_pos = 0;
		while (dnsbuf[pos] != '\x00') {
			cnt = int(dnsbuf[pos]);
			for (int i = 1; i <= cnt; i++)
				domain[domain_pos++] = dnsbuf[++pos];
			pos++;
			if (dnsbuf[pos] == '\x00')
				break;
			domain[domain_pos++] = '.';
		}
		int dotpos;
		int dotnum = 0;
		int secdotpos;
		int firdotpos;
		for (int j = domain_pos - 1; j >= 0; j--)
			if (domain[j] == '.') {
				dotnum++;
				if (dotnum == 2)
					secdotpos = j;
				else if (dotnum == 1)
					firdotpos = j;
			}
		int hash_domain = string_mkhash(domain);
		if (dotnum > 1) {
			memcpy(topdomain, (domain + secdotpos + 1),
					domain_pos - secdotpos - 1);
			memcpy(hostname, domain, secdotpos);
//			printf("topdomain is %s hostname is %s\n", topdomain, hostname);
			int hash_domain = string_mkhash(domain) % HOLE_SIZE;
			int hash_topdomain = string_mkhash(topdomain) % HOLE_SIZE;
//			printf("%d %d\n", hash_domain, hash_topdomain);
			if (vis_domain[ip_num][hash_domain])
				continue;
			else {
				vis_domain[ip_num][hash_domain] = true;
				host_name_num[ip_num][hash_topdomain]++;
//				highlight_output(31, "host_num_num is ");
//				printf("host_num_num is %d\n",
//						host_name_num[ip_num][hash_topdomain]);
#if(DEBUG)
				printf("domain is %s\nhost is %s topdomain is %s\n\n", domain,hostname,topdomain);
#endif
			}
		}
		//how about a domain do not have dot??
		else {
			all_flow[ip_num].dns.onedot_num++;
		}
		pos++;
		int type = int(dnsbuf[pos++]);
		type = type << 8 + int(dnsbuf[pos++]);
		if (type == 16)
			all_flow[ip_num].dns.txt_num++;
		else if (type == 15)
			all_flow[ip_num].dns.mail_num++;
	}
	all_flow[ip_num].dns.pkt_num++;
//	printf("pkt_num is %d\n", all_flow[ip_num].dns.pkt_num);
	if (all_flow[ip_num].dns.pkt_num > 250) {
		all_flow[ip_num].dns.max_host_name_num = -1;
		for (int i = 0; i < HOLE_SIZE; i++) {
			all_flow[ip_num].dns.max_host_name_num =
					all_flow[ip_num].dns.max_host_name_num
							> host_name_num[ip_num][i] ?
							all_flow[ip_num].dns.max_host_name_num :
							host_name_num[ip_num][i]; //max(cur_flow.max_host_name_num,host_name_num[i]);
#if(DEBUG)
							if(host_name_num[i])
							printf("%d host num is %d\n", i, host_name_num[i]);
#endif
		}
#if(DEBUG)
		printf("the max host name is %d\n", cur_flow.max_host_name_num);
#endif
#if(SHOW_DNS_VECTOR)
		printf("dns flow vector is \n");
		printf(
				"max_host_name_num is %d, malform_num is %d\n txt_num is %d mail_num is %d\n onedot_num is %d\n",
				all_flow[ip_num].dns.max_host_name_num,
				all_flow[ip_num].dns.malformed_num,
				all_flow[ip_num].dns.txt_num, all_flow[ip_num].dns.mail_num,
				all_flow[ip_num].dns.onedot_num);
#endif
		int res = judge_dns(all_flow[ip_num].dns);
		if (res) {
			warn[ip_num] = 1;
			printf("\033[1;31mdns-%s-", inet_ntoa(dstip));
			printf("%s is dangerous\033[1;0m\n", inet_ntoa(srcip));
		}
		memset(vis_domain[ip_num], 0, HOLE_SIZE);
		memset(&all_flow[ip_num].dns, 0, sizeof(dns_vector));
		memset(host_name_num[ip_num], 0, HOLE_SIZE);
	}
	return;
}

void tcp_stream_to_vector(const u_char*packet, struct pcap_pkthdr hdr) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	struct iphdr *ipptr;
	struct tcphdr *tcpptr;
	char tcpbuf[1 << 12];
	struct in_addr srcip, dstip;
	bool tag;
	ipptr = (struct iphdr*) (packet + sizeof(ether_header));
	tcpptr =
			(struct tcphdr*) (packet + sizeof(ether_header) + (ipptr->ihl) * 4);
	memset(tcpbuf, 0, sizeof(tcpbuf));
	srcip.s_addr = in_addr_t(ipptr->saddr);
	dstip.s_addr = in_addr_t(ipptr->daddr);
	tag = 0;
	// 1: in->out 0:out->in
#if(KNOW_INTRANET)
	if ((ntohl(ipptr->saddr) & subnet_mask) == subnet_intranet
			&& (ntohl(ipptr->daddr) & subnet_mask) == subnet_intranet)
		return;
	else if ((ntohl(ipptr->saddr) & subnet_mask) != subnet_intranet
			&& (ntohl(ipptr->daddr) & subnet_mask) != subnet_intranet)
		return;
	else if ((ntohl(ipptr->saddr) & subnet_mask) == subnet_intranet)
		tag = 1;
	else {
		tag = 0;
	}
#elif(KNOW_EXTRANET)
	if( (ntohl(ipptr->saddr) & subnet_mask) == subnet_extranet &&
			(ntohl(ipptr->daddr) & subnet_mask) == subnet_extranet)
	return;
	else if((ntohl(ipptr->saddr) & subnet_mask) != subnet_extranet &&
			(ntohl(ipptr->daddr) & subnet_mask) != subnet_extranet)
	return;
	else if((ntohl(ipptr->saddr) & subnet_mask) != subnet_extranet) tag = 1;
	else {
		tag = 0;
	}
#endif
	int ip_num = ip_mkhash(tag ? ipptr->saddr : ipptr->daddr,
			tag ? ipptr->daddr : ipptr->saddr);
	if (warn[ip_num])
		return;
	// new add
	if (all_flow[ip_num].tcp.pkt_num + all_flow[ip_num].dns.pkt_num) {
		if (MAX(ipptr->saddr, ipptr->daddr) != all_flow[ip_num].ip_big
				&& MIN(ipptr->saddr, ipptr->daddr)
						!= all_flow[ip_num].ip_small) {
			if (all_flow[ip_num].crash_num > 90)
				memset(&all_flow[ip_num], 0, sizeof(flow_vector));
			else {
				all_flow[ip_num].crash_num++;
				return;
			}
		} else {
			all_flow[ip_num].crash_num = 0;
		}
	} else {
		all_flow[ip_num].ip_big = MAX(ipptr->saddr, ipptr->daddr);
		all_flow[ip_num].ip_small = MIN(ipptr->saddr, ipptr->daddr);
	}
	// finish
	int cnt = all_flow[ip_num].tcp.pkt_num;
	all_flow[ip_num].tcp.pkt_size[cnt] = ntohs(ipptr->tot_len)
			- (ipptr->ihl) * 4 - (tcpptr->th_off) * 4;
	//hdr.caplen;

	all_flow[ip_num].tcp.pkt_tag[cnt] = tag;
	all_flow[ip_num].tcp.pkt_time[cnt] = double(hdr.ts.tv_sec)
			+ double(hdr.ts.tv_usec / 1000000.0);
	all_flow[ip_num].tcp.pkt_num++;
	if (all_flow[ip_num].tcp.pkt_num > 299) {
//		printf("go judge\n");
		int res = judge_tcp(all_flow[ip_num].tcp);
//		printf("end judge\n");
		if (res == 1) {
			warn[ip_num] = 1;
//			std::string sip = inet_ntoa(srcip);
//			std::string dip = inet_ntoa(dstip);
//			std::cout << "here sip and dip is " << sip << "  " << dip
//					<< std::endl;
			printf("\033[1;31mtcp-%s-", inet_ntoa(dstip));
			printf("%s is dangerous\033[1;0m\n", inet_ntoa(srcip));
		}
		memset(&all_flow[ip_num].tcp, 0, sizeof(tcp_vector));
	}
	return;
}

