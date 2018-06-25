#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <errno.h>
#include <sys/socket.h>
#include <iostream>
#include <netinet/in.h>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <map>
#include <set>
#include <cmath>
#include <vector>
#include <netinet/udp.h>
#include "stream_to_vector.h"
#include "judge_out_control.h"
#ifdef linux
#include <unistd.h>
#include <dirent.h>
#include "debug.h"
#include "init.h"
#elif WIN32
#include <direct.h>
#endif

unsigned int subnet_intranet; //存储子网ip，用于区分内部IP地址和外部IP地址
unsigned int subnet_extranet; //存储子网ip，用于区分内部IP地址和外部IP地址
unsigned int subnet_mask;  //设定子网掩码，用于区获取子网号

char dir_https[] =
		"/home/csober/Documents/Github/ggs-ddu/Trojan-beta/SplitedFlow/https_noack";
char dir_dns[] =
		"/home/csober/Documents/Github/ggs-ddu/Trojan-beta/SplitedFlow/dns";

void sniff_pcap(const char* dir) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	const u_char *packet;
	struct pcap_pkthdr hdr; /* pcap.h */
	struct iphdr *ipptr;
	struct tcphdr *tcpptr;
	struct udphdr *udpptr;
	struct ethhdr *ethptr;
	struct ether_header *eptr;
	char tcpbuf[1 << 12];
	descr = pcap_open_offline(dir, errbuf);
	if (descr == NULL) {
		printf("pcap_open_offline(): %s\n", errbuf);
		printf("%s\n", dir);
		pcap_close(descr);
	}
	struct in_addr srcip, dstip;
	bool tag;
	int cnt = 0;
	while (true) {
		packet = pcap_next(descr, &hdr);
		if (packet == NULL) {
			break;
		}
		eptr = (struct ether_header *) packet;
		if (ntohs(eptr->ether_type) != 0x800)
			continue;
		ipptr = (struct iphdr*) (packet + sizeof(ether_header));
		if (ipptr->protocol == 6) {
			tcpptr = (struct tcphdr *) (packet + sizeof(ether_header)
					+ (ipptr->ihl) * 4);
			uint16_t sport = ntohs(tcpptr->source);
			uint16_t dport = ntohs(tcpptr->dest);
			int tcplen = ntohs(ipptr->tot_len) - (ipptr->ihl) * 4
					- (tcpptr->th_off) * 4;
			if (tcplen <= 0)
				continue;
			if (dport == uint16_t(443) || sport == uint16_t(443)) {
				if (packet[sizeof(ether_header) + (ipptr->ihl) * 4
						+ (tcpptr->th_off) * 4] != '\x17')
					continue;
			}
			cnt++;
//			printf("go stream to vector\n");
			tcp_stream_to_vector(packet, hdr);
//			printf("end stream to vector\n");
		} else if (ipptr->protocol == 17) {
			udpptr = (struct udphdr *) (packet + sizeof(ether_header)
					+ (ipptr->ihl) * 4);
			uint16_t sport = ntohs(udpptr->source);
			uint16_t dport = ntohs(udpptr->dest);
			int udplen = ntohs(ipptr->tot_len)
					- (sizeof(ether_header) - (ipptr->ihl) * 4 - 8);
			if (udplen < 0)
				continue;
			cnt++;
			dns_stream_to_vector(packet, hdr);
		}
	}
	pcap_close(descr);
	return;
}

int read_file(char* base_dir) {
	DIR* pdir;
	struct dirent *ent;
	char childpath[512];
	pdir = opendir(base_dir);
	highlight_output(32,
			"#######################     Dectecting  Begin     ########################\n");
	printf("\n");
	highlight_output(33,
			"#######################  Proproccessing PcapFile  ########################\n");
	memset(childpath, 0, sizeof(childpath));
	while ((ent = readdir(pdir)) != NULL) {
		sprintf(childpath, "%s/%s", base_dir, ent->d_name);
		if (ent->d_type & DT_DIR) {
			if ((strcmp(ent->d_name, ".") == 0)
					|| (strcmp(ent->d_name, "..") == 0))
				continue;
			read_file(childpath);
		} else {
#if(SHOW_CHILD_PATH)
			std::string msg = "Proproccessing " + std::string(childpath);
			highlight_output(34, (char*) msg.c_str());
			sniff_pcap((const char*) childpath);
			msg = "Finished " + std::string(childpath);
			highlight_output(34, (char*) msg.c_str());
#endif
		}
	}
	highlight_output(33,
			"#######################  Finished Proproccessing  ########################\n");
	closedir(pdir);
	return 0;
}

int main(int argc, const char*argv[]) {
	//char dir[] = "/mnt/myusbmount/Trojan_Monitor/tcp_trojan/cmdrat.pcap";
	if (argc != 3) {
		printf("Usage: ./https file ip");
		return 0;
	}
	subnet_intranet = ntohl(inet_addr(argv[2]));
	printf("%s\n", argv[1]);
	subnet_mask = ntohl(inet_addr("255.0.0.0"));
#if(JUDGE_FILE)
	read_file((char*) argv[1]);
#else
	sniff_pcap(argv[1]);
	printf("\n\n");
#endif
	return 0;
}
