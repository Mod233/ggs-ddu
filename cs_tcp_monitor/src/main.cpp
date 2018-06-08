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
#elif WIN32
#include <direct.h>
#endif

char dir_https[] =
		"/home/csober/Documents/Github/ggs-ddu/Trojan-beta/SplitedFlow/https_noack";
char dir_dns[] =
		"/home/csober/Documents/Github/ggs-ddu/Trojan-beta/SplitedFlow/dns";

void sniff_pcap(char* dir) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	const u_char *packet;
	struct pcap_pkthdr hdr; /* pcap.h */
	struct iphdr *ipptr;
	struct tcphdr *tcpptr;
	struct udphdr *udpptr;
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
		ipptr = (struct iphdr*) (packet + sizeof(ether_header));
		if (ipptr->protocol == 6) {
			tcpptr = (struct tcphdr *) (packet + sizeof(ether_header)
					+ (ipptr->ihl) * 4);
			uint16_t sport = ntohs(tcpptr->source);
			uint16_t dport = ntohs(tcpptr->dest);
			int tcplen = ntohs(ipptr->tot_len)
					- (sizeof(ether_header) - (ipptr->ihl) * 4
							- (tcpptr->th_off) * 4);
			if (tcplen < 0)
				continue;
			if (dport == uint16_t(443) || sport == uint16_t(443)) {
				if (packet[sizeof(ether_header) + (ipptr->ihl) * 4
						+ (tcpptr->th_off) * 4] != '\x17')
					continue;
			}
			cnt++;
			tcp_stream_to_vector(packet, hdr);
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

int main(int argc, const char*argv[]) {
	char dir[] = "/mnt/myusbmount/Trojan_Monitor/tcp_trojan/cmdrat.pcap";
	sniff_pcap(dir);
	printf("\n\n");
	return 0;
}
