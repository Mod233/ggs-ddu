//============================================================================
// Name        : dns_c.cpp
// Author      : cs
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

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
#include <vector>
#include <unistd.h>
#include <dirent.h>
#include <pthread.h>
//#include <thread>
#include <netinet/udp.h>

//#include "debug.h"
#define SHOW_CHILD_PATH 1
#define JUDGE_FILE 1
//#include "stream_to_vector.h"
char dir[] = "/home/csober/Documents/Github/ggs-ddu/Trojan-beta/SplitedFlow/dns";
struct dns_packet{
	bool malformed;

};
struct dns_vector{
	int port;
	int domain_num;
	double time;
	std::string name;
	long long upload;
	int upload_num;
	long long download;
	int download_num;
	int malformed_num;
	int transaction_num;
	int max_host_name_num;
	dns_packet pkt[300];
	dns_vector(){
		port = 0;
		domain_num = 0;
		time = 0.0;
		upload = 0;
		upload_num = 0;
		download = 0;
		download_num = 0;
		malformed_num = 0;
		transaction_num = 0;
		max_host_name_num = 0;
	}
	void init(){
		port = 0;
		domain_num = 0;
		time = 0.0;
		upload = 0;
		upload_num = 0;
		download = 0;
		download_num = 0;
		malformed_num = 0;
		transaction_num = 0;
		max_host_name_num = 0;
	}
};

//#include "dns.h"
struct dnshdr{
	u_int16_t id;
	u_int16_t flags;
	u_int16_t qsnum;
	u_int16_t anrnum;
	u_int16_t aurnum;
	u_int16_t adrnum;
};

//#include "stream_to_vector.cpp"
std::map<std::string, int> show;
std::map<std::pair<std::string,std::string>, int> hostnum;
std::map<std::string, int> white_list;
/*
={{"qq.com", 1 }, {"baidu.com", 1}, {"sina.com", 1}, {"google.com", 1},\
{"4399.com", 1}, {"youku.com", 1}, {"souhu.com", 1}, {"taobao.com", 1},{"sina.com", 1},{"dgso.com", 1},\
{"163.com", 1},{"hao123.com", 1},{"tudou.com", 1},{"pps.tv", 1}, {"xunlei.com", 1}, {"sogou.com", 1},\
{"56.com"1, }, {"tmall.com", 1},{"ku6.com", 1},{"ifeng.com", 1},{"360.cn", 1}, {"so.com", 1}, \
{"2345.com", 1},{"qiyi.com", 1},{"alipay.com", 1},{"renren.com", 1},{"sm.cn", 1},{"zol.com", 1},

		              "tianya.cn", "paipai.com", "microsoft.com", "pptv.com", "kugou.com", "joy.cn", "96pk.com", "10086.cn", "pomoho.com", "youdao.com",
		              "58.com", "xinhuanet.com", "letv.com", "mop.com", "m18.com", "douban.com", "zhihu.com", "sdo.com", "alibaba.com",
		              "funshion.com", "vancl.com", "126.com", "wushen.com", "6.cn", "soufun.com", "jiayuan.com", "china.com", "csdn.com",
		              "bilibili.com", "kugou.com", "jd.com", "jingdong.com", "meituan.com", "dnion.com", "version.bind", "activum.nu", "VERSION.BIND"]

};
	 */

dns_vector dns_stream_to_vector(char*dir){
	show.clear();
	hostnum.clear();
	dns_vector cur_flow;
	cur_flow.init();
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	const u_char *packet;
	struct pcap_pkthdr hdr;
	struct iphdr *ipptr;
	struct udphdr *udpptr;
	struct dnshdr *dnsptr;
	char dnsbuf[1<<12];
	descr = pcap_open_offline(dir,errbuf);
	if(descr == NULL){
		printf("pcap_open_offline(): %s\n", errbuf);
		printf("%s\n", dir);
		pcap_close(descr);
		return cur_flow;
	}
	int cnt = 0;
	struct in_addr srcip, dstip;
	std::string sip, dip, name;
	bool tag;
	while(true){
	//	printf("%d\n", cnt);
		packet = pcap_next(descr, &hdr);
		if(packet == NULL){
//			printf("FINISH READING\n");
			break;
		}
		ipptr = (struct iphdr*)(packet + sizeof(ether_header));
		udpptr = (struct udphdr*)(packet + sizeof(ether_header) + (ipptr->ihl)*4);
		dnsptr = (struct dnshdr*)(packet + sizeof(ether_header) + (ipptr->ihl)*4 + 8);
		memset(dnsbuf, 0, sizeof(dnsbuf));
		srcip.s_addr = in_addr_t(ipptr->saddr);
		dstip.s_addr = in_addr_t(ipptr->daddr);
		uint16_t sport = ntohs(udpptr->source);
		uint16_t dport = ntohs(udpptr->dest);
		sip = inet_ntoa(srcip);
		dip = inet_ntoa(dstip);
		tag = 0;
		int dnslen = ntohs(udpptr->len) - 8;
		if(dnslen < 1) continue;
		if(dport==uint16_t(53)) {cur_flow.upload_num++;cur_flow.upload+=dnslen;}
		else {cur_flow.download_num++;cur_flow.download+=dnslen;}

		//if a packet is too small , do not
		if(dnslen<10) continue;
		cnt++;
		memcpy(dnsbuf, (packet + sizeof(ether_header) + (ipptr->ihl)*4 + 8 + 12), dnslen);
		if((ntohs(dnsptr->qsnum) > u_int16_t(5)) || (ntohs(dnsptr->anrnum) > u_int16_t(100)) || (ntohs(dnsptr->aurnum) > u_int16_t(100)) || (ntohs(dnsptr->adrnum)>u_int16_t(100))){
			cur_flow.pkt[cnt].malformed = true;
			cur_flow.malformed_num++;
			continue;
		}
		else cur_flow.pkt[cnt].malformed = false;
		if( dnslen != ntohs(udpptr->len)-8){
			cur_flow.pkt[cnt].malformed = true;
			cur_flow.malformed_num++;
			continue;
		}
		for(int i=0;i<ntohs(dnsptr->qsnum);i++){
			int pos = 0;
			int cnt = 0;
			std::string domain = "";
			while(dnsbuf[pos]!='\x00'){
				cnt = int(dnsbuf[pos]);
				for(int i=1;i<=cnt;i++)
					domain += dnsbuf[++pos];
				pos++;
				if(dnsbuf[pos]=='\x00')break;
				domain += '.';
			}
			int dotpos;
			int dotnum = 0;
			int secdotpos;
			for(int j = domain.length()-1;j>=0;j--)
				if(domain[j]=='.'){
					dotnum++;
					if(dotnum==2)
						secdotpos=j;
				}
			if(dotnum==1){
				if(show.count(domain)) continue;
				else{
					cur_flow.domain_num++;
					show[domain]=1;
				}
			}
			else if(dotnum>1){
				std::string topdomain = domain.substr(secdotpos+1);
				std::string hostname = domain.substr(0,secdotpos);
				std::pair<std::string,std::string> cur_pair = make_pair(topdomain,hostname);
				//std::cout<<"topdomain is "<<topdomain<<" hostname is "<<hostname<<std::endl;
				//printf("topdomain is %s  hostname is %s\n", topdomain, hostname);
				if(hostnum.count(cur_pair)) continue;
				else {
					hostnum[cur_pair] = 1;
					show[topdomain]++;
				}
				if(white_list.count(topdomain)){
					if(dport==uint16_t(53)) {cur_flow.upload_num--;cur_flow.upload-=dnslen;}
					else {cur_flow.download_num--;cur_flow.download-=dnslen;}
				}
			}
		}
	}
	return cur_flow;
}




//#include "judge_dns.h"

//#include "judge_dns.cpp"
int judge_dns(dns_vector cur){
	cur.max_host_name_num = -1;
	for(std::map<std::string, int>::iterator i=show.begin();i!=show.end();i++)
		cur.max_host_name_num = std::max(cur.max_host_name_num, i->second);
	if(cur.malformed_num>50)
		return 1;
	else if(cur.max_host_name_num>70)
		return 2;
	else
		return 0;
}

// main

void highlight_output(int color_id, char*msg){
	//"RED": 31, "GREEN": 32, "YELLOW": 33, "BLUE": 34, "PURPLE": 35, "CYAN": 36, "GREY": 37, "WHITE": 38
	printf("\033[1;%dm%s\033[1;0m\n", color_id, msg);
}


int read_file(char* base_dir){
	DIR* pdir;
	struct dirent * ent;
	char childpath[512];
	pdir = opendir(base_dir);
	memset(childpath, 0, sizeof(childpath));
	while((ent = readdir(pdir)) != NULL){
		sprintf(childpath, "%s/%s", base_dir, ent->d_name);
		if(ent->d_type & DT_DIR){
			if((strcmp(ent->d_name, ".")==0) || (strcmp(ent->d_name, ".."))==0) continue;
			read_file(childpath);
		}
		else{
#if(SHOW_CHILD_PATH)
			printf("childpath is %s\n", childpath);
#endif
			dns_vector cur = dns_stream_to_vector(childpath);
			int ret = judge_dns(cur);
			if(ret){
				int pos;
				for(pos = strlen(childpath)-1;pos>=0;pos--) if(childpath[pos]=='/') break;
				std::string filename = std::string(childpath+pos+1);
				std::string warning;
				if(ret==1) warning= "dns-malformed - " + filename;
				else warning = "dns-max_host_name - " + filename;
				//printf("https-dangerous - %s\n", filename.c_str());
				highlight_output(31, (char*)warning.c_str());
				filename = "/home/csober/Documents/Github/ggs-ddu/Trojan-beta/Warning/dns_warning/"+ filename;
				std::string cmd = "cp " + std::string(childpath) + std::string(" ") + filename;
				system(cmd.c_str());
			}
		}
	}
	return 0;
}

int main(int argc,const char*argv[]){
	printf("starting!\n");
#if(JUDGE_FILE)
	read_file(dir);
#endif
	printf("ending\n");
	printf("\n\n");
	return 0;
}













