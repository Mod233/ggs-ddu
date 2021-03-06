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
#include <netinet/udp.h>
using namespace std;
map<string,int> show;
#define DEBUG 1
int dns_ip(char*dir, string result){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */
    struct iphdr *ipptr;
    struct tcphdr *tcpptr;
    struct udphdr *udpptr;
    u_char *ptr;
    descr = pcap_open_offline(dir, errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_offlive(): %s\n",errbuf);
        exit(1);
    }
    show.clear();
    int cnt=1;
    while(true){
        printf("%d\n", cnt++);
        //cout<<"$$"<<endl;
    	packet = pcap_next(descr, &hdr);
    	if(packet == NULL){
    		printf("Finish reading!\n");
    		break;
    	}
    	eptr = (struct ether_header *) packet;
    	if(ntohs(eptr->ether_type) != 0x800) continue;
    	ipptr = (struct iphdr *) (packet+sizeof(ether_header));
    	if(ipptr->version != 4) continue;
    	struct in_addr srcip, dstip;
    	srcip.s_addr = in_addr_t(ipptr->saddr);
    	dstip.s_addr = in_addr_t(ipptr->daddr);
    	if(ipptr->protocol != 17) continue;
    	udpptr = (struct udphdr *)(packet+sizeof(ether_header)+sizeof(iphdr));
    	uint16_t dport = ntohs(udpptr->source);
    	uint16_t sport = ntohs(udpptr->dest);
    	string sip=inet_ntoa(srcip);
    	string dip=inet_ntoa(dstip);
    	if(dport != uint16_t(53) && sport != uint16_t(53)) continue;
    	string name;
    	if(dport == uint16_t(53)) name = dip+"-"+sip; //+":"+to_string(sport);
    	else name = sip + "-" + dip; //+":"+to_string(dport);
    	name = result + "/dns/" + name + string(".pcap");
    	FILE* pFile;
    	if(show.count(name)){
    		show[name]++;
    		pFile = fopen(name.c_str(),"a");
    		fwrite(&hdr.ts.tv_sec,1,4,pFile);
    		fwrite(&hdr.ts.tv_usec,1,4,pFile);
    		fwrite(&hdr.caplen,1,8,pFile);
    		fwrite(packet,1,hdr.caplen,pFile);
    		fclose(pFile);
    	}
    	else{
    		show[name] = 1;
    		pcap_file_header ph;
    		ph.magic = 0xa1b2c3d4;
    		ph.version_major = 0x02;
    		ph.version_minor = 0x04;
    		ph.thiszone = 0;
    		ph.sigfigs = 0;
    		ph.snaplen = 65535;
    		ph.linktype = 0x1;
    		pFile = fopen(name.c_str(), "w");
    		    	cout<<"$$"<<endl;
    		fwrite(&ph, 1, 24, pFile);
    		fwrite(&hdr.ts.tv_sec, 1, 4, pFile);
    		fwrite(&hdr.ts.tv_usec, 1, 4, pFile);
    		fwrite(&hdr.caplen, 1, 8, pFile);
    		fwrite(packet, 1, hdr.caplen, pFile);
    		    	cout<<"$$"<<endl;
    		fclose(pFile);
    	}
    }
    printf("Finish dns!\n");
    return 0;
}

int tcp_ip(char*dir, string result){
    char errbuf[PCAP_ERRBUF_SIZE];
    cout<<"pcap_file_header "<<sizeof(pcap_file_header)<<endl;
    cout<<"pcap_pkthdr "<<sizeof(pcap_pkthdr)<<endl;
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */
    struct iphdr *ipptr;
    struct tcphdr *tcpptr;
    struct udphdr *udpptr;
    u_char *ptr;
    descr = pcap_open_offline(dir,errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_offlive(): %s\n",errbuf);
        exit(1);
    }
    show.clear();
    while(true){
    	packet = pcap_next(descr,&hdr);
    	if(packet == NULL){
    		printf("Finish reading!\n");
    		break;
    	}
    	eptr = (struct ether_header *) packet;
    	if(ntohs(eptr->ether_type)!=0x800) continue;
    	ipptr = (struct iphdr *) (packet+sizeof(ether_header));
    	if(ipptr->version != 4) continue;
    	struct in_addr srcip,dstip;
    	srcip.s_addr = in_addr_t(ipptr->saddr);
    	dstip.s_addr = in_addr_t(ipptr->daddr);
    	if(ipptr->protocol != 6) continue;
    	udpptr = (struct udphdr *)(packet+sizeof(ether_header)+sizeof(iphdr));
    	uint16_t dport = ntohs(udpptr->source);
    	uint16_t sport = ntohs(udpptr->dest);
    	string sip=inet_ntoa(srcip);
    	string dip=inet_ntoa(dstip);
    	string name;
    	name = min(sip, dip) + '-' + max(sip, dip);
    	name = result + "/tcp/" + name + string(".pcap");
    	FILE* pFile;
    	if(show.count(name)){
    		show[name]++;
    		pFile=fopen(name.c_str(),"a");
    		fwrite(&hdr.ts.tv_sec,1,4,pFile);
    		fwrite(&hdr.ts.tv_usec,1,4,pFile);
    		fwrite(&hdr.caplen,1,8,pFile);
    		fwrite(packet,1,hdr.caplen,pFile);
    		fclose(pFile);
    	}
    	else{
    		show[name]=1;
    		pcap_file_header ph;
    		ph.magic=0xa1b2c3d4;
    		ph.version_major=0x02;
    		ph.version_minor=0x04;
    		ph.thiszone=0;
    		ph.sigfigs=0;
    		ph.snaplen=65535;
    		ph.linktype=0x1;
    		pFile=fopen(name.c_str(),"w");
    		fwrite(&ph,1,24,pFile);
    		fwrite(&hdr.ts.tv_sec,1,4,pFile);
    		fwrite(&hdr.ts.tv_usec,1,4,pFile);
    		fwrite(&hdr.caplen,1,8,pFile);
    		fwrite(packet,1,hdr.caplen,pFile);
    		fclose(pFile);
    	}
    }
    printf("Finish tcp\n");
    return 0;
}

int pair_ip(char*dir, string result){
    char errbuf[PCAP_ERRBUF_SIZE];
    cout<<"pcap_file_header "<<sizeof(pcap_file_header)<<endl;
    cout<<"pcap_pkthdr "<<sizeof(pcap_pkthdr)<<endl;
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */
    struct iphdr *ipptr;
    struct tcphdr *tcpptr;
    struct udphdr *udpptr;
    u_char *ptr;
    descr = pcap_open_offline(dir,errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_offlive(): %s\n",errbuf);
        exit(1);
    }
    show.clear();
    while(true){
    	packet = pcap_next(descr,&hdr);
    	if(packet == NULL){
    		printf("Finish reading!\n");
    		break;
    	}
    	eptr = (struct ether_header *) packet;
    	if(ntohs(eptr->ether_type)!=0x800) continue;
    	ipptr = (struct iphdr *) (packet+sizeof(ether_header));
    	if(ipptr->version != 4) continue;
    	struct in_addr srcip,dstip;
    	srcip.s_addr = in_addr_t(ipptr->saddr);
    	dstip.s_addr = in_addr_t(ipptr->daddr);
    	if(ipptr->protocol != 6 && ipptr->protocol != 17) continue;
    	udpptr = (struct udphdr *)(packet+sizeof(ether_header)+sizeof(iphdr));
    	uint16_t dport = ntohs(udpptr->source);
    	uint16_t sport = ntohs(udpptr->dest);
    	string sip=inet_ntoa(srcip);
    	string dip=inet_ntoa(dstip);
    	string name;
    	name = min(sip, dip) + '-' + max(sip, dip);
    	name = result + "/pair_ip/" + name + string(".pcap");
    	FILE* pFile;
    	if(show.count(name)){
    		show[name]++;
    		pFile=fopen(name.c_str(),"a");
    		fwrite(&hdr.ts.tv_sec,1,4,pFile);
    		fwrite(&hdr.ts.tv_usec,1,4,pFile);
    		fwrite(&hdr.caplen,1,8,pFile);
    		fwrite(packet,1,hdr.caplen,pFile);
    		fclose(pFile);
    	}
    	else{
    		show[name]=1;
    		pcap_file_header ph;
    		ph.magic=0xa1b2c3d4;
    		ph.version_major=0x02;
    		ph.version_minor=0x04;
    		ph.thiszone=0;
    		ph.sigfigs=0;
    		ph.snaplen=65535;
    		ph.linktype=0x1;
    		pFile=fopen(name.c_str(),"w");
    		fwrite(&ph,1,24,pFile);
    		fwrite(&hdr.ts.tv_sec,1,4,pFile);
    		fwrite(&hdr.ts.tv_usec,1,4,pFile);
    		fwrite(&hdr.caplen,1,8,pFile);
    		fwrite(packet,1,hdr.caplen,pFile);
    		fclose(pFile);
    	}
    }
    return 0;
}


int main(int argc, char **argv){
	printf("$$$$$$\n");
#if(!DEBUG)
    char dir[200];
    string result;
    printf("Input original flow dir\n");
    scanf("%s", dir);
    if(strlen(dir)>200 || strlen(dir)<0 ){
        printf("dir is too long!\n");
        return 0;
    }
    char dir2[50];
    printf("Input result flow dir\n");
    scanf("%s", dir2);
    if(strlen(dir2)>200 || strlen(dir2)<0){
        printf("result flow dir is too long\n");
        return 0;
    }
    result=string(dir2);
#else
    char dir[200] = "/mnt/myusbmount/Trojan_Monitor/luoyang/jindun1.pcap";
    string result = "/mnt/myusbmount/Trojan_Monitor/IP_FLOW";
#endif
    dns_ip(dir, result);
    tcp_ip(dir, result);
    pair_ip(dir, result);
    printf("Finish all\n");
    return 0;
}

