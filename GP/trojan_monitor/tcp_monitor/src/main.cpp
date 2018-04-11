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
#elif WIN32
#include <direct.h>
#endif
#define JUDGE_FILE 1
#define SHOW_CHILD_PATH 1

char dir[] = "/mnt/myusbmount/Trojan_Monitor/IP_FLOW2/tcp_noack";



// 比较核心的时间分片
#if(0)
int apriori_heatbeat(int slice_num, double min_support, tid_vector* ite){
	int threshold;
	threshold = slice_num*4/ceil(slice_num*min_support);
	std::map<int,int> ck;
	std::map<int,int> lk;
	std::map<int,int> show;
	show.clear();
	for(int i=0;i<slice_num;i++){
		int len = clu[i].pkt_num;
		for(int j=0;j<len;j++){
			int tmp = clu[i].pkt_tag[j]?clu[i].pkt_size[j]:-clu[i].pkt_size[j];
			if(show.count(tmp)) {show[tmp]++;ck[tmp]++;}
			else{
				show[tmp] = 1;
				ck[tmp] = 1;
			}
		}
	}
	for(std::map<int,int>::iterator i=ck.begin();i!=ck.end();i++)
		if(i->second < min_support) ck.erase(i);

}
#endif


int read_file(char* base_dir){
	DIR* pdir;
	struct dirent *ent;
	char childpath[512];
	pdir = opendir(base_dir);
	memset(childpath,0,sizeof(childpath));
	while((ent = readdir(pdir))!=NULL){
		sprintf(childpath, "%s/%s", base_dir, ent->d_name);
		if(ent->d_type & DT_DIR){
			if((strcmp(ent->d_name, ".") == 0) || (strcmp(ent->d_name, "..") == 0)) continue;
			read_file(childpath);
		}
		else{
#if(SHOW_CHILD_PATH)
			printf("childpath is %s\n", childpath);
#endif
			flow_vector cur = stream_to_vector(childpath);
			int ret = judge_tcp(cur);
			if(ret)
				printf("######################\n%s is dangerous\n######################\n", childpath);
		}
	}
	return 0;
}


int main(int argc,const char*argv[]) {
#if(JUDGE_FILE)
	read_file(dir);
#else
	flow_vector cur =stream_to_vector(dir);
	int ret = judge_tcp(cur);
	if(ret)
		printf("%s is dangerous\n", dir);
#endif
	printf("Finish!\n");
	return 0;
}
