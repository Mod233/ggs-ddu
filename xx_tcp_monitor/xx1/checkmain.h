#ifndef _NG_CHECKMAIN_H
#define _NG_CHECKMAIN_H


#if defined(__FastPath__)
#include "fp-netgraph.h"
#include "netinet/fp-in.h"
#include "netinet/fp-ip.h"
#include "netinet/fp-udp.h"
#include "netinet/fp-tcp.h"
#include "fpn.h"
#include "fpn-mempool.h"
#include "fpn-ring.h"
#include "fpn-dpdk.h"
#include "rte_mempool.h"
#endif
#include <stdint.h>
#include <vector>
#include <string>
//替换flow结构体
typedef struct flow_array
{
	double packet_arrival_time_list[250];     //tcp包到达时间, 对包方向序列进行分片的依据，只需存前250个包
	char packet_sign_list[250];               //tcp包方向，0为由外向内，1为由由内向外
	int packet_size_list[250];		          //tcp包载荷长度，用于去心跳、去控制包等噪声
	char packet_flag_list[250];               //tcp包头标志，包括2保留位，及6个标志位：URG、ACK、PUSH、RST、SYN、FIN
	unsigned int sequence[250];
	unsigned short srcport[250];
	std::vector<std::string> data;
	unsigned long  len;
}flow_array;

typedef struct flow                          //重要数据结构，存储流中包信息，以ip对和传输层协议类型三元组为分流依据，协议类型为tcp
{
	int packet_number;		                  //流中当前包个数，包个数达到250时，开始后续处理和木马判断
	char alarm;
	uint32_t srcip;
	uint32_t dstip;
	struct flow *next;
	flow_array *array_ptr;
	std::vector<std::string> data;
}flow;

typedef struct _cluster                       //重要数据结构，存储流分片后所得包簇信息，成员与流结构体中对应，分片处理后无需tcp包头标志
{
	int packet_number;//一个簇中包含的包的个数
	double *packet_arrival_time_list;//对应流的到达时间
	char *packet_sign_list;//包方向
	unsigned int *sequence;
	int *packet_size_list;//包大小
}cluster;
typedef struct po
{
	int num;//包个数
	double time[250];//包到达时间
}po;
//基于频繁项挖掘的去心跳算法相关结构体
typedef struct             //项结构体
{
	int size[4];           //每个项最多包涵四个元素，元素为带方向的包大小
}_item;
typedef struct             //项集结构体
{
	int num;               //项集中项的个数
	int size;              //项集中项的大小，也即项中元素个数
	_item item[250];       //项数组，设项集中最多可能有250个项集
}set;

int packet_capture();

#endif /* _NG_CHECKMAIN_H */
