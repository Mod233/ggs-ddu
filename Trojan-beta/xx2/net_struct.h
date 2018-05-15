
/******************************************************************************
版权说明：xupan编写
版本号：0.1
生成日期：2013-9-3
作者：xupan
内容：各种数据结构的定义，这些数据结果包含：链路层，IP，tcp，udp数据包头部的定义； 
									  包含：会话特征结果结构体；
									  包含: 会话存储结构中小链表；
									  包含：会话建立函数
									  包含：函数操作出错的宏定义；
功能：组织数据结构，方便模块化。
	  函数具体定义存在文件heapmanage.cpp文件中
和其他头文件关系：
修改日志：
	作者		时间					版本		描述
	xupan	2013-9-3			0.1		建立该文档
	xupan   2013-10-30		0.2		修改会话特征存储结构， 添加存储字段， 多模匹配为开关模式
	开关为STRING_MATCH, 在net_struct.h文件中
函数列表：
1.
*******************************************************************************/

#include <stdint.h>
#include <time.h>

#define TCP_ID  6					//IP数据包中封装TCP数据包的ID
#define UDP_ID  17

/*********************************************************************************
网络数据包头部定义
**********************************************************************************/
typedef struct eth_hdr			//Ethernet Header Structure
{
	unsigned char   eth_dst[6];
	unsigned char   eth_src[6];
	unsigned short  eth_type;
}ETH_HDR;

typedef struct ip_hdr			//IP Header Structure
{
	unsigned char  ip_ver_hlen;  // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
	unsigned char  ip_tos;           // IP type of service
	unsigned short ip_total_length;  // Total length
	unsigned short ip_id;            // Unique identifier
	unsigned char  ip_fragment_id;

	unsigned char  ip_frag_offset ;        // Fragment offset field
	unsigned char  ip_ttl;           // Time to live
	unsigned char  ip_protocol;      // Protocol(TCP,UDP etc)
	unsigned short ip_checksum;      // IP checksum
	unsigned int   ip_srcaddr;       // Source address
	unsigned int   ip_destaddr;      // Destination address
}IPV4_HDR;

typedef struct udp_hdr			//UDP Header Structure
{
	unsigned short source_port;     // Source port no.
	unsigned short dest_port;       // Dest. port no.
	unsigned short udp_length;      // Udp packet length
	unsigned short udp_checksum;    // Udp checksum (optional)
}UDP_HDR;

typedef struct tcp_header		// TCP Header Structure
{ 
	unsigned short source_port;  // source port 
	unsigned short dest_port;    // destination port 
	unsigned int   sequence;     // sequence number - 32 bits 
	unsigned int   acknowledge;  // acknowledgement number - 32 bits 

	unsigned short hrf;          //首部长度+保留字段+码元比特

	unsigned short window;          // window 
	unsigned short checksum;        // checksum 
	unsigned short urgent_pointer;  // urgent pointer 
}TCP_HDR;
