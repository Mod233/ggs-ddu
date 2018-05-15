/**********************************************************************
版权说明：xupan编写
版本号：0.1
生成日期：2013-9-3
作者：xupan
内容：mysql数据库和C语音之间的一些接口函数的封装，错误变量的定义， 数据库连接相关的结构体定义
功能：简化C语音操作mysql数据库操作过程，减少出错的概率，力求编写健壮完善的数据库操作程序
和其他头文件关系：
修改日志：
	作者	时间		版本	描述
	xupan	2013-9-3	0.1		建立该文档
函数列表：
1.
2.
********************************************************************/
#include <pcap.h>

#define pcap_state_ok 0
#define pcap_open_adaper_failed 1
#define pcap_get_adaper_failed 2
#define pcap_open_whitelist_failed 3
#define pcap_compile_whitelist_failed 3
#define packet_capture_failed 4

class winpcap
{
public:
	pcap_if_t *alldevs;   //设备列表
	pcap_t *adhandle;	  //设备句柄
	unsigned int NetMask; //网络掩码
private:

public:
	int Get_Adapter_List();				//获取适配器列表
	int Open_Adapter(char* filename);	//打开pcap文件
	int Open_Rec_Adapter(int inum);		//打开适配器
	int Open_Rec_Adapter(int adapter_num, char* ruler);  //打开适配器
	int Open_Send_Adapter(int inum);
	void Close_Adapter();				//关闭适配器
	void Capture_packet();
};
