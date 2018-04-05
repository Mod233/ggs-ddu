
#include "winpcap.h"
#include "net_struct.h"
#include <netinet/in.h>

/********************************************************************************************* 
名称	：Get_Adapter_List 
功能	：获得网络适配器列表
被调用	：
调用	：无
输入	：无
输出	：网络适配器列表
返回值	：
其他	：

*********************************************************************************************/ 
int winpcap::Get_Adapter_List()
{
	int retcode;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *d;

	if(alldevs == NULL)
		pcap_freealldevs(alldevs);

	retcode = pcap_findalldevs(&alldevs, errbuf);
	if(retcode == -1)
	{
		alldevs = NULL;
		return pcap_get_adaper_failed;
	}
	for(d = alldevs; d != NULL ;d = d->next)
		printf("%s\n",d->name);
	return pcap_state_ok;
}

/********************************************************************************************* 
名称	：Open_Adapter 
功能	：打开pcap文件
被调用	：
调用	：无
输入	：无
输出	：pcap文件句柄adhandle
返回值	：
其他	：

*********************************************************************************************/
int winpcap::Open_Adapter(char* filename)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	if(alldevs == NULL)
		return pcap_open_adaper_failed;

	if ((adhandle = pcap_open_offline(filename,			// name of the device
		errbuf					// error buffer
		)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file %s\n",filename);
		pcap_freealldevs(alldevs);
		return pcap_open_adaper_failed;
	}
		
	pcap_freealldevs(alldevs);

	return pcap_state_ok;
}

/********************************************************************************************* 
名称	：Open_Rec_Adapter 
功能	：打开网卡适配器
被调用	：
调用	：无
输入	：网卡编号, 白名单文件white.txt
输出	：网卡适配器句柄adhandle
返回值	：
其他	：

*********************************************************************************************/
int winpcap::Open_Rec_Adapter(int adapter_num)
{
	int i;
	pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE];
	char ruler[7000];  //白名单规则长度 7000 约300个IP地址
	struct bpf_program  fcode;
	FILE *fp;

	if(alldevs == NULL)
		return -1;

	for(d = alldevs, i = 0; i < adapter_num-1 ;d = d->next, i++);
	

	/* Open the device */
	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		pcap_freealldevs(alldevs);
		return pcap_open_adaper_failed;
	}

	/*Get the write list*/
	if( (fp = fopen("white.txt","r")) !=0)
	{
		printf("Can't open the white list\n");
		pcap_freealldevs(alldevs);
		return pcap_open_whitelist_failed;
	}
	fgets(ruler, 7000, fp);
	if( fclose(fp) )
		printf("the file white.txt was not closed");

	/*Set Filter Ruler*/
	if(d->addresses != NULL)
	{
		NetMask = ((sockaddr_in*)(d->addresses->netmask))->sin_addr.s_addr;
	}
	else
		NetMask = 0xffffff;

	if(pcap_compile(adhandle, &fcode, ruler, 1, NetMask) < 0)//or udp port 53
	{
		pcap_close(adhandle);
		
		NetMask = 0;
		adhandle = NULL;

		return pcap_compile_whitelist_failed;
	}

	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		pcap_close(adhandle);

		NetMask = 0;
		adhandle = NULL;
		return pcap_compile_whitelist_failed;
	}

	printf("[STATUS]	Filter ruler: %s.\n", ruler);
	printf("[STATUS]	Open the device %s.\n", d->name);
	pcap_freealldevs(alldevs);
	return 0;
}
/********************************************************************************************* 
名称	：Open_Rec_Adapter 
功能	：打开网卡适配器
被调用	：
调用	：无
输入	：网卡编号, 抓包规则过滤数组
输出	：网卡适配器句柄adhandle
返回值	：
其他	：

*********************************************************************************************/
int winpcap::Open_Rec_Adapter(int adapter_num, char* ruler)
{
	int i;
	pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program  fcode;
	
	if(alldevs == NULL)
		return -1;

	for(d = alldevs, i = 0; i < adapter_num-1 ;d = d->next, i++);
	printf("%s\n",d->name);

	/* Open the device */
	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		pcap_freealldevs(alldevs);
		return pcap_open_adaper_failed;
	}

	/*Set Filter Ruler*/
	if(d->addresses != NULL && d->addresses->netmask != NULL)
	{
		NetMask = ((sockaddr_in*)(d->addresses->netmask))->sin_addr.s_addr;
	}
	else
		NetMask = 0xffffff;

	//ruler = "tcp and net 192.168.252.0/24";
	if(pcap_compile(adhandle, &fcode, ruler, 1, NetMask) < 0)//or udp port 53
	{
		pcap_close(adhandle);
		
		NetMask = 0;
		adhandle = NULL;

		return pcap_compile_whitelist_failed;
	}

	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		pcap_close(adhandle);

		NetMask = 0;
		adhandle = NULL;
		return pcap_compile_whitelist_failed;
	}

	pcap_freealldevs(alldevs);
	return 0;
}


/********************************************************************************************* 
名称	：Open_Send_Adapter 
功能	：打开网卡适配器
被调用	：
调用	：无
输入	：网卡编号
输出	：网卡适配器句柄adhandle
返回值	：
其他	：

*********************************************************************************************/
int winpcap::Open_Send_Adapter(int adapter_num)
{
	int i;
	pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE];
	//struct bpf_program  fcode;
	
	if(alldevs == NULL)
		return -1;

	for(d = alldevs, i = 0; i < adapter_num-1 ;d = d->next, i++);
	
	/* Open the device */
	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		pcap_freealldevs(alldevs);
		return pcap_open_adaper_failed;
	}
	pcap_freealldevs(alldevs);
	return 0;
}

