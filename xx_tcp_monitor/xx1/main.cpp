/******************************************************************************
版权说明：
版本号：0.1
生成日期：2017-4-6
作者：
内容：主函数，抓包，存储，分析
功能：各种功能
********************************************************************************/
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <vector>
#include <map>
#include <string>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "net_struct.h"
#include "heart_beat.h"
#include "winpcap.h"

winpcap my_pcap;        //抓包类
char cap[] = "/mnt/myusbmount/Trojan_Monitor/tcp_trojan/cmdrat.pcap";
unsigned int subnet_intranet = ntohl(inet_addr("10.0.0.0"));      //存储子网ip，用于区分内部IP地址和外部IP地址
unsigned int subnet_extranet = ntohl(inet_addr("103.0.0.0"));     //存储子网ip，用于区分内部IP地址和外部IP地址
unsigned int subnet_mask =ntohl(inet_addr("255.0.0.0"));  //设定子网掩码，用于区获取子网号
FILE* fp = NULL;
char ip1[30];              //存源IP字符串
char ip2[30];              //存目的IP字符串
flow ** flow_pointer_array ;  //流结构体指针数组，存储1000万个流结构体指针，每个流结构体指针用其对应ip对的哈希值索引
flow *flow_ptr;            //用flow_ptr替换所有flow_ptr
cluster cluster_list[20];  //每条流分片后，最多取只取前20个簇的信息，作为判断是否木马的依据
int packets_number_no_ack = 0;		 //去除控制包后，流中包个数
int packet_id_list_no_ack[250];		 //流中非控制包的索引号数组，对应去除控制包后流中数据包
int slice_n;  //一条流分片后所得包簇个数
int item1; //流中的心跳种类数
//增加
static u_char xo[8];
static u_char perm[8];
struct po *port[65536];
struct pcap_file_header *file_header = (struct pcap_file_header *)malloc(sizeof(struct pcap_file_header));
/***************** 哈希函数 ******************/

void getrnd ()
{
    struct timeval s;
    u_int *ptr;
    //从如下的文件中读取随机数流
    int fd = open ("/dev/urandom", O_RDONLY);
    if (fd > 0)
    {
        read (fd, xo, 8);
        read (fd, perm, 8);
        close (fd);
        return;
    }

    //如果从"/dev/urandom"中读取到了随机数函数就返回了，那么以下不会执行
    gettimeofday (&s, 0);
    srand (s.tv_usec);
    ptr = (u_int *) xo;
    *ptr = rand ();
    *(ptr + 1) = rand ();
    ptr = (u_int *) perm;
    *ptr = rand ();
    *(ptr + 1) = rand ();
}


//将perm数组的各个元素分别转化为0-11之间的整数，之后会在mkhash函数中使用到
//xor数组的各个元素都是char型，元素值是0和255之间的随机数
static void init_hash (void)
{
    int i, n, j;
    int p[8];
    getrnd ();
    for (i = 0; i < 8; i++)
        p[i] = i;
    for (i = 0; i < 8; i++)
    {
        n = perm[i] % (8 - i);
        perm[i] = p[n];
        for (j = 0; j < 7 - n; j++)
            p[n + j] = p[n + j + 1];
    }
}

//增加
static u_int mkhash (u_int src, u_int dest)
{
    u_int res = 0;
    int i;
    u_char data[8];
    //将代表源/目的地址及端口的整数依次存入一个12个元素的u_char类型的数组中
    u_int *stupid_strict_aliasing_warnings=(u_int*)data;
    *stupid_strict_aliasing_warnings = src;
    *(u_int *) (data + 4) = dest;
    //perm[]在init_hash函数中其元素分别随机存储了0-11之间的数
    //0-11之间的数分别保存在了该数组中，只是在数组中位置随机
    //所以，data[perm[i]]是随机取出data的某个元素再与xor[i]随机数
    //进行异或操作，res每次右移八位，所以res最终结果是res迭代的和
    //然后将结果与大的素数16715791(0xff100f)取余，作为hash后的值
    for (i = 0; i < 8; i++)
        res = ( (res << 8) + (data[perm[i]] ^ xo[i])) % 0xff100f;
    return res;
}

/*********************************************************************************************
名称	check_init,check_exit
功能	：
被调用	：outnet_control函数
调用	：
输入	：全局变量（簇结构体数组），
输出	：
返回值	：
其他	：
*********************************************************************************************/

int main()
{
	/*局部变量定义*/
	int ret = 0;

	init_hash();

	int f;
	f = open(cap,O_RDONLY, 0);
	read(f,file_header, 24);
	close(f);
	printf("snaplen:%d\n",file_header->snaplen);

	file_header->magic = 0xa1b2c3d4;
	file_header->version_major = 2;
	file_header->version_minor = 4;
	file_header->thiszone = 0;
	file_header->sigfigs = 0;
	file_header->snaplen = 32;
	file_header->linktype = 1;

	printf("程序配置参数成功\n");

	/*打开端口，开始抓包*/
	ret = my_pcap.Get_Adapter_List();
	if(ret != pcap_state_ok)
	{
		printf("get_adapter_list wrong\n");
		return 0;
	}

	ret = my_pcap.Open_Adapter(cap);
	if(ret != pcap_state_ok)
	{
		printf("open_adapter wrong\n");
		return 0;
	}
	printf("网络适配器打开，程序开始监控........\n\n");
	/*抓包，存储,处理数据包*/

	flow_pointer_array = (flow **)malloc(sizeof(flow *)*10000000);
	memset(flow_pointer_array, 0, (sizeof(flow *))*10000000);
	fp = fopen("/root/result.txt", "w");
	//fp1 = fopen("/root/test.txt", "w");

	ret = packet_capture();
	printf("capture end\n");
	fclose(fp);

	if(flow_pointer_array!=NULL)
	{
		free(flow_pointer_array);  //流结构体指针数组，存储1000万个流结构体指针，每个流结构体指针用其对应ip对的哈希值索引
		flow_pointer_array = NULL; //4.13改
	}

	if(ret != 0)
	{
		printf("packet_capture() failed, return is: %d\n", ret);
		return 0;
	}
	return 0;
}


/*********************************************************************************************
名称	：time_slice
功能	：对非控制包分片为簇
被调用	：outnet_control函数
调用	：
输入	：全局变量（簇结构体数组）， 非控制包方向、带符号包大小、包到达时间、最大包到达时间间隔
输出	：分片所得簇结构体数组，簇个数返回值
返回值	：
其他	：
*********************************************************************************************/
static int time_slice(char* sign_list, int* size_list, double* timeline, double arrival_time_max)
{
	double timeslice = 0.0;
	int last_i;//,stlen,edlen;
	int n = 0;

	if (packets_number_no_ack <= 1)
		return 0;

	//stlen = packets_number_no_ack/3;
	//edlen = packets_number_no_ack*2/3;

	timeslice = arrival_time_max/2.0; //1/2包到达间隔时间的最大值

	last_i = 0; //下一个簇首包位置

	//对流中所有非控制包分簇
	for(int i=1;i<packets_number_no_ack;i++)
	{
		//if ((timeline[i]-timeline[i-1]>0.8) && (timeline[i]-timeline[i-1]> 5 || timeline[i] - timeline[last_i] > timeslice || timeline[i] - timeline[i-1] > (timeline[edlen]-timeline[stlen])/(edlen-stlen)*5 || (timeline[i] - timeline[i-1])*(i-1-last_i) > 5*(timeline[i-1]-timeline[last_i]))) //0.5 react_time
		//if ((timeline[i]-timeline[i-1]>0.8) && (timeline[i]-timeline[i-1]> 3 || timeline[i] - timeline[last_i] > timeslice || (timeline[i] - timeline[i-1])*(i-1-last_i) > 10*(timeline[i]-timeline[last_i]))) //0.5 react_time
		//if ((timeline[i]-timeline[i-1]>0.8) && (timeline[i]-timeline[i-1]> 3 || timeline[i] - timeline[last_i] > timeslice || ((i-last_i)>1 && (timeline[i] - timeline[i-1])*(i-1-last_i) > 10*(timeline[i]-timeline[last_i])))) //0.5 react_time
		if ((timeline[i]-timeline[i-1]>0.8) && (timeline[i]-timeline[i-1]> 5 || timeline[i] - timeline[last_i] > timeslice || ((i-last_i)>1 && (timeline[i] - timeline[i-1])*(i-1-last_i) > 10*(timeline[i]-timeline[last_i])))) //0.5 react_time
		{
			//申请簇结构体空间
			cluster_list[ n ].packet_arrival_time_list = (double *)malloc(sizeof(double)*(i-last_i));
			cluster_list[ n ].packet_sign_list = (char *)malloc(sizeof(char)*(i-last_i));
			cluster_list[ n ].packet_size_list = (int *)malloc(sizeof(int)*(i-last_i));
			cluster_list[ n ].packet_number = i-last_i;//簇中包个数
			//提取并存储簇中包信息到申请簇结构体空间
			for(int j=last_i;j<i;j++)
			{
				cluster_list[ n ].packet_arrival_time_list[ j-last_i ] = timeline[ j ];
				cluster_list[ n ].packet_sign_list[ j-last_i ] = sign_list[ j ];
				cluster_list[ n ].packet_size_list[ j-last_i ] = size_list[ j ];
			}
			last_i = i;
			n++;
			if (n == 20)
				break;
		}
	}

	if(n < 20)
	{
		//簇个数未达到20，则为最后一个簇申请簇结构体空间
		cluster_list[ n ].packet_arrival_time_list = (double *)malloc(sizeof(double)*(packets_number_no_ack-last_i));
		cluster_list[ n ].packet_sign_list = (char *)malloc(sizeof(char)*(packets_number_no_ack-last_i));
		cluster_list[ n ].packet_size_list = (int *)malloc(sizeof(int)*(packets_number_no_ack-last_i));
		cluster_list[ n ].packet_number = packets_number_no_ack -last_i;

		//提取并存储簇中包信息到申请簇结构体空间
		for(int j=last_i;j<packets_number_no_ack;j++)
		{
			cluster_list[ n ].packet_arrival_time_list[ j-last_i ] = timeline[ j ];
			cluster_list[ n ].packet_sign_list[ j-last_i ] = sign_list[ j ];
			cluster_list[ n ].packet_size_list[ j-last_i ] = size_list[ j ];
		}
		n++;
	}

	return n;
}

/*********************************************************************************************
名称	：cut_heartbeat
功能	：对包簇去心跳
被调用	：outnet_control函数
调用	：
输入	：全局变量（簇结构体数组）， 簇个数，心跳包大小
输出	：去心跳后的簇结构体数组
返回值	：
其他	：
*********************************************************************************************/
static void cut_heartbeat(int slice_num, set* seti)
{
	int index[3];
	int n;
	int x=0;

	for(int i=0;i<seti->num;i++)
	{
		for(int k=0;k<slice_num;k++)
		{
			n=0;
			for(int j=0;j<seti->size;j++)
				for(int l=0;l<cluster_list[k].packet_number;l++)
					if (seti->item[i].size[j] == cluster_list[k].packet_size_list[l])
					{
						index[n] = l;
						n++;
						break;
					}


			if (n == seti->size)
			{
				int m;
				for(m=1;m<n;m++)
					if(index[m-1]>index[m])
						break;
				if(m == n)
					for(int j=0;j<n;j++)
					{
						for(int l=index[j]-x;l<cluster_list[k].packet_number-1;l++)
						{
							cluster_list[k].packet_sign_list[l]=cluster_list[k].packet_sign_list[l+1];
							cluster_list[k].packet_size_list[l]=cluster_list[k].packet_size_list[l+1];
							cluster_list[k].packet_arrival_time_list[l]=cluster_list[k].packet_arrival_time_list[l+1];
						}
						cluster_list[k].packet_number--;
						x--;
					}
			}
		}

	}
	return;
}

//计算数组第m到第n个元素中0的个数
static int zero_num(char *a, int m, int n)
{
	int k;
	k=0;
	for(int i=m;i<=n;i++)
	{
		if(a[i]==0)
			k++;
	}
	return k;
}


/*********************************************************************************************
名称	：outnet_control
功能	：提取流中非控制包信息，对非控制包分片为簇、去心跳、去小包簇，
		  统计外部控制簇个数、簇总数
被调用	：Make_TCP_Judgement函数
调用	：time_slice、apriori、cut_heartbeat、zero_num
输入	：全局变量， 非控制包索引号数组指针，非控制包数，簇总数变量地址，外部控制簇变量地址
输出	：是否能判断外部控制簇的返回值
返回值	：
其他	：
*********************************************************************************************/
static int outnet_control(int* packet_id_ptr, int packets_num, int* i_num, int* o_num,int nn)
{
	char packet_sign_list[packets_num];
	int packet_signed_size_list[packets_num];
	double packet_arrival_time_list[packets_num];
	double delta_arrival_time;
	double arrival_time_max=0.0;
	int slice_num=0;

	if (packets_num < 2)
		return 0;

	//根据非控制包索引号数组，提取流中非控制包的信息，包括包方向、带符号包大小、包到达时间、最大包到达时间间隔
	for(int i=0;i<packets_num;i++)
	{
		packet_sign_list[i] = flow_ptr->array_ptr->packet_sign_list[packet_id_ptr[i]];                 //包方向数组

		if  (packet_sign_list[i] == 1)
		{
			packet_signed_size_list[i] = flow_ptr->array_ptr->packet_size_list[packet_id_ptr[i]];
		}
		else if (packet_sign_list[i] == 0)
		{
			packet_signed_size_list[i] = -(flow_ptr->array_ptr->packet_size_list[packet_id_ptr[i]]);   //带符号包大小数组
		}

		packet_arrival_time_list[i] = flow_ptr->array_ptr->packet_arrival_time_list[packet_id_ptr[i]]; //包到达时间数组
		/*delta_arrival_time[i] = flow_ptr->packet_arrival_time_list[packet_id_ptr[i+1]] - flow_ptr->packet_arrival_time_list[packet_id_ptr[i]];
		if((delta_arrival_time[i] > arrival_time_max) && (i<packets_num-1))//fixed : lose a )
			arrival_time_max = delta_arrival_time[i]; //最大包到达时间间隔*/
		if(i<packets_num-1)
		{
			delta_arrival_time = flow_ptr->array_ptr->packet_arrival_time_list[packet_id_ptr[i+1]] - flow_ptr->array_ptr->packet_arrival_time_list[packet_id_ptr[i]];
			if(delta_arrival_time > arrival_time_max)//fixed : lose a )
				arrival_time_max = delta_arrival_time; //最大包到达时间间隔
		}
	}

	//对流中非控制包进行分片，保存分片数
	slice_num = time_slice(packet_sign_list,packet_signed_size_list,packet_arrival_time_list,arrival_time_max);
	slice_n = slice_num;
	printf("%d\n",slice_n);

	if (slice_num < 3) //分片数太少，无法判断是否外部控制
		return 0;

	float delta_time_first = 0.0;
	delta_time_first = cluster_list[1].packet_arrival_time_list[0] - cluster_list[0].packet_arrival_time_list[0]; //前两个簇出现时间间隔
	if (delta_time_first < 0.95) //前两个簇出现时间间隔太小，无法判断是否外部控制
		return 0;

	//通过频繁项挖掘发现心跳，返回心跳类型数，带方向心跳包大小存于it中
	set it;
	item1 = 0;
	if (slice_num > 3)
	{

		item1 = apriori(cluster_list, slice_num, 0.6, &it);

	}
	//去除簇中心跳包
	if (item1 != 0)
		cut_heartbeat(slice_num,&it);

	int max=0;
	int slice_num1=0;
	int slice_num2=0;
	//去除簇中最大包大小小于19的簇
	for(int i=0;i<slice_num;i++)
	{
		if(cluster_list[i].packet_number > 0)
		{
			slice_num1++;
			slice_num2++;
			max = 0;
			for(int j=0;j<cluster_list[i].packet_number;j++)
				if(cluster_list[i].packet_size_list[j]>max)
					max = cluster_list[i].packet_size_list[j];
			if(max <=19)
			{
				cluster_list[i].packet_number = 0;
				slice_num1--;
			}
		}
	}

	if(slice_num1 < 1)
		return 0;

	int p_num;
	char *sign;
	*i_num = 0;
	*o_num = 0;
	//通过簇中包方向序列，统计外部控制簇数目，簇总数
	for(int i=0;i<slice_num;i++)
	{

		p_num = cluster_list[i].packet_number;      //簇中包个数
		sign = cluster_list[i].packet_sign_list;    //簇中包方向数组
		int sum,zero_num_1toend;

		zero_num_1toend = zero_num(sign,1,p_num-1); //簇中第0个包之后，大小为0的包个数
		/*
		是外部控制簇的条件：
		1.包个数大于1时，第一个包方向为0，其后包方向不全为0
		2.包个数大于2小于等于6时（3、4、5），包方向全为1
		3.包个数大于6时，前6个包方向全为1或者后6个包方向全为1
		*/
		printf("%d\n",p_num);
		if (p_num > 1 && ((sign[0] == 0 && (zero_num_1toend != p_num-1)) || (p_num > 2 &&  ((p_num<=6 && zero_num(sign,0,p_num-1) == 0) || (p_num>6 && (zero_num(sign,0,5) == 0 || zero_num(sign,p_num-6,p_num-1) == 0)))  )))
		{
			sum=0;
			for(int j=0;j<p_num;j++)
				sum += cluster_list[i].packet_size_list[j];

			if (sum > 0)
				(*o_num)++;
			(*i_num)++;
		}
		/*
		不是外部控制簇的条件：
		1.包个数大于1时，第一个包方向为1，其后包方向不全为1
		2.包个数大于2小于等于6时，包方向全为0
		3.包个数大于6时，前6个包方向全为1或者后6个包方向全为0
		*/
		else if (p_num > 1 && ((sign[0] == 1 && (zero_num_1toend != 0)) || (p_num > 2 && ((p_num<=6 && zero_num(sign,0,p_num-1) == p_num) || (p_num>6 && (zero_num(sign,0,5) == 6 || zero_num(sign,p_num-6,p_num-1) == 6))) )))
		{
			(*i_num)++;
		}
		//(*i_num)+=(slice_num-slice_num1);
	}
	return 1;
}

/*********************************************************************************************
名称	：Make_TCP_Judgement
功能	：分片前，统计流中相关信息，判断流类型
		  调用outnet_contro函数，分片后通过判断外部控制簇占比，判断是否为木马通信流
被调用	：packet_capture 函数
调用	：outnet_control
输入	：全局变量， 无需输入
输出	：流类型的返回值
返回值	：
其他	：
*********************************************************************************************/
static int Make_TCP_Judgement(int n)
{

	int outnet_ctl = 0;

	unsigned int up_num = 0;
	unsigned int up_syn_num = 0;
	unsigned int down_num = 0;
	unsigned int down_syn_num = 0;
	float up_syn_ratio = 0.0;
	float down_syn_ratio = 0.0;
	unsigned int up_num_no_ack = 0;
	int synackfromin = 0;

	packets_number_no_ack = 0;
	for(int i=0;i<250;i++){

	}
	//获取流中上传包总数、上传syn包数，下载包总数、下载syn包数，
	for(int i=0;i<250;i++)
	{
		if  (flow_ptr->array_ptr->packet_sign_list[i] == 1)
		{
			up_num++;            //流中上传包总数
			if  ((flow_ptr->array_ptr->packet_flag_list[i] & 0x07) != 0)
				up_syn_num++;    //流中上传syn包数
		}
		else if(flow_ptr->array_ptr->packet_sign_list[i] == 0)
		{
			down_num++;          //流中下载包总数
			if  ((flow_ptr->array_ptr->packet_flag_list[i] & 0x07) != 0)
				down_syn_num++;  //流中下载syn包数
		}

		if(flow_ptr->array_ptr->packet_size_list[i] > 1)
		{

			packet_id_list_no_ack[packets_number_no_ack] = i; //非控制包索引号
			packets_number_no_ack ++;                         //非控制包个数

			if (flow_ptr->array_ptr->packet_sign_list[i] == 1)
				up_num_no_ack++;                              //上行非控制包个数
		}

		if((flow_ptr->array_ptr->packet_flag_list[i] & 0x12) == 0x12 && flow_ptr->array_ptr->packet_sign_list[i] == 1)
			synackfromin = 1;     //有由外向内的syn包，认为流属于内网web服务器

	}

	//计算上行syn包占比、下载syn包占比
	if (up_num > 2)
		up_syn_ratio = (float)(up_syn_num)/(float)(up_num);
	else
		up_syn_ratio = 0.0;
	if (down_num > 2)
		down_syn_ratio = (float)(down_syn_num)/(float)(down_num);
	else
		down_syn_ratio= 0.0;

	if (up_syn_ratio >0.8 || down_syn_ratio > 0.8) //上行syn包占比或下载syn包占比过高，则认为是洪攻击流
		return 101; //"SYN flooding detected! Continues SYN request!";

	if (synackfromin == 1) //有由外向内的syn包，正常流
		return 203; //"Normal! syn from outside!" server in internal network


	if (packets_number_no_ack < 3) //除去控制包后，包个数小于3，无法判断流类型
		return 900; //"Unknow! Few packets!";


	if (up_num_no_ack < 2 || (float)(up_num_no_ack)/(float)(packets_number_no_ack) < 0.1) //上行非控制包个数太少，或者占比太小，正常流, 可调参数
		return 200; //"Normal! Pure download!";

	int t_num=0; //分片后，流中簇总数
	int o_num=0; //外部控制簇数
	outnet_ctl = outnet_control(packet_id_list_no_ack, packets_number_no_ack, &t_num, &o_num,n);

	//外部控制判断结束，释放簇结构体
	for(int i=0;i<slice_n;i++)
	{
	  free(cluster_list[ i ].packet_arrival_time_list);
	  free(cluster_list[ i ].packet_sign_list);
	  free(cluster_list[ i ].packet_size_list);
	  cluster_list[ i ].packet_arrival_time_list = NULL;
	  cluster_list[ i ].packet_sign_list = NULL;
	  cluster_list[ i ].packet_size_list = NULL;
	  cluster_list[ i ].packet_number = 0;
	}

	if(outnet_ctl) //可能有外部控制特征
	{
		printf("%d,%d\n",o_num,t_num);
		if (!o_num) //没有外部控制簇，正常流
			return 902; //"Normal! Automatic stream!"
		else if (t_num > 0 && (float)(o_num)/(float)(t_num) > 0.80) //外部控制簇数占比过高，是木马
			return 102; //"Trojan detected! Outside control!"
	}
	return 903; //"Unknown! Not regular!"
}




/*********************************************************************************************
名称	：ip_inttochar
功能	：将IP地址由unsigned int 类型 转换 为 char 型
被调用	：
调用	：无
输入	：unsigned int ip ,  char* ipchar
输出	：转换后的Ip地址， 位于ipchar参数中
返回值	：无
其他	：
*********************************************************************************************/
static void ip_inttochar(unsigned int ip,char ipchar[30])
{
	int i;
	int ipdate=ip;
//	ipdate=ntohl(ip);    //可能转换的字符串形式的IP地址是反的
	for(i=0;i<30;i++)
		ipchar[i]=0;
	sprintf(ipchar,"%u.%u.%u.%u",(unsigned char)(ipdate>>24),(unsigned char)(ipdate>>16),(unsigned char)(ipdate>>8),(unsigned char)(ipdate));
}

/*********************************************************************************************
名称	：ip_chartoint
功能	：将IP地址由char 型 转换 为 unsigned int 类型
被调用	：
调用	：无
输入	：char* ip
输出	：unsigned int 型 Ip地址
返回值	：Ip地址
其他	：

*********************************************************************************************/

static unsigned int ip_chartoint(char ip[] )
{
    return ntohl(inet_addr(ip));
}

/*
static double getusec(void)
{
	struct timeval stp;
	//uint64_t cur = 0;
	gettimeofday(&stp, NULL);
	return  (((double)stp.tv_sec) + ((double)stp.tv_usec)/1000000.0);
	//return  (((uint64_t)stp.tv_sec)*1000000 + (uint64_t)stp.tv_usec);
}*/

int packet_capture()
{
	int ret;
	uint8_t is_send = 0;          //包方向
	uint32_t srcip = 0;           //源ip
	uint32_t dstip = 0;           //目的ip
	unsigned short srcport;
	unsigned short dstport;
	struct po *p;
	struct po *p1;
	unsigned short por[250];
	int p_num;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	ETH_HDR *pETHHdr;
	IPV4_HDR  *pIPHdr;
	TCP_HDR   *pTCPHdr;
	int  IPhdrlen;
	int num=1;  //当前IP对编号、个数
	int judge_num=0;
	int trojan_num=0;
	int unknown_num=0;
	int normal_num=0;
	int flooding_num=0;
	int rec_num=0;

	char filename[100];
	int ff;
	struct pcap_phdr {
		struct timeval ts;	/* time stamp */
		unsigned int caplen;	/* length of portion present */
		unsigned int len;	/* length this packet (off wire) */
	};
	struct pcap_phdr hdr;
	int pn=0;
	int cnt=1;
	while ((ret = pcap_next_ex(my_pcap.adhandle, &header, &pkt_data)) >= 0)
	{
		//printf("ok");
		if(ret == 0)
			continue;

		if(ret == -1)
		{
			printf("[ERROR]		Unable to read the packet: %s\n",pcap_geterr(my_pcap.adhandle));
			return packet_capture_failed;
		}

		if(header->caplen < (uint32_t)14)
			continue;
		pETHHdr = (ETH_HDR*)pkt_data ;
		//if(pETHHdr->eth_type != (uint16_t)0x8)       //非以太网包
		if(pETHHdr->eth_type != (uint16_t)0x8 && pETHHdr->eth_type != (uint16_t)0x81)       //非以太网包
			continue;
		pIPHdr = (IPV4_HDR*)(pkt_data + 14);			//链路层包头为14字节
		if(pETHHdr->eth_type == (uint16_t)0x81)
			pIPHdr = (IPV4_HDR*)(pkt_data + 18);			//链路层包头为14字节
		if ( (pIPHdr->ip_ver_hlen & 0xf0 )!= 0x40)		//不是IPv4的数据包
		{
			continue;
		}

		IPhdrlen = ((pIPHdr->ip_ver_hlen )& 0xf)*4;		//计算IP包头长度
		if(IPhdrlen != 20)
			continue;
		if( (pIPHdr->ip_protocol) != TCP_ID)
			continue;
		pTCPHdr = (TCP_HDR*)((unsigned char*)pIPHdr + IPhdrlen);
		dstip = ntohl(pIPHdr->ip_destaddr);
		srcip = ntohl(pIPHdr->ip_srcaddr);
		srcport = ntohs(pTCPHdr->source_port);
		dstport = ntohs(pTCPHdr->dest_port);
	//	printf("$$$$\n");
	//	printf("srcip:%u dstip:%u subnet_mask:%u subnet_intranet:%u subnet_extranet:%u\n", srcip, dstip, subnet_mask, subnet_intranet, subnet_extranet);
		if((srcip & subnet_mask ) == subnet_extranet && (dstip & subnet_mask ) == subnet_extranet)  //子网异常包，不处理
			continue;
		if((((srcip & subnet_mask) == subnet_intranet) && ((dstip & subnet_mask) == subnet_intranet)))// || (((srcip & subnet_mask) == subnet2) && ((dstip & subnet_mask) == subnet2)))      //源IP在内网，目的IP也在内网，即内网数据，不处理
			continue;

		if((srcip & subnet_mask) == subnet_intranet){
	//		printf("is_send %d\n", cnt++);
			is_send = 1;                             //上传包
		}
		else if((dstip & subnet_mask) == subnet_intranet){
	//		printf("is_get %d\n", cnt++);
			is_send = 0;                            //下载包
			dstip = ntohl(pIPHdr->ip_srcaddr);        //交换源、目的ip，后续不在通过is_send判断包方向，认为上传、下载包ip对相同，便于索引流
			srcip = ntohl(pIPHdr->ip_destaddr);
			srcport = ntohs(pTCPHdr->dest_port);
			dstport = ntohs(pTCPHdr->source_port);
		}
		if((dstport < 1024 && dstport != 80) || (srcport < 1024 && srcport != 80)) continue;

		//得到源ip和目的ip字符串
		memset(ip1,0,sizeof(ip1));
		memset(ip2,0,sizeof(ip2));
		ip_inttochar(srcip, ip1);
		ip_inttochar(dstip, ip2);

		flow *prev_flow_ptr;

		int cur = mkhash(srcip,dstip)%10000000;
		//printf("cur:%d\n",cur);
		prev_flow_ptr = NULL;

		char fl = (char)(ntohs(pTCPHdr->hrf) & 0x00ff);
		if(!flow_pointer_array[cur])// && ((fl & 0x02) && !(fl & 0x10) && !(fl & 0x04)))
	 //若不存在，且标志位满足SYN=1 ACK=0 RST=0（连接请求，第一次握手）
		{
			flow_pointer_array[cur] = (flow *)malloc(sizeof(flow));
			memset(flow_pointer_array[cur],0,sizeof(flow));
			flow_pointer_array[cur]->srcip = srcip;
			flow_pointer_array[cur]->dstip = dstip;
			flow_pointer_array[cur]->array_ptr = (flow_array *)malloc(sizeof(flow_array));
		//	flow_pointer_array[cur]->data.push_back(std::string(pkt_data));
			memset(flow_pointer_array[cur]->array_ptr,0,sizeof(flow_array));
			num++;
		}
		flow_ptr = flow_pointer_array[cur];
		while(flow_ptr)
		{
			if (flow_ptr->srcip == srcip && flow_ptr->dstip == dstip)
				break;
			prev_flow_ptr = flow_ptr;
			flow_ptr = flow_ptr->next;
		}
		if(!flow_ptr)// && ((fl & 0x02) && !(fl & 0x10) && !(fl & 0x04)))
		{
			flow_ptr = (flow *)malloc(sizeof(flow));
			memset(flow_ptr,0,sizeof(flow));
			if (prev_flow_ptr)
				prev_flow_ptr->next = flow_ptr;
			flow_ptr->srcip = srcip;
			flow_ptr->dstip = dstip;
			flow_ptr->array_ptr = (flow_array *)malloc(sizeof(flow_array));
			memset(flow_ptr->array_ptr,0,sizeof(flow_array));
			num++;
		}
		//在流中增加一个包的信息
		if(!flow_ptr)
			continue;

		if(flow_ptr->alarm == 1)
		{
			gettimeofday(&(hdr.ts), NULL);
			hdr.caplen = header->caplen;
			hdr.len = header->len;

			sprintf(filename,"/root/alarm/%s_%s.pcap", ip1, ip2);
			ff=open(filename, O_WRONLY|O_APPEND, 0644);//O_APPEND

			write(ff, (char *)&hdr, 4);
			write(ff, ((char *)&hdr)+8, 4);
			write(ff, ((char *)&hdr)+16, sizeof(hdr)-16);
			write(ff, pkt_data, hdr.caplen);
			close(ff);
		}

		if(flow_ptr->packet_number == 250)
			continue;
		flow_ptr->array_ptr->packet_arrival_time_list[flow_ptr->packet_number] = (double(header->ts.tv_sec) + double(header->ts.tv_usec)/1000000.0);//(double)getusec();//包到达时间
		flow_ptr->array_ptr->packet_sign_list[flow_ptr->packet_number] = is_send;//方向
		flow_ptr->array_ptr->packet_size_list[flow_ptr->packet_number] = (ntohs(pIPHdr->ip_total_length) - IPhdrlen - ((ntohs(pTCPHdr->hrf) & 0xf000) >> 10)); //包大小
		flow_ptr->array_ptr->packet_flag_list[flow_ptr->packet_number] = (char)(ntohs(pTCPHdr->hrf) & 0x00ff);//包的TCP头中标志位
		flow_ptr->array_ptr->sequence[flow_ptr->packet_number] = ntohl(pTCPHdr->sequence);
		flow_ptr->array_ptr->srcport[flow_ptr->packet_number] = srcport;
		flow_ptr->array_ptr->data.push_back(std::string(pkt_data));
		flow_ptr->array_ptr->len += header->caplen;
		flow_ptr->packet_number++;//流中包信息
		if(pn<25)
			printf("%d: %f, %d, %d, %d, %d\n",pn,flow_ptr->array_ptr->packet_arrival_time_list[flow_ptr->packet_number-1],flow_ptr->array_ptr->packet_size_list[flow_ptr->packet_number-1],flow_ptr->array_ptr->packet_flag_list[flow_ptr->packet_number-1],fl,flow_ptr->array_ptr->packet_sign_list[flow_ptr->packet_number-1]);

		if(pn==25)
		{
			printf("\n");
			//return 0;
		}
		pn++;


		//流中包个数达到250时，开始检测
		if (flow_ptr->packet_number == 250)
		{
		  printf("begin to judge\n");
		  //fprintf(fp,"flow: %d\n\n",flow_ptr->array_ptr->srcport[249]);
		  judge_num++; //判断次数加1
		  //write down the packet!
		  char name[70];
		  memset(name,0,sizeof(name));
		  sprintf(name, "%d_judge.pcap", judge_num);
		  FILE* pFile;
		  pcap_file_header ph;
		  ph.magic = 0xa1b2c3d4;
		  ph.version_major = 0x02;
		  ph.version_minor = 0x04;
		  ph.thiszone = 0;
		  ph.sigfigs = 0;
		  ph.snaplen = 65535;
		  ph.linktype = 0x1;
		  pFile = fopen(name, "w+");
		  fwrite(&ph, 1, 24, pFile);
		  fwrite(&hdr.ts.tv_sec, 1, 4, pFile);
		  fwrite(&hdr.ts.tv_usec, 1, 4, pFile);
		  fwrite(&hdr.caplen, 1, 8, pFile);
		  fwrite(&flow_ptr->array_ptr->data, 1, flow_ptr->array_ptr->len, pFile);
		  fclose(pFile);

		  p_num=0;
		  float syn_num=0.0;
		  float rst_num=0.0;
		  memset(port, 0, (sizeof(po *))*65536);
		  for(int i=0;i<250;i++)
		  {
			  if ((flow_ptr->array_ptr->packet_flag_list[i] & 0x12) == 0x12)
				  syn_num++;
			  else if((flow_ptr->array_ptr->packet_flag_list[i] & 0x14) == 0x14)
				  rst_num++;
			  p = port[flow_ptr->array_ptr->srcport[i]];
			  if(p)
				  p->time[p->num] = flow_ptr->array_ptr->packet_arrival_time_list[i];
			  else
			  {
				  por[p_num] = flow_ptr->array_ptr->srcport[i];
				  p_num++;
			  	  p = port[flow_ptr->array_ptr->srcport[i]] = (po *)malloc(sizeof(po));
			  	  p->num=0;
			  	  p->time[p->num] = flow_ptr->array_ptr->packet_arrival_time_list[i];
			  }
			  p->num++;
		  }
		  int cl0=0;
		  if(p_num > 1)
		  {
			  int i;
			  for(i=0;i<p_num -1;i++)
			  {
				  p = port[por[i]];
				  p1 = port[por[i+1]];
				  if(p->num > 1 && p1->num > 1)
					  if(!(p->time[0] < p->time[p->num-1] && p->time[p->num-1]< p1->time[0] && p1->time[0] < p1->time[p1->num-1]))
					  {
						  break;
					  }
			  }
			  if(i == p_num -1)
				  cl0=1;
		  }
		  int cl1=0;
		  int pm=0;
		  if(p_num>4 && syn_num and rst_num/syn_num>0.7)
		  {
			  for(int i=0;i<p_num -1;i++)
			  {
				  p = port[por[i]];
				  if(p->num>pm)
					  pm=p->num;
			  }
			  if(pm<60)
				  cl1=1;
		  }
		  if(cl0==0 && cl1==0)// && cl0==0)
		  {
			  ret = Make_TCP_Judgement(judge_num);//判断流类型

			  //printf("cur: %d\n",cur);
			  if (ret == 102){
				  trojan_num = trojan_num + 1; //是木马, 木马数加1
				  sprintf(filename,"/root/alarm/%s_%s.pcap", ip1, ip2);
				  ff = open(filename, O_WRONLY|O_CREAT, 0644);
				  write(ff, ((char *)file_header), sizeof(*file_header));
				  close(ff);
				  flow_ptr->alarm = 1;
				  if(item1 == 0)
					  fprintf(fp,"Trojan%d : %s:%d -> %s:%d\n\n",trojan_num,ip1,srcport,ip2,dstport);
				  else
					  fprintf(fp,"Trojan%d : %s:%d -> %s:%d  存在心跳\n\n",trojan_num,ip1,srcport,ip2,dstport);
				  if(item1 == 0)
					  printf("Trojan%d : %s:%d -> %s:%d\n\n",trojan_num,ip1,srcport,ip2,dstport);
				  else
					  printf("Trojan%d : %s:%d -> %s:%d  存在心跳\n\n",trojan_num,ip1,srcport,ip2,dstport);
				  //printf("Judge: %d, Trojan: %d Flooding: %d Unknown: %d Normal: %d Total: %d\n\n*****************************\n", judge_num, trojan_num, flooding_num, unknown_num, normal_num, num-1);
			  }
			  else if (ret == 101)
				  flooding_num++;//是洪攻击, 洪攻击数加1
			  else if (ret == 900 || ret == 903)
				  unknown_num = unknown_num + 1;//是未知类型, 未知类型数加1
			  else if (ret == 200 || ret == 203 || ret == 902)
				  normal_num = normal_num + 1;//正常流，正常数加1
		  }
		  else
		  {
			  rec_num++;
		  }
		  printf("Judge: %d, Trojan: %d Flooding: %d Reconnect: %d Unknown: %d Normal: %d Total: %d\n\n*****************************\n", judge_num, trojan_num, flooding_num, rec_num, unknown_num, normal_num, num-1);

		  free(flow_ptr->array_ptr);
		  flow_ptr->array_ptr = NULL;

		  flow_ptr = NULL;
		}

	}
	return 0;
}
