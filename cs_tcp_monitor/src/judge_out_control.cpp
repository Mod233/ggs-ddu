#include "stream_to_vector.h"
#include "apriori_cut_heartbeat.h"
#include <stdio.h>
#include <string.h>
#include "init.h"
#include "debug.h"
#define CLU_NUM 70
#define SLICE_NUM 50
int time_slice(tcp_vector stream_vector, double delta_time,
		cluster_vector* clu) {
	int pos = 0;
	int n = 0;
	for (int i = 0; i < CLU_NUM; i++)
		memset(&clu[i], 0, sizeof(cluster_vector));
	for (int i = 1; i < PKT_NUM; i++) {
		if ((stream_vector.pkt_time[i] - stream_vector.pkt_time[i - 1] > 0.8)
				&& (stream_vector.pkt_time[i] - stream_vector.pkt_time[i - 1]
						> 5
						|| stream_vector.pkt_time[i]
								- stream_vector.pkt_time[pos] > delta_time
						|| ((i - pos) > 1
								&& (stream_vector.pkt_time[i]
										- stream_vector.pkt_time[i - 1])
										* (i - 1 - pos)
										> 10
												* (stream_vector.pkt_time[i]
														- stream_vector.pkt_time[pos])))) {
			clu[n].pkt_num = i - pos;
			for (int j = pos; j < i; j++) {
				if (stream_vector.pkt_size[j] < 2)
					break;
				clu[n].pkt_time[j - pos] = stream_vector.pkt_time[j];
				clu[n].pkt_tag[j - pos] = stream_vector.pkt_tag[j];
				clu[n].pkt_size[j - pos] = stream_vector.pkt_size[j];
			}
			pos = i;
			n++;
			if (n == SLICE_NUM)
				break;
		}
	}
	if (n < SLICE_NUM) {
		clu[n].pkt_num = 0;
		for (int j = pos; j < PKT_NUM; j++) {
			if (stream_vector.pkt_size[j] < 2)
				break;
			clu[n].pkt_time[j - pos] = stream_vector.pkt_time[j];
			clu[n].pkt_tag[j - pos] = stream_vector.pkt_tag[j];
			clu[n].pkt_size[j - pos] = stream_vector.pkt_size[j];
			clu[n].pkt_num++;
		}
		n++;
	}
	return n;
}

int judge_out_control(tcp_vector stream_vector, cluster_vector* clu) {
	if (stream_vector.pkt_num < 290)
		return 0;
	int slice_num = 0;
	int heart_num;
	char packet_sign_list[PKT_NUM];
	int packet_signed_size_list[PKT_NUM];
	double packet_arrival_time_list[PKT_NUM];
	double delta_arrival_time;
	double arrival_time_max = 0.0;

	for (int i = 1; i < PKT_NUM; i++) {
		delta_arrival_time = stream_vector.pkt_time[i]
				- stream_vector.pkt_time[i - 1];
		arrival_time_max = std::max(arrival_time_max, delta_arrival_time);
	}
	slice_num = time_slice(stream_vector, arrival_time_max / 2.0, clu);
//	printf("after slice\n");
	double delta_time_first = 0.0;
	delta_time_first = clu[1].pkt_time[0] - clu[0].pkt_time[0];
#if(SHOW_SLICE_RESULT)
	printf("slice num is %d\n", slice_num);
	for (int i = 0; i < slice_num; i++) {
		printf("slice_num %d:\n", i);
		for (int j = 0; j < clu[i].pkt_num; j++) {
			if (clu[i].pkt_tag[j])
			printf("%u ", clu[i].pkt_size[j]);
			else
			printf("-%u ", clu[i].pkt_size[j]);
		}
		printf("\n");
	}
#endif
	if (slice_num < 3) {  // important!
#if(SHOW_SLICE_RESULT)
			printf("not enough slice_num\n");
#endif
		return 0;
	}
	int outctl_num = 0;
	int single_pkt_num = 0;
	// clu集是没有去心跳的，下面依据 heart 数组去心跳。

#if(CUT_HEARTBEAT)
	int heart[10];
	memset(heart, 0, sizeof(heart));
//	printf("go find_heartbeat\n");
	heart_num = find_heartbeat(slice_num, clu, CONFIGDENT, heart);
//	printf("after find_heartbeat\n");
	bool vis[10];
	for (int i = 0; i < slice_num; i++) {
		memset(vis, 0, sizeof(vis));
		for (int j = 0; j < clu[i].pkt_num; j++) {
			int tmp =
					clu[i].pkt_tag[j] ?
							clu[i].pkt_size[j] : -clu[i].pkt_size[j];
			for (int k = 0; k < heart_num; k++) {
				if (vis[k])
					continue;          //心跳只去一次
				if (heart[k] == tmp) {
					vis[k] = 1;
					clu[i].pkt_tag[j] = 0;
					clu[i].pkt_size[j] = 0;
					clu[i].pkt_num--;
					break;
				}
			}
		}
	}
#endif

#if(SHOW_SLICE_RESULT_AFTER_CUT)
	printf("heartbeat is \n");
	for (int i = 0; i < heart_num; i++)
		printf("%d ", heart[i]);
	printf("\n");
	printf("\n\n$$$$$$after heartbeat cut$$$$$$\n\n");
	printf("slice num is %d\n", slice_num);
	for (int i = 0; i < slice_num; i++) {
		printf("slice_num %d:\n", i);
		int pos = 0;
		for (int j = 0; j < clu[i].pkt_num; j++) {
			while (clu[i].pkt_size[pos] < 2)
				pos++;
			if (clu[i].pkt_tag[pos])
				printf("%u ", clu[i].pkt_size[pos]);
			else
				printf("-%u ", clu[i].pkt_size[pos]);
			pos++;
		}
		printf("\n");
	}
#endif
	for (int i = 0; i < slice_num; i++) {
		if (clu[i].pkt_num == 1) {
			single_pkt_num++;
			continue;
		}
#if(UP_DOWN)
		//add up_data:down_data
		int up_data = 0;
		int down_data = 0;
		for (int j = 0, cnt = 0; cnt < clu[i].pkt_num; j++) {
			if (clu[i].pkt_size[j])
				cnt++;
			if (clu[i].pkt_tag[j])
				up_data += clu[i].pkt_size[j];
			else
				down_data += clu[i].pkt_size[j];
		}
		if (up_data > down_data)
			continue;
#endif
		int pos = 0, pos2, pos3;
		while (clu[i].pkt_size[pos] < 1)
			pos++;
		if (clu[i].pkt_tag[pos])
			continue;
		if (clu[i].pkt_size[pos] > 200)
			continue;
		pos2 = pos + 1;
		while (clu[i].pkt_size[pos2] < 1)
			pos2++;
		if (clu[i].pkt_num > 3) {
			pos3 = pos2 + 1;
			while (clu[i].pkt_size[pos3] < 1)
				pos3++;
			if (clu[i].pkt_tag[pos2] || clu[i].pkt_tag[pos3]) {
				outctl_num++;
				//printf("slice num is %d pkt_num is %d\n", i,clu[i].pkt_num);
			}
		} else if (clu[i].pkt_num > 1) {
			if (clu[i].pkt_tag[pos2]) {
				outctl_num++;
				//printf("slice num is %d pkt_num is %d\n", i,clu[i].pkt_num);
			}
		}
	}
#if(SHOW_OUTCTL)
	printf("outctl_num is %d ~~~~ slice_num is %d\n", outctl_num,
			slice_num - single_pkt_num);
#endif
	//beijing add
	if (slice_num < 5)
		return 0;
	if (outctl_num > (slice_num - single_pkt_num) / 2)
		return 1;
	else
		return 0;
}

// 对攻击进行判断
int judge_tcp(tcp_vector stream_vector) {
	cluster_vector clu[CLU_NUM];
	int outnet_ctl = 0;
	outnet_ctl = judge_out_control(stream_vector, clu);
	return outnet_ctl;
}

int judge_dns(dns_vector cur) {
	if (cur.malformed_num > 50)
		return 1;
	else if (cur.max_host_name_num > 70)
		return 2;
	else if ((cur.txt_num + cur.mail_num) > 70)
		return 3;
	else if (cur.onedot_num > 70)
		return 4;
	else
		return 0;
}
