#include <stdio.h>
#include "stream_to_vector.h"
#include <stdlib.h>
#include "debug.h"
#include "init.h"
int heart_num[256];
int q[256];
int find_heartbeat(int slice_num, cluster_vector* clu, double confi,
		int* heart) {
	int heart_num = 0;
	if (slice_num < 20)
		return 0;
	int max_count = -1;
	int max_pos = -1;
	for (int i = 0; i < slice_num; i++) {
		if (clu[i].pkt_num > 5)
			continue;
		int heart_hash = heart_mkhash(clu[i].pkt_size,
				clu[i].pkt_num > 5 ? 5 : clu[i].pkt_num);
		q[heart_hash] += 1 << (8 - slice_num);
		if (max_count < q[heart_hash]) {
			max_count = q[heart_hash];
			max_pos = i;
		}
	}
	heart_num = clu[max_pos].pkt_num;
	for (int i = 0; i < heart_num; i++)
		heart[i] = clu[max_pos].pkt_size[i];
#if(SHOW_HEARTPKT)
	highlight_output(31, "########Heart packet is######## ");
	for (int i = 0; i < heart_num; i++)
		printf("%d ", heart[i]);
	highlight_output(31, "\n############################# ");
#endif
	return heart_num;
}

