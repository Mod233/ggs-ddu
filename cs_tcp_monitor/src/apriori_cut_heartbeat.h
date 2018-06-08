#ifndef APRIORI_CUT_HEARTBEAT_H_
#define APRIORI_CUT_HEARTBEAT_H_
#include <string>
#include <map>
#include <set>
#include <vector>
typedef std::map<std::set<std::string>, int> map_s;

int find_heartbeat(int slice_num, cluster_vector* clu, double confi,
		int* heart);

#endif /* APRIORI_CUT_HEARTBEAT_H_ */
