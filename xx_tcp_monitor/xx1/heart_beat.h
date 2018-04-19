#ifndef _NG_HEART_BEAT_H
#define _NG_HEART_BEAT_H

#include "checkmain.h"

typedef struct
{
	int data[250];
	int number[250];
	int length;
}SqList_heart;


int apriori(cluster* cluster_list, int lengthD, float minSup, set* ite);
#endif /* _NG_HEART_BEAT_H */
