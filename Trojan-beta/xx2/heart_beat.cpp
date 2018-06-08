#include<stdlib.h>
#include "heart_beat.h"

static void ListAdd(SqList_heart *L, int e)
{
	L->data[L->length] = e;
	L->number[L->length] = 1;
	L->length++;
}

static int LocateElem(SqList_heart* L,int e)
{
	int i;
	for(i=0; i<L->length; i++)
		if(L->data[i] == e)
			return i; //返回元素e的位号
	return -1; //退出循环，说明查找失败
}

//按值查询
static int Elem_num(SqList_heart* L,int e)
{
	int i;
	i = LocateElem(L, e);

	if(i != -1)
		return L->number[i]; //返回元素e的shumu
	else
		return 0; //查找失败
}

static void Elem_num_add(SqList_heart* L,int e)
{
	int i;
	i = LocateElem(L, e);

	if(i != -1)
		L->number[i]++; //返回元素e的shumu
} 


static void getC(cluster* cluster, int* C, int lengthD, set *keys)
{
	//'''对keys中的每一个key进行计数'''
	int judge[250];
	int c;

	for(int i=0;i<keys->num;i++)
	{
		c = 0;
		for (int j=0;j<lengthD;j++)
		{
			int k;
			for (k=0;k < keys->size;k++)
			{
				int l;
				for (l=0;l < cluster[j].packet_number;l++)
				{
					if (keys->item[i].size[k] == cluster[j].packet_size_list[l])
					{
						judge[k]= l;
						break;
					}
				}
				if(l == cluster[j].packet_number)
					break;
			}
			if(k == keys->size)
			{
				int m;
				for(m=1;m<k;m++)
					if(judge[m]<judge[m-1])
						break;
				if(m == k)
					c++;
			}
		}
		C[i] = c;
	}
	return;
}

static void getCutKeys(set* keys, int* CNum, float minSup, int length)
{
	//'''剪枝步'''
	int n,x;

	n=keys->num;
	x=0;
	for (int i=0;i<n;i++)
	{
		if ((float)(CNum[i])/(float)(length) < minSup)
		{
			for(int k=i-x;k<keys->num-1;k++)
			{
				int j;
				for(j=0;j<keys->size;j++)
					keys->item[k].size[j] = keys->item[k+1].size[j];
			}
			keys->num--;
			x++;
		}
	}
	return;
}

static void aproiri_gen(set* keys1, set* keys2)
{
	//'''连接步'''
	int key[4];

	keys2->num =  0;
	keys2->size = keys1->size+1;

	//printf("aproiri_gen\n");

	for(int i=0;i<keys1->num;i++)
		for(int j=0;j<keys1->num;j++)
			if (i != j)
			{
				int k;
				for(k=0;k<keys1->size;k++)
					key[k] = keys1->item[i].size[k];
				int m;
				for(m=0;m<keys1->size;m++)
				{
					int l;
					for(l=0;l<keys1->size;l++)
						if (keys1->item[j].size[m] == key[l])
							break;
					if(l == keys1->size)
					{
						key[k]=keys1->item[j].size[m];
						k++;
						break;
					}
				}

				if (k == keys1->size+1)
				{
					int x;
					for(x=0;x<keys2->num;x++)
					{
						int y;
						for(y=0;y<keys2->size;y++)
							if(key[y] != keys2->item[x].size[y])
								break;
						if(y == keys2->size)
							break;
					}

					if (keys2->num == 0 || x == keys2->num)
					{
						for(int z=0;z<keys2->size;z++)
						{
							keys2->item[keys2->num].size[z] = key[z];
						}
						keys2->num++;

					}
				}
			}
}
static double ceil(double x)
{
   register double ret;
   unsigned short int temp1, temp2;
  
   __asm__("fnstcw %0" : "=m" (temp1));
   temp2 = (temp1 & 0xf3ff) | 0x0800; /* rounding up */
   __asm__("fldcw %0" : : "m" (temp2));
   __asm__("frndint" : "=t" (ret) : "0" (x));
   __asm__("fldcw %0" : : "m" (temp1));
  
   return ret;
}//向上取整


//cluster:每个时间片 lengthD:时间片数量 ite:心跳集合
int apriori(cluster* cluster, int lengthD, float minSup, set* ite)
{
	//'''频繁项集用keys表示，
	//key表示项集中的某一项，
	//cutKeys表示经过剪枝步的某k项集。
	//C表示某k项集的每一项在事务数据库D中的支持计数
	//'''
	int threshold;
	threshold = lengthD*4/ceil(lengthD * minSup);

	SqList_heart L;
	L.length = 0;

	for (int i=0;i<lengthD;i++)
	{
		for (int j=0;j<cluster[i].packet_number;j++)
		{
			if (Elem_num(&L,cluster[i].packet_size_list[j]))
			{
				if(abs(cluster[i].packet_size_list[j]) < 1000)
					Elem_num_add(&L,cluster[i].packet_size_list[j]);
			}
			else
			{
				ListAdd(&L,cluster[i].packet_size_list[j]);
			}
		}
	}


	set cutKeys1;
	cutKeys1.num = 0;
	cutKeys1.size = 1;
	for(int i=0;i<L.length;i++)
		if ((float)(L.number[i])/(float)(lengthD) >= minSup)
		{
			cutKeys1.item[cutKeys1.num].size[0] = L.data[i];
			cutKeys1.num++;
		}

	if(cutKeys1.num < 2)
	{
		return 0;
	}

	set* keys = &cutKeys1;

	set a;
	set* keysa = &a;
	keysa->num = 0;
	keysa->size = 0;
	set* temp;

	int x = 0;

	int C[250];
	while(keys->num != 0)
	{
		getC(cluster, C,lengthD, keys);

		getCutKeys(keys, C, minSup, lengthD);

		if ((x == 0 && keys->num > threshold) || keys->num == 0)
		{
			return 0;
		}
		x++;

		if (x > 3)
			return 0;

		ite->num =  keys->num;
		ite->size = keys->size;

		int i;
		for(i=0;i<keys->num;i++)
		{
			int j;
			for(j=0;j<keys->size;j++)
				ite->item[i].size[j] = keys->item[i].size[j];
		}

		aproiri_gen(keys, keysa);
		temp = keys;
		keys = keysa;
		keysa = temp;
	}

	if(ite->size < 2)
		return 0;
	return 1;
}
