#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include "debug.h"
//#include "init.h"
#define HASH_SIZE 20

u_char xo[HASH_SIZE] = { 77, 22, 182, 100, 238, 136, 249, 164, 109, 222, 190,
		45, 251, 120, 99, 107, 151, 187, 29, 145 };
u_char perm[HASH_SIZE] = { 0, 16, 15, 14, 5, 4, 18, 2, 9, 17, 7, 8, 11, 12, 10,
		1, 19, 6, 3, 13 };
void getrnd() {
	struct timeval s;
	u_int *ptr;
	//从如下的文件中读取随机数流
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd > 0) {
		read(fd, xo, HASH_SIZE);
		read(fd, perm, HASH_SIZE);
		close(fd);
		return;
	}

	//如果从"/dev/urandom"中读取到了随机数函数就返回了，那么以下不会执行

	/*
	 gettimeofday (&s, 0);
	 srand (s.tv_usec);
	 ptr = (u_int *) xo;
	 *ptr = rand ();
	 *(ptr + 1) = rand ();
	 ptr = (u_int *) perm;
	 *ptr = rand ();
	 *(ptr + 1) = rand ();
	 */
}

//增加
int string_mkhash(char*msg) {
	int len = strlen(msg);
	u_char data[HASH_SIZE];
	if (len > HASH_SIZE)
		memcpy(data, msg, HASH_SIZE);
	else {
		memcpy(data, msg, len);
		for (int i = len; i < HASH_SIZE; i++)
			data[i] = '\x14';
	}
	int res = 0;
	//perm[]在init_hash函数中其元素分别随机存储了0-11之间的数
	//0-11之间的数分别保存在了该数组中，只是在数组中位置随机
	//所以，data[perm[i]]是随机取出data的某个元素再与xor[i]随机数
	//进行异或操作，res每次右移八位，所以res最终结果是res迭代的和
	//然后将结果与大的素数16715791(0xff100f)取余，作为hash后的值
	for (int i = 0; i < HASH_SIZE; i++)
		res = ((res << 8) + (data[perm[i]] ^ xo[i])) % 0xff100f;

	return (res % 541 + 541) % 541;
}

u_int ip_mkhash(u_int src, u_int dest) {
	u_int tmp;
	if (src < dest) {
		tmp = src;
		src = dest;
		dest = tmp;
	}
	u_int res = 0;
	int i;
	u_char data[8];
	u_int *stupid_strict_aliasing_warnings = (u_int*) data;
	*stupid_strict_aliasing_warnings = src;
	*(u_int *) (data + 4) = dest;
	for (i = 0; i < 8; i++)
		res = ((res << 8) + (data[perm[i]] ^ xo[i])) % 0xff100f;
	return res % IP_SIZE;
}

u_int heart_mkhash(u_int* num, int size) {
	int cnt = 0;
	u_int res = 0;
	//if num is an array from struct , how to end the *num???
	for (int i = 0; i < size; i++) {
		cnt++;
		res = res * 31 + num[i];
		if (cnt > 5)
			break;
	}
	return res % 523;
}

void highlight_output(int color_id, char*msg) {
	//"RED": 31, "GREEN": 32, "YELLOW": 33, "BLUE": 34, "PURPLE": 35, "CYAN": 36, "GREY": 37, "WHITE": 38
	printf("\033[1;%dm%s\033[1;0m\n", color_id, msg);
}
