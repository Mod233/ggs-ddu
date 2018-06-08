#ifndef SRC_INIT_H_
#define SRC_INIT_H_
#include <stdio.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

void getrnd();

void highlight_output(int color_id, char*msg);
int string_mkhash(char*msg);
u_int ip_mkhash(u_int src, u_int dest);
u_int heart_mkhash(u_int* num,int size);

#endif /* SRC_INIT_H_ */
