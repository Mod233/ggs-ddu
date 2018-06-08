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


#include <vector>
using namespace std;

#define HASH_SIZE 20
static u_char xo[HASH_SIZE];
static u_char perm[HASH_SIZE];
void getrnd ()
{
    struct timeval s;
    u_int *ptr;
    //从如下的文件中读取随机数流
    int fd = open ("/dev/urandom", O_RDONLY);
    if (fd > 0)
    {
        read (fd, xo, HASH_SIZE);
        read (fd, perm, HASH_SIZE);
        close (fd);
        return;
    }

    //如果从"/dev/urandom"中读取到了随机数函数就返回了，那么以下不会执行
    printf("as\n");
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


//将perm数组的各个元素分别转化为0-11之间的整数，之后会在mkhash函数中使用到
//xor数组的各个元素都是char型，元素值是0和255之间的随机数
static void init_hash (void)
{
    int i, n, j;
    int p[HASH_SIZE];
    getrnd ();
    for (i = 0; i < HASH_SIZE; i++)
        p[i] = i;
    for (i = 0; i < HASH_SIZE; i++)
    {
        n = perm[i] % (HASH_SIZE - i);
        perm[i] = p[n];
        for (j = 0; j < HASH_SIZE -1 - n; j++)
            p[n + j] = p[n + j + 1];
    }
}

//增加
static u_int mkhash (char*msg){
    int len=strlen(msg);
    u_char data[HASH_SIZE];
    if(len>HASH_SIZE)
        memcpy(data,msg,HASH_SIZE);
    else{
        memcpy(data,msg,len);
        for(int i=len;i<HASH_SIZE;i++)
            data[i]='0x14';
    }
    u_int res = 0;
    //perm[]在init_hash函数中其元素分别随机存储了0-11之间的数
    //0-11之间的数分别保存在了该数组中，只是在数组中位置随机
    //所以，data[perm[i]]是随机取出data的某个元素再与xor[i]随机数
    //进行异或操作，res每次右移八位，所以res最终结果是res迭代的和
    //然后将结果与大的素数16715791(0xff100f)取余，作为hash后的值
    for (int i = 0; i < HASH_SIZE; i++)
        res = ( (res << 8) + (data[perm[i]] ^ xo[i])) % 0xff100f;
    return res%541;
}
const int MAX1  = 1e5;
void get_prime(){
    bool vis[MAX1];
    vector<int> prime;
    memset(vis,0,sizeof(vis));
    prime.clear();
    for(int i=2;i<MAX1;i++){
        if(!vis[i]) prime.push_back(i);
        for(int j=0;i*prime[j]<MAX1;j++){
            vis[i*prime[j]]=1;
        }
    }
    for(int i=0;i<100;i++)
        printf("%d\n",prime[i]);
}
int main(int argc,const char*argv[]){
    int a=3;
    get_prime();
    init_hash();
    char str[90]="suchaniceday.123421fs";
    u_int ans = mkhash(str);
    printf("Random is \n");
    for(int i=0;i<HASH_SIZE;i++){
        printf("%u,", xo[i]);
    }
    printf("\n");
    for(int i=0;i<HASH_SIZE;i++){
        printf("%u,", perm[i]);
    }
    printf("\n");
    for(int i=0;i<HASH_SIZE;i++){
        printf("perm[%d]=%u xo[%d]=%u\n", i,perm[i],i,xo[i]);
    }
    printf("hash result is %u\n",ans);
    return 0;
}
