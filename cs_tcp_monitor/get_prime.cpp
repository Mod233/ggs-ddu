#include <iostream>
#include <cmath>
#include <vector>
#include <cstdio>
#include <cstring>
using namespace std;
vector<int> prime;
#define MAX 1000
void _init(){
    prime.clear();
    bool vis[MAX];
    memset(vis,0,sizeof(vis));
    for(int i=2;i<MAX;i++){
        if(!vis[i]) prime.push_back(i);
        for(int j=0;j<prime.size()&&i*prime[j]<MAX;j++){
            vis[i*prime[j]]=1;
            if(i%prime[j]==0) break;
        }
    }
    for(int i=0;i<100;i++)
        printf("%d\n",prime[i]);
}
int main(int argc,const char*argv[]){
    _init();
    return 0;
}
