#ifndef DEBUG_H_
#define DEBUG_H_

#define SHOW_SLICE_RESULT 0
#define SHOW_SLICE_RESULT_AFTER_CUT 0
#define SHOW_OUTCTL 0
#define SHOW_HEARTPKT 1
#define CUT_HEARTBEAT 1
#define JUDGE_FILE 1
#define SHOW_CHILD_PATH 1
#define SHOW_CK  0
#define SHOW_CK_FINAL 0
#define CONFIGDENT 0.6
#define SHOW_DNS_VECTOR 1
#define IP_SIZE 300000

extern unsigned int subnet_intranet; //存储子网ip，用于区分内部IP地址和外部IP地址
extern unsigned int subnet_extranet; //存储子网ip，用于区分内部IP地址和外部IP地址
extern unsigned int subnet_mask;  //设定子网掩码，用于区获取子网号

#endif /* DEBUG_H_ */
