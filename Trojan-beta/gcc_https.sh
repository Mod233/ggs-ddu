#!/bin/bash

g++ /home/csober/Documents/Github/ggs-ddu/cs_tcp_monitor/src/judge_out_control.cpp \
/home/csober/Documents/Github/ggs-ddu/cs_tcp_monitor/src/stream_to_vector.cpp \
/home/csober/Documents/Github/ggs-ddu/cs_tcp_monitor/src/apriori_cut_heartbeat.cpp \
/home/csober/Documents/Github/ggs-ddu/cs_tcp_monitor/src/main.cpp \
/home/csober/Documents/Github/ggs-ddu/cs_tcp_monitor/src/init.cpp \
-l pcap -o bin/https.out
