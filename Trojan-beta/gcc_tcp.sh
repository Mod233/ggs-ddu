#!/bin/bash

g++ /home/csober/Documents/Github/ggs-ddu/Trojan-beta/xx2/heart_beat.cpp \
/home/csober/Documents/Github/ggs-ddu/Trojan-beta/xx2/main.cpp \
/home/csober/Documents/Github/ggs-ddu/Trojan-beta/xx2/winpcap.cpp \
-o bin/tcp.out -l pcap

