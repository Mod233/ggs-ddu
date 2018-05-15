#!/bin/bash
g++ -std=c++11 Split_flow.cpp -pthread -l pcap \
-o bin/main.out

