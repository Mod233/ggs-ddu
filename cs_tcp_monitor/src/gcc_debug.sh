#!/bin/bash

g++ judge_out_control.cpp stream_to_vector.cpp apriori_cut_heartbeat.cpp init.cpp main.cpp -l pcap -g -o debug_https.out
