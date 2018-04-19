from scapy.all import *
import time
import datetime
import os


fp = open("result.txt", "wb")
class tcp_stream:
    def __init__(self):
        self.ser_port = 0
        self.cli_port = 0
        self.ser_ip = ""
        self.cli_ip = ""
        self.packet_list = []

def stream2vector(file):
    dpkt = rdpcap(file)
    #for i in range(0, len(file)):
    pos1 = file.find(':')
    pos2 = file.find('-')
    pos3 = file.find(':', pos1+1)
    ser_ip = file[0:pos1]
    ser_port = file[pos1+1:pos2]
    cli_ip = file[pos2+1:pos3]
    cli_port = file[pos3+1]
    for buf in dpkt:
        src_ip = buf[IP].src
        dst_ip = buf[IP].src
        src_port = buf[TCP].sport
        dst_port = buf[TCP].dport
        len = buf[IP].len


if __name__ == "__main__":
    stream = tcp_stream()
    start_time = datetime.datetime.now()
    filelist = []
    path = "tcp_flow/"
    filelist = os.listdir(path)
    for filename in filelist:
        print filename
        fp.write(filename + "\n\n\n")
        stream = stream2vector(filename)
        detect_tcp(stream)
    print "finish"

