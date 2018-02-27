from scapy.all import *
import time
import IPython
import itertools
import datetime
import os
from apriori import *

fp = open('1115_file_packet_len_static.txt', "wb")
global packetn


###poacket_process
class streamstruct:
    def __init__(self):
        self.linux_time = 0
        self.print_time = ""
        self.src_ip = ""
        self.dst_ip = ""
        self.packet_num = 0
        self.sport_num = 0
        self.packet_list = []
        self.multistream_list = []


        # print stream


def printheader(stream):
    # fp.write("\n----------------------------\n")
    # fp.write("time,up,sport,dport,length,flagP,flagS,flagF,flagA,num")
    # fp.write("\n----------------------------\n")
    print "\n----------------------------\n"
    print stream.print_time
    print stream.src_ip + '------>' + stream.dst_ip
    print "time,up,sport,dport,length,flagP,flagS,flagF,flagA,num"
    print "\n----------------------------\n"


def printstream(stream):
    for i in stream:
        print i


def printmultistream(stream):
    print "\n----------------------------\n"
    for i in stream:
        printstream(i)
        print "\n"
    print "\n----------------------------\n"


# file to vector
def stream2vector(filename, n):
    pkts = rdpcap(filename, n)
    packet_num = len(pkts)

    # stream matrix
    stream = streamstruct()
    stream.packet_num = packet_num

    # time info
    time_start = pkts[0].time
    stream.linux_time = time_start
    stream.print_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time_start))

    # ip info
    # swap ip info ??
    srcip = pkts[0][IP].src
    if srcip == '10.104.171.2' or srcip.split('.')[
        0] == '172' or srcip == '192.168.81.139' or srcip == '192.168.81.140':
        dstip = pkts[0][IP].dst
    else:
        dstip = srcip
        srcip = pkts[0][IP].dst

    stream.src_ip = srcip
    stream.dst_ip = dstip

    for i in range(0, packet_num):

        tmpIP = pkts[i][IP]
        tmpTCP = pkts[i][TCP]

        # time
        timer = round(pkts[i].time - time_start, 3)

        # len of application layel
        length = tmpIP.len - tmpIP.ihl * 4 - tmpTCP.dataofs * 4

        # up or down
        if tmpIP.src == srcip:
            up = 1
            # port
            sport = tmpTCP.sport
            dport = tmpTCP.dport
        else:
            up = 0
            # port
            dport = tmpTCP.sport
            sport = tmpTCP.dport

        # flags
        flagR = (tmpTCP.flags >> 2) & 1  # RST
        flagP = (tmpTCP.flags >> 3) & 1  # PSH
        flagS = (tmpTCP.flags >> 1) & 1  # SYN
        flagF = (tmpTCP.flags) & 1       # FIN

        stream.packet_list.append((timer, up, sport, dport, length, flagP, flagS, flagF, flagR, i))
    return stream


# total->multistream
def total2multistream(stream):
    sorted_stream = []
    multistream_list = []
    sorted_stream = sorted(stream, key=lambda packets: packets[2])  # sorted by port.
    length = len(stream)
    j = 0
    for i in range(0, length - 1):
        if sorted_stream[i][2] != sorted_stream[i + 1][2]:
            multistream_list.append(sorted_stream[j:i + 1])
            j = i + 1
    multistream_list.append(sorted_stream[j:length])
    return multistream_list


###vector_process
# serilization
def obj2bit(stream, i):
    string = ''.join([str(x[i]) for x in stream])
    return string


def pktlen2bit(stream):
    string = ''.join([str(int(x[4] > 0)) for x in stream])
    return string


def obj2time(stream, i):
    timep = [x[i] for x in stream]
    return timep


def pattern_match(str, pt):
    index = []
    indextmp = -1
    start = 0
    while True:
        indextmp = str.find(pt, start)
        if indextmp != -1:
            index.append(indextmp)
            start = 1 + indextmp
        else:
            break
    return index


def pattern_intersection(pattern):
    index = list(map(pattern_match, pattern[0], pattern[1]))
    if not index:
        print "not match!"
    else:
        tmp = index[0]
        tmp1 = []
        for i in index:
            tmp1 = [val for val in tmp if val in i]
            tmp = tmp1
    return tmp


##parameter delta_time
def instant_response(timeline, pattern_index, printstring):
    instant_intra = 0
    not_instant_intra = 0
    if not pattern_index:
        # print "0 instant response from " + string +"net"
        print ""
    # fp.write("0 instant response from " + printstring +"net\n")
    else:
        for i in pattern_index:
            if timeline[i + 1] - timeline[i] < 1.5:
                instant_intra += 1
            else:
                not_instant_intra += 1
                # print instant_intra,
                # print "instant response from " + str +"net"
                # print not_instant_intra,
                # print "not_instant response from " + str +"net"
                # fp.write(str(instant_intra)+" ")
                # fp.write("instant response from " + printstring +"net\n")
                # fp.write(str(not_instant_intra)+" ")
                # fp.write("not_instant response from " + printstring +"net\n")

    return instant_intra, not_instant_intra


# del packetlen=0
def del_ack(stream):
    new_stream = [i for i in stream if i[4] > 1]
    return new_stream


##heartbeat
# packet len static
def packet_count(packet_list):
    packet_set = set(packet_list)
    count_packet = {}
    for each in packet_list:
        count_packet[each] = count_packet.get(each, 0) + 1
    packet_len_static = sorted(count_packet.iteritems(), key=lambda a: a[1], reverse=True)
    # print "packet_signed_static"
    # print packet_len_static
    # fp.write("\n")
    # fp.write("packet_signed_static\n")
    for x in packet_len_static:
        fp.write("(" + str(x[0]) + "," + str(x[1]) + ")")
    fp.write("\n")
    return packet_len_static


def packet_count_with_up_down(packetlist, up_down):
    packet_set = set(packetlist)
    count_packet = {}
    for i in packet_set:
        count_packet[i] = [0, 0, 0]
    length = len(packetlist)
    for i in range(0, length):
        each = packetlist[i]
        count_packet[each][0] = count_packet[each][0] + 1
        if up_down[i] == 1:
            count_packet[each][1] = count_packet[each][1] + 1
        if up_down[i] == 0:
            count_packet[each][2] = count_packet[each][2] + 1
    packet_len_static = sorted(count_packet.iteritems(), key=lambda a: a[1][0], reverse=True)
    # print "packet_static_with_updown"
    # print packet_len_static
    # fp.write("\n")
    # fp.write(str(len(set(packetlist))))
    # fp.write("\n")
    for key, value in packet_len_static:
        fp.write("(" + str(key) + "," + str(value[0]) + "," + str(value[1]) + "," + str(value[2]) + ")")
    fp.write("\n")
    return packet_len_static


def detect_long_constant(string, n):
    serial1 = string.split("0")
    serial1 = [i for i in serial1 if i != '']
    serial1 = sorted(serial1, reverse=True)
    serial = []
    tmpn = n
    if len(serial1) < n:
        tmpn = len(serial1)
    for j in range(0, tmpn):
        serial.append(serial1[j])

    serial0 = string.split("1")
    serial0 = [i for i in serial0 if i != '']
    serial0 = sorted(serial0, reverse=True)
    tmpn = n
    if len(serial0) < n:
        tmpn = len(serial0)
    for j in range(0, tmpn):
        serial.append(serial0[j])
    # print "long_constant all 0/1 serial"
    # print serial
    fp.write("long_constant all 0/1 serial\n")
    fp.write(str(serial))
    fp.write("\n")
    return serial


def detect_big_packets(up_down, packetlist, n):
    up_down = [(tmp - 0.5) * 2 for tmp in up_down]
    packet_len = map(lambda x, y: x * y, up_down, packetlist)
    packet_len_sorted = sorted(packet_len, key=lambda packet: abs(packet), reverse=True)
    count = len(packet_len_sorted)
    big_packet_list = []
    small_packet_list = []
    if count < n:
        big_packet_list = packet_len_sorted
        small_packet_list = big_packet_list
    else:
        big_packet_list = packet_len_sorted[0:n]
        small_packet_list = packet_len_sorted[-n:count]
    # print big_packet_list,small_packet_list
    return packet_len_sorted, big_packet_list, small_packet_list


def signed_packets(up_down, packetlist):
    up_down = [(tmp - 0.5) * 2 for tmp in up_down]
    packet_len = map(lambda x, y: int(x * y), up_down, packetlist)
    # print big_packet_list,small_packet_list
    return packet_len


# time_slice_serilization
def time_slice(timeline, up_down, packetlist):
    length = len(up_down)
    if length <= 1:
        return [], [], []
    delta_time = []
    stlen = length // 3
    edlen = length * 2 // 3
    for j in range(1, length):
        delta_time.append(timeline[j] - timeline[j - 1])
    delta_time_max = max(delta_time)
    timeslice = delta_time_max / 2.0  # 1.5
    # print "timeslice_delta" + str(timeslice)
    fp.write("\n")
    fp.write("timeslice_delta " + str(timeslice) + "\n")
    last_i = 0
    up_down_slice = []
    packetlist_slice = []
    timeline_slice = []
    for i in range(1, length):
        if (timeline[i] - timeline[i - 1] > 0.8) and (
                            timeline[i] - timeline[i - 1] > 5 or timeline[i] - timeline[last_i] > timeslice or timeline[
                i] - timeline[i - 1] > (timeline[edlen] - timeline[stlen]) / (edlen - stlen) * 5 or (
            timeline[i] - timeline[i - 1]) * (i - 1 - last_i) > 5 * (
            timeline[i - 1] - timeline[last_i])):  # 0.5 react_time
            # print timeline[i]
            timeline_slice.append(timeline[last_i:i])
            up_down_slice.append(up_down[last_i:i])
            packetlist_slice.append(packetlist[last_i:i])
            last_i = i
    timeline_slice.append(timeline[last_i:length])
    up_down_slice.append(up_down[last_i:length])
    packetlist_slice.append(packetlist[last_i:length])
    # print "updown and  packet serial by time"
    # if len(up_down_slice) < 10:
    # 	print up_down_slice,packetlist_slice,timeline_slice
    # else:
    # 	print up_down_slice[0:20],packetlist_slice[0:20],timeline_slice[0:20]
    fp.write("updown and  packet serial by time\n")
    if len(up_down_slice) < 20:
        fp.write(str(timeline_slice) + "\n" + str(up_down_slice) + "\n" + str(packetlist_slice))
        return up_down_slice, packetlist_slice, timeline_slice  # ,packetlist_slice
    else:
        fp.write(
            str(timeline_slice[0:20]) + "\n" + str(up_down_slice[0:20]) + "\n" + str(packetlist_slice[0:20]) + "\n")
        return up_down_slice[0:20], packetlist_slice[0:20], timeline_slice[0:20]  # ,packetlist_slice

        # def packet2abc(stream)

        # produce serial
        # ef
        # main logic
        # single stream

        # reverse ctl


def detect_reverse_ctl(stream):
    fp.write("\n")
    fp.write("stream_total_time " + str(stream[-1][0] - stream[0][0]))
    fp.write("\n")
    stream_no_ack = del_ack(stream)
    if not stream_no_ack:
        return
    # printstream(stream_no_ack)
    up_down_no_ack = obj2bit(stream_no_ack, 1)
    # packetlen = pktlen2bit(stream)
    timeline_no_ack = obj2time(stream_no_ack, 0)

    instant_res_intra = 0
    pattern_index_intra = []
    instant_res_out = 0
    pattern_index_out = []

    # instant response
    # not_instant_res_intra,instant_res_intra,
    # pattern_intra = [[up_down,packetlen],["011","101"]]

    # pattern_intra = [[up_down_no_ack],["0111"]]
    # pattern_index_intra = pattern_intersection(pattern_intra)
    # instant_res_intra,not_instant_intra =  instant_response(timeline_no_ack,pattern_index_intra,"intra")
    # if not_instant_intra:
    # 	fp.write("human inside!\n")
    # pattern_out = [[up_down_no_ack],["1000"]]
    # pattern_index_out = pattern_intersection(pattern_out)
    # instant_res_out,not_instant_out =  instant_response(timeline_no_ack,pattern_index_out,"out")
    # if not_instant_out:
    # 	fp.write("human outside!\n")

    # pattern_out = [[up_down,packetlen],["100","101"]]

    # server first
    up_down = obj2bit(stream, 1)
    flag_s = obj2bit(stream, 6)
    flag_f = obj2bit(stream, 7)
    flag_p = obj2bit(stream, 5)
    pattern_server = [[up_down, flag_s, flag_f, flag_p], ["010", "100", "000", "001"]]
    pattern_index_server = pattern_intersection(pattern_server)
    server_first = 0
    if pattern_index_server:
        # print "Server first push packets!"
        fp.write("port:" + str(stream[0][2]) + "Server first push packets!\n")
        server_first == 1

    ####fixed time & length heartbeat
    count_packet = {}
    packetlist_no_ack = obj2time(stream_no_ack, 4)
    # print packetlist_no_ack
    up_down_no_ack_int = obj2time(stream_no_ack, 1)

    # simple pure 0 pure 1
    fp.write("updown_no_ack\n")
    fp.write(up_down_no_ack + "\n")
    serial_long = detect_long_constant(up_down_no_ack, 2)
    # count_packet = packet_count_with_up_down(packetlist_no_ack,up_down_no_ack_int)
    # big_packets = detect_big_packets(up_down_no_ack_int,packetlist_no_ack,5)

    # fp.write("".join(serial_long)+"\n")
    packetlist_no_ack_signed = signed_packets(up_down_no_ack_int, packetlist_no_ack)
    count_packet_signed = packet_count(packetlist_no_ack_signed)
    if len(set(packetlist_no_ack)) > 20:
        fp.write("too many packets length!\n")
    up_down_slice, packetlist_slice, timeline_slice = time_slice(timeline_no_ack, up_down_no_ack,
                                                                 packetlist_no_ack_signed)
    up_down_slice_array = []
    for x in up_down_slice:
        up_down_slice_array.append(list(x))
    print "up_down_frequent itemset", apriori(up_down_slice_array, 0.7)
    print "\n"
    print "packet_length_list itemset", apriori(packetlist_slice, 0.7)
    print "\n"
    fp.write("up_down_frequent itemset" + str(apriori(up_down_slice_array, 0.7)) + "\n")
    fp.write("packet_length_list itemset" + str(apriori(packetlist_slice, 0.7)) + "\n")


# nonsense
def file2sh(path, filelist):
    fd = open('p2pl.sh', 'wb')
    fd.write("#!/bin/bash\n")
    for i in filelist:
        fd.write("tshark -r '" + path + i + "' -Y 'tcp' -w '" + "sample0/" + i + "' -F libpcap\n")


def file_cut_empty(pat, filelist):
    for i in filelist:
        tmp = rdpcap(path + i)
        if not tmp:
            os.remove(path + i)
            print filelist


# def all_to_ippaair(filename,path):
# realized in lua

if __name__ == "__main__":
    stream = streamstruct()
    starttime = datetime.datetime.now()
    # filename = sys.argv[0]
    # filename = sys.argv[1]
    filelist = []
    multistream = []
    path = "sample0/"
    filelist = os.listdir(path)
    # print filelist[0]
    # print filelist[-1]
    # file2sh(path,filelist)
    # filelist = filelist[0:30]
    # print filelist
    # file_cut_empty(path,filelist)
    for filename in filelist:
        print filename
        fp.write("\n\n")
        fp.write(filename + "\n")
        stream = stream2vector(path + filename)
        stream.multistream_list = total2multistream(stream.packet_list)
        stream.sport_num = len(stream.multistream_list)
        # printheader(stream)
        # printstream(stream.packet_list)
        # printmultistream(stream.multistream_list)
        for i in stream.multistream_list:
            detect_reverse_ctl(i)
    endtime = datetime.datetime.now()
    print endtime - starttime
    # IPython.embed()
    # print "".join(stream)
    # stream.make_table()
    # fp.close()