#!/usr/bin/python
# -*-coding=utf8-*-

from __future__ import division
from stream_proc import *
# import stream_proc.py

from scipy.stats import kstest
import scipy.optimize
import sympy
import numpy as np
import shutil

fmain = open("1118result.txt", "wb")
fk = open("result.txt", "wb")
mal_ip = []


# define
# 1 trojan
# 2 normal
# 9 unknown

# 100 serverfirst
# 101 failure continuous syn
# 102 outside control

# 900 few packets
# 901 few data trans packets

# 902 automatic stream
# 903 not regular

# 200 pure download
# 201 http
# 202 inside upload
# 203 syn from out

# main logic of trojan detection
def server_first(stream):
    up_down = obj2bit(stream, 1)
    flag_s = obj2bit(stream, 6)
    flag_f = obj2bit(stream, 7)
    flag_p = obj2bit(stream, 5)
    pattern_server = [[up_down, flag_s, flag_f, flag_p], ["010", "100", "000", "001"]]
    pattern_index_server = pattern_intersection(pattern_server)
    serverfirst = 0
    if pattern_index_server:
        # print "Server first push packets!"
        # fp.write("port:" + str(stream[0][2])+"Server first push packets!\n")
        serverfirst = 1
    return serverfirst


def continuous_syn_rst(stream):
    up_down = obj2bit(stream, 1)
    flag_s = obj2bit(stream, 6)
    flag_r = obj2bit(stream, 8)
    pattern_server = [[up_down, flag_s, flag_r], ["10", "10", "01"]]
    pattern_index_server = pattern_intersection(pattern_server)
    con_syn_rst = 0
    if pattern_index_server:
        con_syn_rst = 1
    return con_syn_rst


def syn_ratio_static(stream):
    up_down = obj2bit(stream, 1)
    flag_s = obj2bit(stream, 6)
    flag_f = obj2bit(stream, 7)
    flag_r = obj2bit(stream, 8)
    flag_l = []
    for i in range(0, len(flag_s)):
        if flag_s[i] == '1' or flag_r[i] == '1' or flag_f[i] == '1':
            flag_l.append('1')
        else:
            flag_l.append('0')
    flag = "".join(flag_l)
    # print flag
    pattern_syn_up = pattern_intersection([[up_down, flag], ["1", "1"]])
    # print pattern_syn_up
    pattern_syn_down = pattern_intersection([[up_down, flag], ["0", "1"]])
    # print pattern_syn_down
    count_up = up_down.count("1")
    count_down = up_down.count("0")
    if count_up > 2:
        syn_up = len(pattern_syn_up) / count_up
    else:
        syn_up = 0
    if count_down > 2:
        syn_down = len(pattern_syn_down) / count_down
    else:
        syn_down = 0
    # print syn_up, syn_down
    return syn_up, syn_down


def syn_from_out(stream):
    up_down = obj2bit(stream, 1)
    flag_s = obj2bit(stream, 6)
    pattern_outsyn = [[up_down, flag_s], ["10", "10"]]
    pattern_index_outsyn = pattern_intersection(pattern_outsyn)
    outsyn = 0
    if pattern_index_outsyn:
        outsyn = 1
    return outsyn


def detect_http(packets):
    packets = map(abs, packets)
    nppackets = np.array(packets)
    km = np.mean(nppackets)
    kv = np.var(nppackets)

    # http packet follow lognorm distribution
    mu = math.log(km / math.sqrt(1 + kv / km / km), math.e)
    sigma = math.sqrt(math.log(1 + kv / km / km, math.e))

    stat, pvalue = kstest(packets, "lognorm", [mu, sigma])
    # print pvalue
    if pvalue > 0.05:
        return 1
    else:
        return 0


def cut_duplicated(stream_no_ack, item):
    up_down_no_ack_int = obj2time(stream_no_ack, 1)
    packetslist_no_ack = obj2time(stream_no_ack, 4)
    packetslist_no_ack_signed = signed_packets(up_down_no_ack_int, packetslist_no_ack)
    # for i in range(0,len(packetslist_no_ack_signed)):
    # 	stream_no_ack[i][4] = packetslist_no_ack_signed[i]
    packets_most = packet_count(packetslist_no_ack_signed)

    stream_cut_duplicated = [x for x in
                             stream_no_ack]  # if (x[4]*(x[1]-0.5)*2!=packets_most[0][0])]# and x[4]*(x[1]-0.5)*2!=packets_most[1][0])]
    if item:
        for i in item:
            stream_cut_duplicated = [x for x in stream_cut_duplicated if x[4] * (x[1] - 0.5) * 2 != i]
    # print packets_most
    return stream_cut_duplicated


def cut_heartbeat(packetslist_slice, up_down_slice, item):
    tmp = []
    tmp_del = []
    for i in up_down_slice:
        tmp.append(list(i))
    for freq in item:
        for i in range(0, len(up_down_slice)):
            ind = []
            judge = 0
            for j in freq:
                if j in packetslist_slice[i]:
                    ind.append(packetslist_slice[i].index(j))
                else:
                    judge = 1
            if judge == 0 and sorted(ind) == ind:
                k = 0
                for j in ind:
                    del tmp[i][j - k]
                    del packetslist_slice[i][j - k]
                    k = k + 1
                    # tmp_del.append(tmp[i])

    packetslist_slice = [x for x in packetslist_slice if x]
    # tmp = [x for x in tmp if x not in tmp_del]
    up_down_slice = []
    for i in tmp:
        if i:
            up_down_slice.append("".join(i))
    return up_down_slice, packetslist_slice


def outnet_control(stream_no_ack):
    if len(stream_no_ack) < 2:
        return []

    timeline_no_ack = obj2time(stream_no_ack, 0)

    up_down_no_ack_int = obj2time(stream_no_ack, 1)
    packetslist_no_ack = obj2time(stream_no_ack, 4)
    packetslist_no_ack_signed = signed_packets(up_down_no_ack_int, packetslist_no_ack)

    packetslist_no_ack_down = [x for x in packetslist_no_ack_signed if x < 0]

    # if max(packetslist_no_ack) < 50:
    # 	return []

    ishttp = 0
    if len(packetslist_no_ack_down) > 5:
        ishttp = detect_http(packetslist_no_ack_down)
    if ishttp:
        print "ishttp"
        fmain.write("\nishttp\n")
        return []

    up_down_no_ack = obj2bit(stream_no_ack, 1)
    up_down_slice, packetslist_slice, timeline_slice = time_slice(timeline_no_ack, up_down_no_ack,
                                                                  packetslist_no_ack_signed)

    if len(up_down_slice) < 2:
        return []
    delta_time_first = timeline_slice[1][0] - timeline_slice[0][0]
    fmain.write("\ndelta_time\n" + str(delta_time_first) + "\n")
    if delta_time_first < 0.95:
        return []

    # print packetslist_slice
    # print up_down_slice
    # fmain.write("\n")
    # fmain.write(str(packetslist_slice))
    # fmain.write("\n")
    # fmain.write("\n")
    # fmain.write(str(up_down_slice))
    # fmain.write("\n")
    # fmain.write("\n")
    # fmain.write(str(timeline_slice))
    # fmain.write("\n")
    # print timeline_slice

    # cut apriori
    item = []
    if len(up_down_slice) > 3:
        freq_packet = apriori(packetslist_slice[1:], 0.6)
        # print freq_packet
        for i in freq_packet:
            if len(i) > 1:
                item.append(i)

    if item:
        # item = set(item)
        lengthx = len(item[-1])
        fmain.write("\n" + str(lengthx))
        item = [x for x in item if len(x) == lengthx]
        # print item
        fmain.write("item\n")
        fmain.write(str(item))
        fmain.write("\n")
        up_down_slice, packetslist_slice = cut_heartbeat(packetslist_slice, up_down_slice, item)

    if len(up_down_slice) < 2:
        return []
    pkts_abs = []
    for pkts in packetslist_slice:
        pkts_abs.append(map(abs, pkts))
    up_down_slice = [up_down_slice[i] for i in range(1, len(pkts_abs)) if max(pkts_abs[i]) > 19]
    packetslist_slice = [packetslist_slice[i] for i in range(1, len(pkts_abs)) if max(pkts_abs[i]) > 19]

    if len(up_down_slice) < 1:
        return []

    # print up_down_slice
    # print packetslist_slice
    # fmain.write("\n")
    # fmain.write(str(packetslist_slice))
    # fmain.write("\n")
    fmain.write("\nb = ")
    fmain.write(str(up_down_slice))
    fmain.write("\n")
    # print timeline_slice



    outnetcontrol = []
    updown_size = []

    # if len(up_down_slice[0]) > 2 :
    # 	if not re.findall(r"1", up_down_slice[0][-3:]):
    # 		outnetcontrol.append(0)
    # 		if sum(packetslist_slice[0]) > 0:
    # 			updown_size.append(1)
    # 		else:
    # 			updown_size.append(0)

    # 	if not re.findall(r"0", up_down_slice[0][-3:]):
    # 		outnetcontrol.append(1)
    # 		if sum(packetslist_slice[0]) > 0:
    # 			updown_size.append(1)
    # 		else:
    # 			updown_size.append(0)

    slice_num = 0
    for x in up_down_slice[0:]:
        slice_num = slice_num + 1
        if len(x) > 1 and (x[0:1] == "0" and re.findall(r"1", x) or (
                len(x) > 2 and (not re.findall(r"0", x[0:6]) or not re.findall(r"0", x[-6:])))):  # or x[0:3] == "111"):
            outnetcontrol.append(1)
            if sum(packetslist_slice[slice_num - 1]) > 0:
                updown_size.append(1)
            else:
                updown_size.append(0)
        if len(x) > 1 and (x[0:1] == "1" and re.findall(r"0", x) or (
                len(x) > 2 and (not re.findall(r"1", x[0:6]) or not re.findall(r"1", x[-6:])))):
            outnetcontrol.append(0)
            if sum(packetslist_slice[slice_num - 1]) > 0:
                updown_size.append(1)
            else:
                updown_size.append(0)
    # x = ""
    # y = []
    # for i in range(1,len(up_down_slice)):
    # 	x = up_down_slice[i]
    # 	y = map(abs,packetslist_slice[i])
    # 	if len(x) > 1 and ((x[0:2] == "01" and y[1] > y[0]) or (x[0:3] == "001" and y[2] > y[0] and y[2] > y[1])):
    # 		outnetcontrol.append(1)
    # 	if len(x) > 1 and ((x[0:2] == "10" and y[1] > y[0]) or (x[0:3] == "110" and y[2] > y[0] and y[2] > y[1])):
    # 		outnetcontrol.append(0)

    # print outnetcontrol
    # print outnetcontrol
    # print updown_size
    fmain.write("\n")
    fmain.write(str(outnetcontrol))
    fmain.write("\n")
    fmain.write("\n")
    fmain.write(str(updown_size))
    fmain.write("\n")
    # return outnetcontrol
    return map(lambda a, b: int(a) * b, updown_size, outnetcontrol)


#


def trojan_judge(filename, n):
    stream_all = stream2vector(filename, n)
    stream = stream_all.packet_list
    stream_no_ack = del_ack(stream)

    syn_ratio_up, syn_ratio_down = syn_ratio_static(stream_all.packet_list)

    if syn_ratio_up > 0.8 or syn_ratio_down > 0.8:
        mal_ip.append(stream_all.src_ip + " " + stream_all.dst_ip)
        return 101, "SYN flooding detected! Continues SYN request!"
    else:
        return 102, "unknown"
    stream_all.multistream_list = total2multistream(stream_all.packet_list)

    # con_syn_rst = map(continuous_syn_rst,stream_all.multistream_list)
    # if sum(con_syn_rst) > 3:
    # 	if sum(con_syn_rst)/len(con_syn_rst) > 0.8:
    # 		mal_ip.append(stream_all.src_ip + " " + stream_all.dst_ip)
    # 		return 101,"Trojan detected! Continues request connections!"

    # synfromout = map(syn_from_out,stream_all.multistream_list)
    # if len(synfromout) > 0:
    # 	if sum(synfromout) > 0.8:
    # 		# print " "
    # 		return 203, "Normal! syn from outside!"

    # serverfirst = map(server_first,stream_all.multistream_list)
    # if sum(serverfirst):
    # 	if sum(serverfirst)/len(serverfirst) > 0.6:
    # 		return 100,"Trojan detected! Server first push packets!"

    if len(stream_no_ack) < 3:
        return 900, "Unknow! Few packets!"

    updown_all_no_ack = obj2time(stream_no_ack, 1)
    # print updown_all_no_ack
    # print sum(updown_all_no_ack)
    # print len(updown_all_no_ack)
    # print sum(updown_all_no_ack)/len(updown_all_no_ack)
    if sum(updown_all_no_ack) < 2 or sum(updown_all_no_ack) / len(updown_all_no_ack) < 0.1:
        return 200, "Normal! Pure download!"

    # multistream = map(del_ack,stream_all.multistream_list)
    # multistream = [stream for stream in multistream if len(stream)>1]

    # if not multistream:
    # 	return 901, "Unknow! Few data trans packets!"

    # if len(multistream) = 1:

    outnet_ctl = outnet_control(stream_no_ack)
    if not outnet_ctl:
        return 902, "Normal! Automatic stream!"
    if len(outnet_ctl) > 0 and sum(outnet_ctl) / len(outnet_ctl) > 0.73:
        mal_ip.append(stream_all.src_ip + " " + stream_all.dst_ip)
        return 102, "Trojan detected! Outside control!"

    return 903, "Unknown! Not regular!"


# printheader(stream)
# printstream(stream.packet_list)
# printmultistream(stream_all.multistream_list)

if __name__ == "__main__":
    # filename = sys.argv[0]
    # filename = sys.argv[1]
    filelist = []
    multistream = []
    path = "darpa/"
    filelist = os.listdir(path)
    starttime = datetime.datetime.now()
    file_num = len(filelist)
    for i in range(250, 251, 1):
        print i
        packetn = i
        trojan_num = 0
        unknown_num = 0
        mal_file = []
        for filename in filelist:
            # print filename
            fmain.write("\n\n")
            fmain.write(filename + "\n")
            res, string = trojan_judge(path + filename, i)
            if res == 100 or res == 101 or res == 102:
                # print "is trojan!"
                fmain.write("is trojan\n")
                trojan_num = trojan_num + 1
                shutil.copyfile(path + filename, "tmp/" + filename)
                mal_file.append(filename)
            if res == 900 or res == 903:
                unknown_num = unknown_num + 1
            # print string
            fmain.write("\n")
            fmain.write(str(string))
            fmain.write("\n")
        # fmain.write(string)
        # IPython.embed()
        endtime = datetime.datetime.now()
        fk.write(str(i) + " " + str(trojan_num) + " " + str(endtime - starttime) + "\n")
    print path
    print endtime - starttime
    print "detect:" + str(file_num)
    print "trojan:" + str(trojan_num)
    print "normal:" + str(file_num - trojan_num - unknown_num)
    print "unknown:" + str(unknown_num)
    for x in mal_ip:
        print x
    for x in mal_file:
        print x
fmain.close()
fk.close()