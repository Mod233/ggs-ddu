from scapy.all import *
import time
import datetime
import os
fp = open('result.txt', "wb")
warnsub = 30
white_list = ["qq.com", "baidu.com", "sina.com", "google.com", "4399.com", "youku.com", "souhu.com", "taobao.com", "sina.com",
              "dgso.com", "163.com", "hao123.com", "tudou.com", "pps.tv", "xunlei.com", "sogou.com", "56.com", "tmall.com", "ku6.com",
              "tmall.com", "ifeng.com", "360.cn", "so.com", "2345.com", "qiyi.com", "alipay.com", "renren.com", "sm.cn", "zol.com",
              "tianya.cn", "paipai.com", "microsoft.com", "pptv.com", "kugou.com", "joy.cn", "96pk.com", "10086.cn", "pomoho.com", "youdao.com",
              "58.com", "xinhuanet.com", "letv.com", "mop.com", "m18.com", "douban.com", "zhihu.com", "sdo.com", "alibaba.com",
              "funshion.com", "vancl.com", "126.com", "wushen.com", "6.cn", "soufun.com", "jiayuan.com", "china.com", "csdn.com",
              "bilibili.com", "kugou.com", "jd.com", "jingdong.com", "meituan.com", "dnion.com", "version.bind", "activum.nu", "VERSION.BIND"]

path = '/mnt/myusbmount/Trojan_Monitor/dns_flow/'
# path = '/home/csober/Documents/Github/ggs-ddu/GP/trojan_monitor/dns_monitor/wrong_test/'


class dns_stream:
    def __init__(self):
        self.port = 0
        self.domain_num = 0
        self.time = 0
        self.upload = 0
        self.download = 0
        self.packet_list = []
        self.multistream_list = []


def stream2vector(dir):
    dpkt = rdpcap(dir)
    stream = dns_stream()

    # time info
    time_start = dpkt[0].time
    stream.time = time_start
    cnt = 0
    domain_list = []
    subdomain_num = {'subdomain_num': int(0)}
    topdomain_list = []
    transaction_id_list = []
    for buf in dpkt:
        cnt += 1
        srcip = buf[IP].src
        dstip = buf[IP].dst
        srcport = buf[UDP].sport
        dstport = buf[UDP].dport
        dir = 0  # 0:up 1:down
        upload = 0
        download = 0
        malformed = 0  # 0:ok 1:malformed
        use_port = 0
        timer = round(buf.time - time_start, 5)
        cor_length = buf[IP].len - 28  # ip_header 20 udp_header 8
        real_length = len(buf[IP]) - 20 - 8  #
        new_domain = 0
        subcnt = 0
        topdomain = ''
        # try to catch DNS part.
        try:
            tmp = buf[IP]
            tmp = buf[DNS]
        except Exception, e:
            print e.message
            continue

        try:
            if cor_length != real_length and buf[IP].len > 46:  # in case padding some bytes.
                #print srcport, " ", dstport
                #print "length"
                malformed = 1
            elif buf[DNS].qdcount > 2 or buf[DNS].ancount > 50 or buf[DNS].nscount > 20 or buf[DNS].arcount > 20:
                malformed = 1
#            elif buf[DNS].rcode > 5:
#                malformed = 1
            if dstport == 53:
                dir = 0
                upload = real_length
                use_port = srcport
            elif srcport == 53:
                dir = 1
                download = real_length
                use_port = dstport
            # try to catch DNSQR part
            try:
                domain = buf[DNSQR].qname
                i = len(domain)-2
                dot_num = 0
                # get top domain ,like qq.com, baidu.com
                while i >= 0:
                    if domain[i] == '.':
                        dot_num += 1
                        if dot_num > 1:
                            break
                    i -= 1
                topdomain = domain[i+1:-1]
                # judge the domain info.
                if topdomain in white_list:
                    upload = 0
                    subdomain_num[topdomain] = 0
                elif domain in ['activum.nu', 'version.bind', 'VERSION.BIND']:
                    if upload < 90:
                        upload = 0
                        subdomain_num[topdomain] = 0
                else:
                    if topdomain in topdomain_list:
                        if domain not in domain_list:
                            domain_list.append(domain)
                            subdomain_num[topdomain] += 1
                    else:
                        topdomain_list.append(topdomain)
                        domain_list.append(domain)
                        subdomain_num[topdomain] = 1
                        new_domain = 1
            except Exception, e:
                new_domain = 0
            subcnt = subdomain_num[topdomain]
            stream.packet_list.append((timer, use_port, upload, malformed, dir, buf, srcip, dstip, new_domain, subcnt))
        except Exception, e:
 #           try:
 #               data = buf[DNS]
 #           except Exception, e:
 #               print e.message
 #               print "packet ", cnt
 #               continue
            print e.message
            print "packet ", cnt
            stream.packet_list.append((timer, use_port, upload, 1, dir, buf, srcip, dstip, 0, 0))
            continue
    return stream


def total2multistream(packet_list):
    sorted_stream = []
    multistream_list = []
    sorted_stream = sorted(packet_list, key=lambda packets: packets[1])
    length = len(packet_list)
    j = 0
    for i in range(0, length-1):
        if sorted_stream[i][1] != sorted_stream[i+1][1]:
            multistream_list.append(sorted_stream[j:i+1])
            j = i + 1
    multistream_list.append(sorted_stream[j:length])
    return multistream_list


def obj2bit(stream, i):
    string = ''.join([str(x[i]) for x in stream])
    return string


def obj2list(stream, i):
    item = []
    for x in stream:
        item.append(x[5])
    return item


def swap(s1, s2):
    return s2, s1


def detect_dns(stream):
    for flow in stream.multistream_list:
        upspeed = float(0.0)
        downspeed = float(0.0)
        malformed_num = 0
        try:
            ip_1 = flow[0][6]
            ip_2 = flow[0][7]
        except Exception, e:
            print e.message
            continue
        if ip_1 < ip_2:
            ip_1, ip_2 = swap(ip_1, ip_2)
        name = ip_1 + "-" + ip_2 + ":" + str(flow[0][1])
        domain_num = 0
        subdomain_warn = bool(0)
        speed_domain = bool(0)
        for pkt in flow:
            if pkt[4] == 0:
                upspeed += pkt[2]
            else:
                downspeed += pkt[2]
            if pkt[3] == 1:
                malformed_num += 1
            if pkt[8] == 1:
                domain_num += 1
            if pkt[9] > warnsub:
                subdomain_warn = 1
            if pkt[9] > 5:
                speed_domain = 1
        time_use = flow[len(flow)-1][0]-flow[0][0] + 0.0001
        # print name + "  ", upspeed, "  ", downspeed, "  ", time_use
        if len(flow) > 1:
            # print "len ", len(flow)
            upspeed = upspeed/time_use
            downspeed = downspeed/time_use
        pkt_list = obj2list(flow, 5)
        danger = bool(0)
#        print upspeed, " ", len(flow), " ", domain_num
        print upspeed, " ", len(flow), " ", subdomain_warn
        if (upspeed > 200) and (len(flow) > 10) and (pkt[9] > 5):
            danger = 1
        if (upspeed > 300) and (len(flow) > 5) and (pkt[9] > 3):
            danger = 1
        if malformed_num > 3:
            danger = 2
        if subdomain_warn:
            danger = 3
        if danger == 1:
            print "dangerous - " + name
            fp.write("dangerous - " + name + "\n")
            name = "speed_" + name + ".pcap"
            wrpcap("warn_flow/" + name, pkt_list)
        elif danger == 2:
            print "dangerous - " + name
            fp.write("dangerous - " + name + "\n")
            name = "malformed_" + name + ".pcap"
            wrpcap("warn_flow/" + name, pkt_list)
        elif danger == 3:
            print "dangerous - " + name
            fp.write("dangerous - " + name + "\n")
            name = "subdomain_warn_" + name + ".pcap"
            wrpcap("warn_flow/" + name, pkt_list)

if __name__ == "__main__":
    stream = dns_stream()
    starttime = datetime.datetime.now()
    filelist = []
    multistream = []
    #path = "wrong_test/"
    #path = "/mnt/myusbmount/Trojan_Monitor/beijing/dns/speed/"
    filelist = os.listdir(path)
    for filename in filelist:
        print filename
        fp.write("\n\n")
        fp.write(filename + "\n")
        stream = stream2vector(path + filename)
        stream.multistream_list = total2multistream(stream.packet_list)
        detect_dns(stream)
    print "finish!"
