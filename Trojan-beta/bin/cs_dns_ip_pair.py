from scapy.all import *
import time
import datetime
import os
fp = open('result.txt', "wb")
warnsub = 30
DEBUG = True
white_list = ["qq.com", "baidu.com", "sina.com", "google.com", "4399.com", "youku.com", "souhu.com", "taobao.com", "sina.com",
              "dgso.com", "163.com", "hao123.com", "tudou.com", "pps.tv", "xunlei.com", "sogou.com", "56.com", "tmall.com", "ku6.com",
              "tmall.com", "ifeng.com", "360.cn", "so.com", "2345.com", "qiyi.com", "alipay.com", "renren.com", "sm.cn", "zol.com",
              "tianya.cn", "paipai.com", "microsoft.com", "pptv.com", "kugou.com", "joy.cn", "96pk.com", "10086.cn", "pomoho.com", "youdao.com",
              "58.com", "xinhuanet.com", "letv.com", "mop.com", "m18.com", "douban.com", "zhihu.com", "sdo.com", "alibaba.com",
              "funshion.com", "vancl.com", "126.com", "wushen.com", "6.cn", "soufun.com", "jiayuan.com", "china.com", "csdn.com",
              "bilibili.com", "kugou.com", "jd.com", "jingdong.com", "meituan.com", "dnion.com", "version.bind", "activum.nu", "VERSION.BIND"]

path = '/home/csober/Documents/Github/ggs-ddu/Trojan-beta/SplitedFlow/dns/'
warning_path = '/home/csober/Documents/Github/ggs-ddu/Trojan-beta/Warning/dns_warning/'
# path = '/home/csober/Documents/Github/ggs-ddu/GP/trojan_monitor/dns_monitor/wrong_test/'
print_exception = False


class dns_stream:
    def __init__(self):
        self.port = 0
        self.domain_num = 0
        self.time = 0
        self.name = ''
        self.upload = 0
        self.upload_num = 0
        self.download_num = 0
        self.download = 0
        self.packet_list = []
        self.malformed_num = 0
        self.transaction_num = 0
        self.multistream_list = []
        self.max_host_name_num = 0


def hight_output(color, msg):
    color_dit = {"RED": 31, "GREEN": 32, "YELLOW": 33, "BLUE": 34, "PURPLE": 35, "CYAN": 36, "GREY": 37, "WHITE": 38}
    color_id = color_dit[color]
    print '\033[1;%dm%s\033[1;0m' % (color_id, msg)


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
    subcnt = 0
    for buf in dpkt:
        cnt += 1
        srcip = buf[IP].src
        dstip = buf[IP].dst
        stream.name = min(srcip, dstip) + "-" + max(srcip, dstip)
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
        topdomain = ''
        # try to catch DNS part.
        try:
            tmp = buf[IP]
            tmp = buf[DNS]
        except Exception, e:
            if print_exception:
                print e.message
            continue
        transaction_id = buf[DNS].id
        if transaction_id not in transaction_id_list:
            transaction_id_list.append(transaction_id)
        try:
            if cor_length != real_length and buf[IP].len > 46:  # in case padding some bytes.
                if DEBUG:
                    print "cor_length!=real_length"
                stream.malformed_num += 1
                malformed = 1
            elif buf[DNS].qdcount > 2 or buf[DNS].ancount > 50 or buf[DNS].nscount > 20 or buf[DNS].arcount > 20:
                if DEBUG:
                    print "wrong count"
                stream.malformed_num += 1
                malformed = 1
#            elif buf[DNS].rcode > 5:
#                malformed = 1
            if dstport == 53:
                dir = 0
                upload = real_length
                stream.upload += upload
                stream.upload_num += 1
                use_port = srcport
            elif srcport == 53:
                dir = 1
                download = real_length
                stream.download += download
                stream.download += 1
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
                            stream.max_host_name_num = max(stream.max_host_name_num, subdomain_num[topdomain])
                    else:
                        stream.domain_num += 1
                        topdomain_list.append(topdomain)
                        domain_list.append(domain)
                        subdomain_num[topdomain] = 1
                        new_domain = 1
            except Exception, e:
                new_domain = 0
            subcnt = max(subcnt, subdomain_num[topdomain])
            stream.packet_list.append((timer, use_port, upload, malformed, dir, buf, srcip, dstip, new_domain, subcnt, len(transaction_id_list)))
        except Exception, e:
            if print_exception:
                print e.message
            mal = 1
            if len(buf) < 60:
                mal = 0
            stream.packet_list.append((timer, use_port, upload, mal, dir, buf, srcip, dstip, 0, 0, len(transaction_id_list)))
            continue
    try:
        stream.time = stream.packet_list[-1][1]-stream.time
    except Exception, e:
        if print_exception:
            print e.message
        stream.time = 0
    stream.transaction_num = len(transaction_id_list)

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
            if print_exception:
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
        time_use = flow[len(flow)-1][0]-flow[0][0] + 0.0001
        if len(flow) > 1:
            upspeed = upspeed/time_use
            downspeed = downspeed/time_use
        pkt_list = obj2list(flow, 5)
        danger = bool(0)


        if ((upspeed > 200) and (len(flow) > 200)):
            danger = 1
        if ((upspeed > 300) and (len(flow) > 100)):
            danger = 1
        if malformed_num > 50:
            danger = 2
        if subdomain_warn:
            danger = 3
        if danger == 1:
            hight_output("RED", "dns-dangerous - " + name)
            fp.write("dangerous - " + name + "\n")
            name = "speed_" + name + ".pcap"
            wrpcap(warning_path + name, pkt_list)
        elif danger == 2:
            hight_output("RED", "dns-dangerous - " + name)
            fp.write("dangerous - " + name + "\n")
            name = "malformed_" + name + ".pcap"
            wrpcap(warning_path + name, pkt_list)

    pkt_list = obj2list(stream.packet_list, 5)

    if (stream.transaction_num > 2*stream.domain_num) and stream.domain_num >0 and stream.upload/(stream.upload_num+1)>200:
	hight_output("RED", "dns-dangerous - " + stream.name)
        fp.write("dangerous - transaction_num" + stream.name + "\n")
        name = "dangerous_flow" + stream.name + ".pcap"
        wrpcap(warning_path + stream.name, pkt_list)
    elif stream.malformed_num > 10:
	hight_output("RED", "dns-dangerous - malformed " + stream.name)
        fp.write("dangerous - " + stream.name + "\n")
        name = "dangerous_flow" + stream.name + ".pcap"
        wrpcap(warning_path + stream.name, pkt_list)
    elif stream.max_host_name_num >40:
	hight_output("RED", "dns-dangerous - max_host_name_num" + stream.name)
        fp.write("dangerous - " + stream.name + "\n")
        name = "dangerous_flow" + stream.name + ".pcap"
        wrpcap(warning_path + stream.name, pkt_list)

if __name__ == "__main__":
    stream = dns_stream()
    starttime = datetime.datetime.now()
    filelist = []
    multistream = []
    #path = "wrong_test/"
    #path = "/mnt/myusbmount/Trojan_Monitor/beijing/dns/speed/"
    filelist = os.listdir(path)
    for filename in filelist:
        stream = stream2vector(path + filename)
        stream.multistream_list = total2multistream(stream.packet_list)
        detect_dns(stream)
    print ""
    print ""
