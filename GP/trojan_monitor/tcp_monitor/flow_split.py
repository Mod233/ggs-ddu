from scapy.all import *

udp_flow_list = {}
ip_flow_list = {}




class udpflow:
    def __init__(self):
        self.num = int(0)
        self.name = ""
        self.list = []


class ipflow:
    def __init__(self):
        self.num = int(0)
        self.name = ""
        self.list = []


def swap(a, b):
    return b, a


def ipv4_port(dir):
    dpkt = rdpcap(dir)  # sniff(offline=dir, count=0)
    # print "rdpcap"
    cnt = 0
    for buf in dpkt:
        cnt += 1
        try:
            if buf[Ether].type != 0x800:
                continue
        except Exception, e:
            print cnt
            print e.message
            continue
        try:
            if buf[IP].proto != 6:
                continue
        except Exception, e:
            print cnt
            print e.message
            continue
        dstport = 0
        srcport = 0
        try:
            dstport = buf[TCP].dport
            srcport = buf[TCP].sport
        except Exception, e:
            print cnt
            print e.message
            continue

        # judge the direction
        ip_server = buf[IP].src + ":" + str(srcport)
        ip_client = buf[IP].dst + ":" + str(dstport)

        name = ip_server + "-" + ip_client

        # print name
        if name in ip_flow_list:
            a = ip_flow_list[name]
            a.num = a.num + 1
            a.list.append(buf)
            ip_flow_list[name] = a
        else:
            newflow = ipflow()
            newflow.name = name
            newflow.num = 1
            newflow.list.append(buf)
            ip_flow_list[name] = newflow

    for item in ip_flow_list:
        print ip_flow_list[item].name
        name = "ip_flow/" + ip_flow_list[item].name + '.pcap'
        wrpcap(name, ip_flow_list[item].list)
    print "finish splitting dns_flow "


def ipv4(dir):
    dpkt = rdpcap(dir)#sniff(offline=dir, count=0)
    for buf in dpkt:
        ip_1 = buf[IP].src
        ip_2 = buf[IP].dst
        if ip_1 < ip_2:
            ip_1, ip_2 = swap(ip_1, ip_2)
        name = ip_1 + "-" + ip_2

        if name in ip_flow_list:
            item = ip_flow_list[name]
            item.num += 1
            item.list.append(buf)
            ip_flow_list[name] = item
        else:
            new_ip_flow = ipflow()
            new_ip_flow.list.append(buf)
            new_ip_flow.name = name
            new_ip_flow.num = 1
            ip_flow_list[name] = new_ip_flow
    for item in ip_flow_list:
        file_name = "ip_flow/" + item + ".pcap"
        print file_name
        wrpcap(file_name, ip_flow_list[item].list)
    print "finish splitting ip_flow "


if __name__ == '__main__':
    ipv4_port("/mnt/myusbmount/DNS_MONITOR/packet/packets01/pure_dns.pcap")
    #ipv4_dns("/mnt/myusbmount/Trojan_Monitor/beijing/dns/4000300027.pcap.cap")
    #ipv4("/mnt/myusbmount/DNS_MONITOR/packet/beijing_packet/beijing_packet/dns/4000300027.pcap.cap")