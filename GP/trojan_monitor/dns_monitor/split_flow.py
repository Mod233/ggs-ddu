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


def ipv4_dns(dir):
    #dpkt = rdpcap(dir)  # sniff(offline=dir, count=0)
    dpkt = sniff(offline=dir, count=0)
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
            if buf[IP].proto != 17:
                continue
        except Exception, e:
            print cnt
            print e.message
            continue
        dstport = 0
        srcport = 0
        try:
            dstport = buf[UDP].dport
            srcport = buf[UDP].sport
        except Exception, e:
            print cnt
            print e.message
            continue

        if (dstport != 53) and (srcport != 53):
            continue
        ip_1 = buf[IP].src
        ip_2 = buf[IP].dst
        if ip_1 < ip_2:
            ip_1, ip_2 = swap(ip_1, ip_2)
        name = ip_1 + "-" + ip_2
        port_src = buf[UDP].sport
        port_dst = buf[UDP].dport
        if port_dst == 53:
            name = name + ":" + str(port_src)
        elif port_src == 53:
            name = name + ":" + str(port_dst)
        # print name
        if name in udp_flow_list:
            a = udp_flow_list[name]
            a.num = a.num + 1
            a.list.append(buf)
            udp_flow_list[name] = a
        else:
            newflow = udpflow()
            newflow.name = name
            newflow.num = 1
            newflow.list.append(buf)
            udp_flow_list[name] = newflow

    for item in udp_flow_list:
        print udp_flow_list[item].name
        name = "udp_flow/" + udp_flow_list[item].name + '.pcap'
        wrpcap(name, udp_flow_list[item].list)
    print "finish splitting dns_flow "


def ipv4(dir):
    # dpkt = rdpcap(dir)#sniff(offline=dir, count=0)
    dpkt = sniff(count=0, offline=dir)
    for buf in dpkt:
        try:
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
        except Exception, e:
            print e.message
            continue
    print "finish splitting ip_flow "


if __name__ == '__main__':
    #ip_port("/mnt/myusbmount/DNS_MONITOR/packet/packets01/pure_dns.pcap")
    ipv4_dns("/root/Downloads/colasoft_packets0118_2(1).cap")
    #ipv4("/mnt/myusbmount/DNS_MONITOR/packet/beijing_packet/beijing_packet/dns/4000300027.pcap.cap")
