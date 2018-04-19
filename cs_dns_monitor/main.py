from scapy.all import *
dnsflow = {}
url = {}
t = 1
subdoo = {}

max_up_payload = 40
max_down_payload = 200
max_domain_length = 20
max_interact_pkt = 4
max_domain_num = 20
max_last_time = 5



while t:
    Mod = 50
    print "t is ", t
    t = t - 1

    #dpkt = sniff(iface="enp0s31f6", count=30, filter='port 53 and ip ')# and length<200 ')
    dpkt = sniff(offline="/mnt/myusbmount/DNS_MONITOR/packet/packets01/pure_dns.pcap", count=0, filter='ip4 and udp port 53')  # and length<200 ')


    #wrpcap("demo.pcap", dpkt)
    s = 1
    for buf in dpkt:
        #print s
        strr = str(buf)
        ty = strr[12:14]
        if ty == "\x86\xdd":
            continue
        s = s + 1
        pkt_time = buf.time
        ip_src = buf[IP].src
        ip_dst = buf[IP].dst
      #  print ip_dst, "  ", ip_src
        port_src = buf[UDP].sport
        port_dst = buf[UDP].dport
        domain = str()
        direct = bool(1)  # 0:up 1:down
        buf2 = str(buf)        #Jul 3
        bpktup = int(0)
        spktdw = int(0)
        domain_num = int(0)
        subdomain_num = int(0)

        if port_dst == 53:
            direct = 0
            # can change
            dns_payload = len(buf)-42-16
            domain = buf2[54:-4]
# after the test u should add it
#            p = len(domain[0:0 + 1])
#            if p == 0:
#                i = 0
#            else:
#                i = ord(domain[0:1])
#            j = 0
#            k = 0
#            pos = 0
            # print "pos is "
            # print pos
            # print dns_payload

#            while pos != dns_payload-1:
#                k = j
#                j = pos
#                pos += i+1
#                p = len(domain[pos:pos+1])
#                if p == 0:
#                    break
#                i = ord(domain[pos:pos+1])
#            if k == 0:
#                subdomain = domain[0:0+dns_payload]
#            else:
#                subdomain = domain[k+1:k+1+dns_payload]
#
            if dns_payload > 50:
                bpktup = 1

            name = ip_src + '-' + ip_dst + '-' + str(port_src)
        else:
            dns_data = str(buf2[42:])
            info = dns_data.find('\x00', 12)
            subdomain = dns_data[12:info]
            dns_payload = len(dns_data)-info-4
            if dns_payload < 50:
                spktdw = 1
            name = ip_dst + '-' + ip_src + '-' + str(port_dst)

        if name in dnsflow:
            item = dnsflow[name]
            if domain not in item[12]:
                dnsflow[name][12].append(domain)
                dnsflow[name][4] += 1

            dnsflow[name][0] += bpktup
            dnsflow[name][1] += spktdw
            if direct:
                dnsflow[name][3] += dns_payload
            else:
                dnsflow[name][2] += dns_payload
            dnsflow[name][11] += str(direct)
            dnsflow[name][6] += 1
            dnsflow[name][8] += pkt_time - dnsflow[name][7]
            #dnsflow[name][7] = pkt_time
            dnsflow[name][9].append(buf)

            item = dnsflow[name]
            last_time = pkt_time-item[7]
            last_time = last_time + 1
            # change!
#            if last_time > max_last_time: #begin time segment
#                print "last_time"
#                dnsflow[name][10] = 1
            if (item[6]/last_time) > max_interact_pkt:         #when the num of pkt beyond 10:
                if item[6] > 18:
                    print "pknum and last_time is", item[6], "  ", last_time
                    print "interact_pkt"
                    dnsflow[name][10] = 1
            if item[5] > max_domain_num:
   #             print "max_domain_num"
                dnsflow[name][10] = 1
            if item[4] > 20:
   #             print "max_domain_num"
                dnsflow[name][10] = 1
          #  if last_time > max_last_time:
          #      print "max_last_time"
          #      dnsflow[name][10] = 1
            if (item[2]/last_time) > max_up_payload:
                if item[6] > 15:
#                    print "max_up_payload ", item[2], "  ", last_time
                    dnsflow[name][10] = 1
            if (item[3]/last_time) > max_down_payload:
                if item[6] > 15:
                    dnsflow[name][10] = 1
#                    print "max_down_payload"
#                    print "max_down_payload ", item[3], "  ", last_time

            #if dnsflow[name][10] == 1:
                #print name + " is dangerous"
        else:
            Mod = Mod + 50
            item = [bpktup, spktdw, 0, 0, 1, 1, 1, pkt_time, 0, [], bool(0), [], []]
            item[9].append(buf)
            item[12].append(domain)
            if direct == 0:
                item[2] = dns_payload
                item[11] += str(0)
            else:
                item[3] = dns_payload
                item[11] += str(1)
            dnsflow[name] = item
        #Mod = 50 * dnsflow.
        if s % 50 == 0:
            for item in dnsflow.keys():
                filename = item + ".pcap"
                if dnsflow[item][10] == 1:
                    print "dangerous " + filename
                    print "the details of the dangerous stream"
                    print ("bpktup:%5d spktdw:%5d payloadup:%5d payloaddw:%5d domainnum:%5d pktnum:%5d"%(dnsflow[name][0], dnsflow[name][1], dnsflow[name][2], dnsflow[name][3], dnsflow[name][4], dnsflow[name][6]))
                    print ("subdmn:%5d pktnum:%5d " %(dnsflow[name][5], dnsflow[name][6]))
                    wrpcap("dangerous "+filename, dnsflow[item][9])
                else:
                    print "safe " + filename
                    wrpcap("safe " + filename, dnsflow[item][9])
        # f = open("/root/PycharmProjects/cs_monitor/"+filename, "ab")
        # f.write(dnsflow[item][9])
        # f.close()
            dnsflow.clear()
            for item in dnsflow.keys():
                del dnsflow[item]
        # print dnsflow[item][0]
        # print dnsflow[item][1]
        # print dnsflow[item][2]
        # print dnsflow[item][3]
        # print dnsflow[item][4]
        # print dnsflow[item][5]
        # print dnsflow[item][6]
        # print dnsflow[item][7]
        # print dnsflow[item][8]
        # print dnsflow[item][9]
        # print dnsflow[item][10]
        # print dnsflow[item][11]
        # for str in dnsflow[item][12]:
        #      print str
print "END"

#
#
# print dpkt
# print len(dpkt)
# print dpkt[1].type
# print dpkt[1].dst
# print dpkt[1].src
# print "the pay load is "
# print dpkt[2][DNS].id
# print dpkt[2][DNS].qr
# print dpkt[2][DNS].qdcount
# print len(dpkt[2][DNS])
# print "aaaaaa"
# print repr(dpkt[2][DNS])
# print dpkt[2][DNS].qd
# s = str((dpkt[2][DNS].qd))
# print ord(s[0:1])
# wrpcap("demo.pcap", dpkt)
