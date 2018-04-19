from scapy.all import *
import time
import shutil
import dpkt
import binascii
import struct, socket, sys, os, argparse, logging, md5


def delete_ssl_shakehand(dir):
    dpkt = rdpcap(dir)
    cnt = 0
    Handshake_num = 0
    Change_CiperSpec = 0
    Alert_num = 0
    Application_num = 0
    data_handshake = []
    data_application = []
    data_alert = []
    data_without_handshake = []
    for buf in dpkt:
        cnt = cnt + 1
        flagR = (buf[TCP].flags >> 2) & 1  # RST
        flagP = (buf[TCP].flags >> 3) & 1  # PSH
        flagS = (buf[TCP].flags >> 1) & 1  # SYN
        flagF = (buf[TCP].flags) & 1       # FIN

        if flagR | flagS | flagF:
            continue

        tcp_buf = str(buf[TCP])
        if len(tcp_buf) - 20 < 1:
            continue
        if tcp_buf[20] == '\x16':
            print "Handshake"
            data_handshake.append(buf)
            Handshake_num = Handshake_num + 1
            continue
        data_without_handshake.append(buf)
        if tcp_buf[20] == '\x17':
            print "Application"
            Application_num += 1
            data_application.append(buf)
            continue
        elif tcp_buf[20] == '\x15':
            print "Alert"
            Alert_num += 1
            data_alert.append(buf)
    filename = dir[0:dir.rfind('.')]
    if os.path.exists(filename):
        shutil.rmtree(filename)
    os.mkdir(filename)
    wrpcap(filename + "/application.pcap", data_application)
    wrpcap(filename + "/handshake.pcap", data_handshake)
    wrpcap(filename + "/alert.pcap", data_alert)


def save_application_data2(dir):
    dpkt = rdpcap(dir)
    cnt = 0
    Handshake_num = 0
    Change_CiperSpec = 0
    Alert_num = 0
    Application_num = 0
    data_handshake = []
    data_application = []
    data_alert = []
    data_without_handshake = []
    for buf in dpkt:
        cnt = cnt + 1
        flagR = (buf[TCP].flags >> 2) & 1  # RST
        flagP = (buf[TCP].flags >> 3) & 1  # PSH
        flagS = (buf[TCP].flags >> 1) & 1  # SYN
        flagF = (buf[TCP].flags) & 1       # FIN

        if flagR | flagS | flagF:
            continue
        try:
            ssl_buf = str(buf[ASN1_Packet])
        except Exception, e:
            print e.message
            continue
        print ssl_buf
        tcp_buf = str(buf[TCP])
        if len(tcp_buf) - 20 < 1:
            continue
        if tcp_buf[20] == '\x16':
            print "Handshake"
            data_handshake.append(buf)
            Handshake_num = Handshake_num + 1
            continue
        data_without_handshake.append(buf)
        if tcp_buf[20] == '\x17':
            print "Application"
            Application_num += 1
            data_application.append(buf)
            continue
        elif tcp_buf[20] == '\x15':
            print "Alert"
            Alert_num += 1
            data_alert.append(buf)
    filename = dir[0:dir.rfind('.')]
    if os.path.exists(filename):
        shutil.rmtree(filename)
    os.mkdir(filename)
    wrpcap(filename + "/application.pcap", data_application)
    wrpcap(filename + "/handshake.pcap", data_handshake)
    wrpcap(filename + "/alert.pcap", data_alert)


class ClientHello(object):
    def __init__(self, msgtype=int(1), msglen=int(0), version='', gmt_unix_time='', random_bytes='', \
                 sess_id_len=int(0), sess_id='', cipherslen=int(0), ciphers=[], complen=int(0), comps=[], extlen=int(0)):
        self.msgtype = msgtype
        self.msglen = msglen
        self.version = version
        self.gmt_unix_time = gmt_unix_time
        self.random_bytes = random_bytes
        self.sess_id_len = sess_id_len
        self.sess_id = sess_id
        self.cipherslen = cipherslen
        self.ciphers = ciphers
        self.complen = complen
        self.comps = comps
        self.extlen = extlen
        self.exts = []

    def print_item(self):
        print "_____ClientHelloDone_____"
        print 'msgtype ', (self.msgtype)
        print 'msglen ', (self.msglen)
        print 'version ', binascii.b2a_hex(self.version)
        print 'gmt_unix_time', binascii.b2a_hex(self.gmt_unix_time)
        print 'random_bytes ', binascii.b2a_hex(self.random_bytes)
        print 'sess_id_len ', self.sess_id_len
        print 'sess_id ', binascii.b2a_hex(self.sess_id)
        print 'cipherslen ', self.cipherslen
        print 'ciphers ', self.ciphers
        print 'complen', self.complen
        print 'comps', self.comps
        print 'extlen', self.extlen
    pass


class ServerHello(object):
    def __init__(self, msgtype=int(2), msglen=int(0), version='', gmt_unix_time='', random_bytes='', \
                 sess_id_len=int(0), sess_id='', ciphers='', comps='', extlen=int(0)):
        self.msgtype = msgtype
        self.msglen = msglen
        self.version = version
        self.gmt_unix_time = gmt_unix_time
        self.random_bytes = random_bytes
        self.sess_id_len = sess_id_len
        self.sess_id = sess_id
        self.ciphers = ciphers
        self.comps = comps
        self.extlen = extlen
        self.exts = []

    def print_item(self):
        print "_____ServerHello_____"
        print 'msgtype ', (self.msgtype)
        print 'msglen ', (self.msglen)
        print 'version ', binascii.b2a_hex(self.version)
        print 'gmt_unix_time', binascii.b2a_hex(self.gmt_unix_time)
        print 'random_bytes ', binascii.b2a_hex(self.random_bytes)
        print 'sess_id_len ', self.sess_id_len
        print 'sess_id ', binascii.b2a_hex(self.sess_id)
        print 'ciphers ', self.ciphers
        print 'comps', self.comps
        print 'extlen', self.extlen
    pass


class Certificate(object):
    def __init__(self, msgtype=int(1), msglen=int(0), certification_len=int(0), certification=[]):
        self.msgtype = 11
        self.msglen = msglen
        self.certification_len = certification_len
        self.certification = certification


    def print_item(self):
        print "_____Certificate_____"
        print 'msgtype ', (self.msgtype)
        print 'msglen ', (self.msglen)
        print 'certification_len ', (self.certification_len)
        print 'cerfification', self.certification  # binascii.b2a_hex(self.gmt_unix_time)
    pass


class ServerKeyExchange(object):
    def __init__(self, msgtype=int(1), msglen=int(0), curve_type='', named_curve='', pubkey_len=int(0), \
                 pubkey='', sig_hash_alg='', sig_hash_alg_sig='', sig_len=int(0), sig=''):
        self.msgtype = msgtype
        self.msglen = msglen
        self.curve_type = curve_type
        self.named_curve = named_curve
        self.pubkey_len = pubkey_len
        self.pubkey = pubkey
        self.sig_hash_alg = sig_hash_alg
        self.sig_hash_alg_sig = sig_hash_alg_sig
        self.sig_len = sig_len
        self.sig = sig

    def print_item(self):
        print "_____ServerKeyExchange_____"
        print 'msgtype ', (self.msgtype)
        print 'msglen ', (self.msglen)
        print 'curve_type ', binascii.b2a_hex(self.curve_type)
        print 'named_curve ', binascii.b2a_hex(self.named_curve)
        print 'pubkey_len ', (self.pubkey_len)
        print 'pubkey ', binascii.b2a_hex(self.pubkey)
        print 'sig_hash_alg ', binascii.b2a_hex(self.sig_hash_alg)
        print 'sig_hash_alg_sig ', binascii.b2a_hex(self.sig_hash_alg_sig)
        print 'sig_len ', self.sig_len
        print 'sig ', binascii.b2a_hex(self.sig)
    pass


class ServerHelloDone(object):
    def __init__(self, msgtype='', msglen=int(0), extlen=int(0)):
        self.msgtype = msgtype
        self.msglen = msglen
        self.extlen = extlen

    def print_item(self):
        print "_____ServerHelloDone_____"
        print 'msgtype ', (self.msgtype)
        print 'msglen ', (self.msglen)
        # print 'extlen ', (self.extlen)
    pass


class ClientKeyExchange(object):
    def __init__(self, msgtype='', msglen=int(0), pubkey_len=int(0), pubkey=''):
        self.msgtype = msgtype
        self.msglen = msglen
        self.pubkey_len = pubkey_len
        self.pubkey = pubkey

    def print_item(self):
        print "_____ClientKeyExchange_____"
        print 'msgtype ', (self.msgtype)
        print 'msglen ', self.msglen
        print 'pubkey_len ', self.pubkey_len
        print 'pubkey ', binascii.b2a_hex(self.pubkey)
    pass


def to_int(str):
    ans = 0
    length = len(str)
    for i in range(0, length-1):
        if str[i].isdigit():
            ans = ans*16 + ord(str[i])-ord('0')
        else:
            ans = ans*16 + ord(str[i])-ord('a')+10
    return ans


def extract_handshake_vector(dir):
    doneList = []
    ClientHello_list = []
    ServerHello_list = []
    Certificate_list = []
    ServerKeyExchange_list = []
    Certificate_list = []
    ServerHelloDone_list = []
    ClientKeyExchange_list = []
    print("Extract :%s" %(dir))
    tcp_piece = {}
    f = open(dir, 'rb')
    try:
        pcap = dpkt.pcap.Reader(f)
    except:
        print("Error reading cap: %s", dir)
        return
    count = 0
    try:
        for ts, buf in pcap:
            count += 1
            try:
                upperdata = dpkt.ethernet.Ethernet(buf).data
                while upperdata.__class__ not in [dpkt.ip.IP, str]:
                    upperdata = upperdata.data
                if upperdata.__class__ == dpkt.ip.IP:
                    ippack = upperdata
                    tcppack = ippack.data
                    ssldata = tcppack.data
                else:
                    continue
                if not ssldata:
                    continue
                srcip = socket.inet_ntoa(ippack.src)
                if srcip in doneList:
                    continue
                tuple4 = (srcip, socket.inet_ntoa(ippack.dst), tcppack.sport, tcppack.dport)
                seq = tcppack.seq
                if not tcp_piece.has_key(tuple4):
                    tcp_piece[tuple4] = {}
                tcp_piece[tuple4][seq] = ssldata
            except Exception, e:
                print e.message()
                pass
    except Exception, e:
        print e.message
    f.close()

    for t4, dic in tcp_piece.iteritems():
        srcip = t4[0]
        sport = t4[2]
        if srcip in doneList:
            continue
        seq = min(dic.keys())
        sslcombined = dic[seq]
        piecelen = len(sslcombined)
        while (dic.has_key(seq+piecelen)):
            seq += piecelen
            sslcombined += dic[seq]
            piecelen = len(dic[seq])
        totallen = len(sslcombined)
        curpos = 0
        while curpos < totallen:
            # print 'curpos is ', curpos
            if totallen-curpos < 12:
                break
            if sslcombined[curpos] != '\x16':
                curpos += struct.unpack('!H', sslcombined[curpos+3:curpos+5])[0]
                curpos += 5
                continue
            else:
                # pktlen = struct.unpack('!I', '\x00\x00'+sslcombined[curpos+3:curpos+5])[0]
                curpos += 5
                if sslcombined[curpos] == '\x01':    # Client Hello
                    curpkt = ClientHello()
                    curpkt.msgtype = struct.unpack('!H', '\x00'+sslcombined[curpos:curpos+1])[0]
                    curpos += 1
                    curpkt.msglen = struct.unpack('!I', '\x00'+sslcombined[curpos:curpos+3])[0]
                    curpos += 3
                    curpkt.version = (sslcombined[curpos:curpos+2])
                    curpos += 2
                    curpkt.gtm_unix_time = (sslcombined[curpos:curpos+4])
                    curpos += 4
                    curpkt.random_bytes = (sslcombined[curpos:curpos+28])
                    curpos += 28
                    curpkt.sess_id_len = struct.unpack('!H', '\x00'+sslcombined[curpos:curpos+1])[0]
                    curpos += 1
                    curpkt.sess_id = (sslcombined[curpos:curpos+curpkt.sess_id_len])
                    curpos += curpkt.sess_id_len
                    curpkt.cipherslen = struct.unpack('!I', '\x00\x00'+sslcombined[curpos:curpos+2])[0]
                    curpos += 2
                    for i in range(0, curpkt.cipherslen/2):
                        # print "i is ", i
                        curpkt.ciphers.append(binascii.b2a_hex(sslcombined[curpos:curpos+2]))
                        curpos += 2

                    curpkt.complen = struct.unpack('!I', '\x00\x00\x00'+sslcombined[curpos:curpos+1])[0]
                    curpos += 1
                    for i in range(0, curpkt.complen):
                        curpkt.comps.append(binascii.b2a_hex(sslcombined[curpos:curpos+1]))
                        i += 1
                        curpos += 1
                    curpkt.extlen = struct.unpack('!I', '\x00\x00'+sslcombined[curpos:curpos+2])[0]
                    curpos += 2
                    curpos += curpkt.extlen
                    ClientHello_list.append(curpkt)
                    curpkt.print_item()
                elif sslcombined[curpos] == '\x02':  # Server Hello
                    curpkt = ServerHello()
                    curpkt.msgtype = struct.unpack('!H', '\x00' + sslcombined[curpos:curpos + 1])[0]
                    curpos += 1
                    curpkt.msglen = struct.unpack('!I', '\x00' + sslcombined[curpos:curpos + 3])[0]
                    curpos += 3
                    curpkt.version = sslcombined[curpos:curpos + 2]
                    curpos += 2
                    curpkt.gtm_unix_time = (sslcombined[curpos:curpos + 4])
                    curpos += 4
                    curpkt.random_bytes = (sslcombined[curpos:curpos + 28])
                    curpos += 28
                    curpkt.sess_id_len = struct.unpack('!H', '\x00' + sslcombined[curpos:curpos + 1])[0]
                    curpos += 1
                    curpkt.sess_id = sslcombined[curpos:curpos + curpkt.sess_id_len]
                    curpos += curpkt.sess_id_len
                    curpkt.ciphers = (sslcombined[curpos:curpos + 2])
                    curpos += 2
                    curpkt.comps = (sslcombined[curpos])
                    curpos += 1
                    curpkt.extlen = struct.unpack('!I', '\x00\x00' + sslcombined[curpos:curpos + 2])[0]
                    curpos += curpkt.extlen
                    curpos += 2
                    ServerHello_list.append(curpkt)
                    curpkt.print_item()
                elif sslcombined[curpos] == '\x0b':  # Certificate
                     curpkt = Certificate()
                     curpkt.msgtype = struct.unpack('!H', '\x00'+sslcombined[curpos:curpos+1])[0]
                     curpos += 1
                     curpkt.msglen = struct.unpack('!I', '\x00'+sslcombined[curpos:curpos+3])[0]
                     curpos += 3
                     curpkt.certification_len = struct.unpack('!I', '\x00'+sslcombined[curpos:curpos+3])[0]
                     curpos += 3
                     pos = 0
                     certification = []
                     while pos < curpkt.certification_len:
                         cerlen = struct.unpack('!I', '\x00'+sslcombined[curpos:curpos+3])[0]
                         curpos += 3
                         certification.append(binascii.b2a_hex(sslcombined[curpos:curpos+cerlen]))
                         curpos += cerlen
                         pos += 3 + cerlen
                     curpkt.certification = certification
                     Certificate_list.append(curpkt)
                     curpkt.print_item()
                elif sslcombined[curpos] == '\x0c':  # Server Key Exchange
                     curpkt = ServerKeyExchange()
                     curpkt.msgtype = struct.unpack('!H', '\x00'+sslcombined[curpos:curpos+1])[0]
                     curpos += 1
                     curpkt.msglen = struct.unpack('!I', '\x00'+sslcombined[curpos:curpos+3])[0]
                     curpos += 3
                     curpkt.curve_type = (sslcombined[curpos:curpos+1])
                     curpos += 1
                     curpkt.named_curve = (sslcombined[curpos:curpos+2])
                     curpos += 2
                     curpkt.pubkey_len = struct.unpack('!H', '\x00'+sslcombined[curpos:curpos+1])[0]
                     curpos += 1
                     curpkt.pubkey = (sslcombined[curpos:curpos+curpkt.pubkey_len])
                     curpos += curpkt.pubkey_len
                     curpkt.sig_hash_alg = (sslcombined[curpos:curpos+1])
                     curpos += 1
                     curpkt.sig_hash_alg_sig = (sslcombined[curpos:curpos+1])
                     curpos += 1
                     curpkt.sig_len = struct.unpack('!I', '\x00\x00'+sslcombined[curpos:curpos+2])[0]
                     curpos += 2
                     curpkt.sig = (sslcombined[curpos:curpos+curpkt.sig_len])
                     curpos += curpkt.sig_len
                     ServerKeyExchange_list.append(curpkt)
                     curpkt.print_item()
                elif sslcombined[curpos] == '\x0e':  # Server Hello Done
                     curpkt = ServerHelloDone()
                     curpkt.msgtype = struct.unpack('!H', '\x00'+sslcombined[curpos:curpos+1])[0]
                     curpos += 1
                     curpkt.msglen = struct.unpack('!I', '\x00'+sslcombined[curpos:curpos+3])[0]
                     curpos += 3
                     curpos += curpkt.msglen
                     ServerHelloDone_list.append(curpkt)
                     curpkt.print_item()
                elif sslcombined[curpos] == '\x10':  # Client Key Exchange
                     curpkt = ClientKeyExchange()
                     curpkt.msgtype = struct.unpack('!H', '\x00'+sslcombined[curpos:curpos+1])[0]
                     curpos += 1
                     curpkt.msglen = struct.unpack('!I', '\x00'+sslcombined[curpos:curpos+3])[0]
                     curpos += 3
                     curpkt.pubkey_len = struct.unpack('!H', '\x00'+sslcombined[curpos:curpos+1])[0]
                     curpos += 1
                     curpkt.pubkey = (sslcombined[curpos:curpos+curpkt.pubkey_len])
                     curpos += curpkt.pubkey_len
                     ClientKeyExchange_list.append(curpkt)
                     curpkt.print_item()
                else:                                # Encrypted Handshake Message
                     print '_____EncryptedHandshakeMessage_____'
    print("%d,%d,%d,%d,%d,%d,%d,%d,%s,%s,%d,%d,%s,%s,%d,%s,%s,%d,%d,%d,%d" %(ClientHello_list[0].msglen, int(binascii.b2a_hex(ClientHello_list[0].version)), ClientHello_list[0].sess_id_len, \
    ClientHello_list[0].cipherslen, ClientHello_list[0].complen, ClientHello_list[0].extlen, \
    ServerHello_list[0].msglen, ServerHello_list[0].sess_id_len, binascii.b2a_hex(ServerHello_list[0].ciphers), \
    binascii.b2a_hex(ServerHello_list[0].comps), ServerHello_list[0].extlen, \
    Certificate_list[0].msglen, len(Certificate_list[0].certification),\
    ServerKeyExchange_list[0].msglen, binascii.b2a_hex(ServerKeyExchange_list[0].curve_type), binascii.b2a_hex(ServerKeyExchange_list[
        0].named_curve), ServerKeyExchange_list[0].pubkey_len, \
    binascii.b2a_hex(ServerKeyExchange_list[0].sig_hash_alg), binascii.b2a_hex(ServerKeyExchange_list[0].sig_hash_alg_sig), \
    ServerKeyExchange_list[0].sig_len, \
    ServerHelloDone_list[0].msglen, \
    ClientKeyExchange_list[0].msglen, ClientKeyExchange_list[0].pubkey_len))

    #ClientHello_list[0].msglen, ClientHello_list[0].version, ClientHello_list[0].sess_id_len, \
    #ClientHello_list[0].cipherslen, ClientHello_list[0].complen, ClientHello_list[0].extlen, \
    #ServerHello_list[0].msglen, ServerHello_list[0].sess_id_len, ServerHelloDone_list[0].ciphers, \
    #ServerHello_list[0].comps, ServerHello_list[0].extlen, \
    #ServerKeyExchange_list[0].msglen, ServerKeyExchange_list[0].curve_type, ServerKeyExchange_list[
    #    0].named_curve, ServerKeyExchange_list[0].pubkey_len, \
    #ServerKeyExchange_list[0].sig_hash_alg, ServerKeyExchange_list[0].sig_hash_alg_sig, \
    #ServerKeyExchange_list[0].sig_len, \
    #ServerHelloDone_list[0].msglen, \
    #ClientKeyExchange_list[0].msglen, ClientKeyExchange_list[0].pubkey_len




if __name__ == "__main__":
    extract_handshake_vector("/home/csober/Documents/GP/flow_data/xunlei_pcap.pcap")

    # save_application_data2("/home/csober/Documents/Github/ggs-ddu/GP/trojan_monitor/tcp_monitor/tcp_flow/xunlei.pcapng")

