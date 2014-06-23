#!/usr/bin/env python
import socket
import os
import sys
import time
import atexit
import random
import string
from collections import defaultdict
from progressbar import ProgressBar
from datetime import datetime
from scapy.all import *

SYS_PATH = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if SYS_PATH not in sys.path:
    sys.path.append(SYS_PATH)
from qiang import networking

# Probe using the fact GFW will configure some router with QoS of certain port

ERROR_NO_DATA = 11
TH_SYN = 0x02        # synchronize sequence numbers
TH_ACK = 0x10        # acknowledgment number set
ROOT_USER_ID = 0
'''
Some parameters. Adjust them if needed.
'''
MAX_PACKETS = 700   # The number of packets to send during each test
MAX_TESTS = 4       # Repeat the test for each port %MAX_TESTS% times
NO_QOS_THRESHOLD = 4    # Minimum requirement for a port to be view as no QoS

def main(dst, dst_port, sport, bandwidth="%d" % (1024 * 1024), ttl=20):
    iface, src, _ = networking.get_route(dst)
    dst_port = int(dst_port)
    bandwidth = bandwidth.lower()
    if bandwidth.endswith("m"): bandwidth = float(bandwidth[ : -1]) * 1024 * 1024
    elif bandwidth.endswith("k"): bandwidth = float(bandwidth[ : -1]) * 1024
    elif bandwidth.endswith("b"): bandwidth = float(bandwidth[ : -1])
    else: bandwidth = float(bandwidth)

    if ROOT_USER_ID == os.geteuid():
        sniffer = networking.create_sniffer(iface, src, dst)
        probe = UdpPacketDropProbe(src, int(sport), dst, dst_port, int(ttl), sniffer, bandwidth=bandwidth)
        sniffer.start_sniffing()
        probe.poke()
        time.sleep(2)
        sniffer.stop_sniffing()
        report = probe.peek()
    else:
        probe = UdpPacketDropProbe(src, int(sport), dst, dst_port, int(ttl), sniffer=None, bandwidth=bandwidth)
        probe.poke()
        time.sleep(2)
        report = probe.peek()
    packets = report.pop('PACKETS')
    # print(report)

    router_hit = defaultdict(int)
    for pkt_id, router_ip in report["ROUTER_IP"].items():
        router_hit[router_ip] += 1
    return router_hit
    # for mark, packet in packets:
    #     formatted_packet = packet.sprintf('%.time% %IP.src% -> %IP.dst% %TCP.flags%')
    #     print('[%s] %s' % (mark, formatted_packet))


class UdpPacketDropProbe(object):
    def __init__(self, src, sport, dst, dport, ttl, sniffer, one_packet_only=False, bandwidth=1024000):
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport
        self.ttl = ttl
        self.sniffer = sniffer
        self.one_packet_only = one_packet_only
        self.report = {
            'ROUTER_IP': {},
            'RESPONDED?': None,
            'PACKETS': []
        }
        self.udp_socket = None
        self.bandwidth = bandwidth

    def poke(self):
        # question = DNS(rd=1, qd=DNSQR(qname='www.gov.cn'))

        if self.sniffer:
            # We send 5000 packets
            packets = []
            print "Building packets..."
            progress = ProgressBar()
            for i in progress(range(0, MAX_PACKETS)):
                packet = IP(src=self.src, dst=self.dst, id=self.ttl * 5 + i, ttl=self.ttl) / UDP(
                    sport=self.sport, dport=self.dport) / (''.join([random.choice(string.printable) for _ in range(1470)]))
                packets.append(packet)
            print "Send them!"
            # A simple throttler
            time_start = datetime.now()
            
            def millisec_passed():
                n = datetime.now() - time_start
                return (n.seconds * 1000 + n.microseconds / 1000.0)

            bytes_sent = 0
            i = 0
            progress = ProgressBar(maxval=MAX_PACKETS).start()
            while i < MAX_PACKETS:
                if bytes_sent / (millisec_passed() / 1000.0) > self.bandwidth:
                    continue
                packet = packets[i]
                networking.send(packet)
                self.report['PACKETS'].append(('PACKET_%d' % i, packet))
                i += 1
                bytes_sent += len(packet)
                progress.update(i)
            progress.finish()
        else:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            atexit.register(self.udp_socket.close)
            self.udp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)
            self.udp_socket.settimeout(0)
            self.udp_socket.bind((self.src, self.sport)) # if sport change the route going through might change
            self.udp_socket.sendto(str(question), (self.dst, self.dport))

    def close(self):
        if self.udp_socket:
            self.udp_socket.close()

    def peek(self):
        if not self.sniffer:
            try:
                self.udp_socket.recv(1024)
                self.report['RESPONDED?'] = True
            except socket.error as e:
                if ERROR_NO_DATA == e[0]:
                    pass
                else:
                    raise
            return self.report
        for packet in self.sniffer.packets:
            if UDP in packet:
                self.analyze_udp_packet(packet)
            elif IPerror in packet and UDPerror in packet:
                self.analyze_udp_error_packet(packet)
        return self.report

    def analyze_udp_packet(self, packet):
        if self.dport != packet[UDP].sport:
            return
        if self.sport != packet[UDP].dport:
            return
        self.report['RESPONDED?'] = True
        self.report['PACKETS'].append(('UNKNOWN', packet))

    def analyze_udp_error_packet(self, packet):
        if self.sport != packet[UDPerror].sport:
            return
        if self.dport != packet[UDPerror].dport:
            return
        self.report['RESPONDED?'] = True
        packet_id = packet[IPerror].id - self.ttl * 5

        if packet_id < MAX_PACKETS:
            self.record_router_ip(packet.src, packet_id, packet)
        else:
            self.report['PACKETS'].append(('UNKNOWN', packet))

    def record_router_ip(self, router_ip, packet_index, packet):
        if packet_index in self.report['ROUTER_IP']:
            self.report['PACKETS'].append(('ADDITIONAL_ROUTER_IP_FOUND_BY_PACKET_%s' % packet_index, packet))
        else:
            self.report['PACKETS'].append(('ROUTER_IP_FOUND_BY_PACKET_%s' % packet_index, packet))
            self.report['ROUTER_IP'][packet_index] = router_ip

if '__main__' == __name__:
    if 6 > len(sys.argv):
        print('[Usage] ./udp_packet_drop_probe.py destination_ip dst_port src_port ttl bandwidth [log, skip]')
        sys.exit(3)
    else:
        dst_ip = sys.argv[1]
        dst_port = int(sys.argv[2])
        src_port = int(sys.argv[3])
        bandwidth = sys.argv[5]
        log = sys.argv[6] if len(sys.argv) > 6 else None
        skip = int(sys.argv[7]) if len(sys.argv) > 7 else 0
        ttl = sys.argv[4]
        if dst_port == 0 and src_port == 0:
            print "Error: Both dst_port and src_port is undefined."
            sys.exit(1)
        print "You may want to adjust some parameters according to your network conditons."
        port = 0
        r = range(skip, 65535)
        if dst_port != 0 and src_port != 0:
            r = range(1)
        for port in r:
            no_qos_count = 0
            for test_count in range(0, MAX_TESTS):
                if dst_port == 0:
                    print "Testing dst_port %d..." % port
                    router_hits = main(dst_ip, port, src_port, bandwidth=bandwidth, ttl=ttl)
                elif src_port == 0:
                    print "Testing src_port %d..." % port
                    router_hits = main(dst_ip, dst_port, port, bandwidth=bandwidth, ttl=ttl)
                else:
                    print "Testing src_port %d and dst_port %d..." % (src_port, dst_port)
                    router_hits = main(dst_ip, dst_port, src_port, bandwidth=bandwidth, ttl=ttl)

                total_hit = sum(router_hits.values())
                ratio = total_hit * 1.0 / MAX_PACKETS
                if ratio < 0.99 and ratio > 0.65:
                    print "Test %d, QoS found, packet loss = %.02f%%." % (test_count, (1.0 - ratio) * 100)
                    if no_qos_count + (MAX_TESTS - test_count) - 1 < NO_QOS_THRESHOLD:
                        break
                elif ratio < 0.65:
                    print "[-]The target router doesn't give enough responses."
                    if log is not None:
                        f = open(log, "a")
                        f.write("[?]Port %d\n" % port)
                        f.close()
                    break
                else:
                    print "Test %d, packet loss = %02f%%, no QoS is found." % (test_count, (1.0 - ratio) * 100)
                    no_qos_count += 1
                    if no_qos_count == NO_QOS_THRESHOLD:
                        print "QoS may not be enabled."
                        if log is not None:
                            f = open(log, "a")
                            if dst_port == 0:
                                f.write("[+]Dst port %d, packet loss = %.02f%%\n" % (port, (1.0 - ratio) * 100))
                            elif src_port == 0:
                                f.write("[+]Src port %d, packet loss = %.02f%%\n" % (port, (1.0 - ratio) * 100))
                            else:
                                f.write("[+]Dst port %d, src port %d, packet loss = %.02f%%\n" % (dst_port, src_port, (1.0 - ratio) * 100))
                            f.close()
            if dst_ip in router_hits:
                # We reached the target!
                print "We reached the target server."
                break
