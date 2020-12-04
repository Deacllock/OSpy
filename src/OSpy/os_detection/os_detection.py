from scapy.all import *
import threading
from datetime import datetime
from datetime import timedelta
from scapy.arch import get_if_list

SEQ_START = 22000
ACK_START = 44000
SPORT_START = 63000

conf.L3socket=L3RawSocket

responses = []

def send_probe(i, dst, dport, window, options):
    seq = SEQ_START + 10 * i
    ack = ACK_START + 10 * i
    sport = SPORT_START + i

    syn = IP(dst=dst)/TCP(sport=sport, dport=dport, flags=0x02, seq=seq,
        ack=ack, window=window, options=options)

    send(syn)
    

def send_probes(dst, dport):
    timestamp = ('Timestamp', (0xFFFFFFFF, 0))
    sack = ('SAckOK', '')
    eol = ('EOL', '')
    nop = ('NOP', '')

    t1 = (1, [('WScale', 10), nop, ('MSS', 1460), timestamp, sack])
    t2 = (63, [('MSS', 1400), ('WScale', 0), sack, timestamp, eol])
    t3 = (4,[timestamp, nop, nop, ('WScale', 5), nop, ('MSS', 640)])
    t4 = (4, [sack, timestamp, ('WScale', 10), eol])
    t5 = (16, [('MSS', 536), sack, timestamp, ('WScale', 10), eol])
    t6 = (512, [('MSS', 265), sack, timestamp])
    
    tcp_probes = [t1, t2, t3, t4, t5, t6]
    l_probes = len(tcp_probes)
    t0 = time.time()
    i = 0
    
    while (i < l_probes):
        if (time.time() - t0 >= 0.1 * i):
            send_probe(i, dst, dport, *tcp_probes[i])
            i += 1

def get_packet(packet):
    if not packet in responses:
        responses.append(packet)

def start_sniff(dst):
    filter = 'host %s and (dst port 63000 or dst port 63001 or dst port 63002 or dst port 63003 or dst port 63004 or dst port 63005)' %dst
    t = AsyncSniffer(iface=get_if_list(), filter=filter, prn=get_packet)#prn=lambda x: x.summary())
    t.start()
    time.sleep(2)

def end_sniff(sniffer):
    sniffer.stop()

sniffer = start_sniff('127.0.0.1')#['enp0s3', 'lo'])
send_probes('127.0.0.1', 80)
for i in responses:
    i.show()
#end_sniff(sniffer)

