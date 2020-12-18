import time
from scapy.all import *


def probe(dst, window, options):

    #variables
    #generate random src?
    src = ""

    #set src and dst
    syn = IP(dst=dst)/TCP(flags=0x02, window=window, options=options)
    syn.show()
    send(syn)

def send_probes(dst):
    #100ms apart
    timestamp = ('Timestamp', (0xFFFFFFFF, 0))
    sack = ('SAckOK', '')
    eol = ('EOL', '')
    nop = ('NOP', '')

    tcp1 = probe(dst, 1, [('WScale', 10), nop, ('MSS', 1460), timestamp, sack])
    tcp2 = probe(dst, 63, [('MSS', 1400), ('WScale', 0), sack, timestamp, eol])
    tcp3 = probe(dst, 4, [timestamp, nop, nop, ('WScale', 5), nop, ('MSS', 640)])
    tcp4 = probe(dst, 4, [sack, timestamp, ('WScale', 10), eol])
    tcp5 = probe(dst, 16, [('MSS', 536), sack, timestamp, ('WScale', 10), eol])
    tcp6 = probe(dst, 512, [('MSS', 265), sack, timestamp])
