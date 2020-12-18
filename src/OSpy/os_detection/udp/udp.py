from scapy.all import *
import threading
from datetime import datetime
from datetime import timedelta

from fingerprints import Result, FingerPrint
from sequence_generation.seq import get_seq
from sequence_generation.t1 import get_t1

SEQ_START = 22000
ACK_START = 44000
SPORT_START = 63000

# Sends an UDP probe used to generate U1 Result and to contribute to other tests.
def send_udp_probe(dst, dport):
    seq = SEQ_START + 10 * i
    ack = ACK_START + 10 * i
    sport = SPORT_START + i

    send(IP(dst=dst, id=0x1042) / UDP(dport = dport) / 'C' * 300)
