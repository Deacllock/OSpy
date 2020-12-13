#   Send 6 TCP probes to Generate SEQ, OPS, WIN and TI tests Results   #

from scapy.all import *
import threading
from datetime import datetime
from datetime import timedelta
import random

from fingerprints import Result, FingerPrint
from sequence_generation.seq import get_seq
from sequence_generation.t1 import get_t1

SEQ_START = 22000
ACK_START = 44000
SPORT_START = 63000

def set_ie():
    category, params = 'IE', {}
    params['R'] = '' #if both probes elicit responses : return 'Y'
    params['DFI'] = '' 
    params['T'] = '' #first probe only
    params['TG'] = ''
    params['CD'] = '' #first probe only
    return Result(category, params)

def send_icmp_probes(dst, dport):
    ip1_id, ip2_id  = random.getrandbits(16), random.getrandbits(16)
    icmp1_id = random.getrandbits(16)
    icmp2_id = icmp1_id + 1
    payload1, payload2 = 120 * b'\x00', 150 * b'\x00'

    send(IP(dst=dst, flags='DF', tos=0, id=ip1_id) / ICMP(code=9, seq=295, id=icmp1_id) / payload1)
    send(IP(dst=dst, flags='DF', tos=4, id=ip2_id) / ICMP(code=0, seq=296, id=icmp2_id) / payload2)


def parse_icmp_responses(responses):
    responses[0].show()

    results_parsing, results = [get_seq, get_ops, get_win, get_t1], []
    for rp in results_parsing:
        results.append(rp(responses))

    for r in results:
        print(r)
