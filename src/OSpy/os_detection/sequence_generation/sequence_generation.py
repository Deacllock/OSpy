#   Send 6 TCP probes to Generate SEQ, OPS, WIN and TI tests Results   #

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

#  Send TCP probes with given parameters using scapy
def send_tcp_probe(i, dst, dport, window, options):
    seq = SEQ_START + 10 * i
    ack = ACK_START + 10 * i
    sport = SPORT_START + i

    syn = IP(dst=dst) / TCP(sport=sport, dport=dport, flags=0x02, seq=seq,
                            ack=ack, window=window, options=options)

    send(syn)

#  Create 6 TCP probes with option given by nmap.org
# Total time shall be 500ms so that we can reliably detect the common 2Hz
# TCP timestamp sequences
def send_tcp_probes(dst, dport):
    timestamp = ('Timestamp', (0xFFFFFFFF, 0))
    sack = ('SAckOK', '')
    eol = ('EOL', '')
    nop = ('NOP', '')

    t1 = (1, [('WScale', 10), nop, ('MSS', 1460), timestamp, sack])
    t2 = (63, [('MSS', 1400), ('WScale', 0), sack, timestamp, eol])
    t3 = (4, [timestamp, nop, nop, ('WScale', 5), nop, ('MSS', 640)])
    t4 = (4, [sack, timestamp, ('WScale', 10), eol])
    t5 = (16, [('MSS', 536), sack, timestamp, ('WScale', 10), eol])
    t6 = (512, [('MSS', 265), sack, timestamp])

    tcp_probes = [t1, t2, t3, t4, t5, t6]
    t0 = time.time()
    i = 0

    while (i < len(tcp_probes)):
        if (time.time() - t0 >= 0.1 * i):
            send_tcp_probe(i, dst, dport, *tcp_probes[i])
            i += 1


#  Makes OPS tests as explained by nmap.org
#  Return Result object

def get_ops(responses):
    category, params = 'OPS', {}

    opt2char = {
        'EOL': 'L',
        'NOP': 'N',
        'MSS': 'M',
        'Timestamp': 'T',
        'SAckOK': 'S',
        'WScale': 'W'}
    
    for i in range(len(responses)):
        p_name, p_val = ('O' + str(i + 1)), ''

        if responses[i] is not None:
            for opt in responses[i][TCP].options:
                p_val += opt2char[opt[0]]
                if (opt[0] == 'MSS' or opt[0] == 'WScale'):
                    p_val += hex(opt[1])[2:].upper()
                    
                if (opt[0] == 'Timestamp'):
                    for ts_val in opt[1]:
                        p_val += '0' if ts_val == 0 else '1'

        params[p_name] = p_val

    return Result(category, params)


#  Makes WIN tests as explained by nmap.org
#  Return Result object
def get_win(responses):
    category, params = 'WIN', {}
    for i in range(len(responses)):
        current = 'W' + str(i + 1)
        if responses[i] is None:
            params[current] = ''
        else:
            params['W' + str(i + 1)] = hex(responses[i][TCP].window)[2:].upper()

    return Result(category, params)

#  Given a TCP response list, makes SEQ, OPS, WIN and T1 tests
#  Return a Result list
def parse_tcp_responses(responses):
    results = []

    #results.append(get_seq(responses))
    results.append(get_ops(responses))
    results.append(get_win(responses))
    #results.append(get_t1(responses[0]))

    return results
