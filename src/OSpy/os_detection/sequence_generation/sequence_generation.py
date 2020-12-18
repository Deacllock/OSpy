from scapy.all import *
import time

from fingerprints import Result, FingerPrint
from sequence_generation.seq import get_seq
from sequence_generation.t1 import get_t1

SEQ_START = 22000
ACK_START = 44000
SPORT_START = 63000

TCP_PROBES_TIMES = []

#  Send TCP probes with given parameters using scapy
def send_tcp_probe(i, dst, dport, window, options):
    seq = SEQ_START + 10 * i
    ack = ACK_START + 10 * i
    sport = SPORT_START + i

    syn = IP(dst=dst) / TCP(sport=sport, dport=dport, flags=0x02, seq=seq,
                            ack=ack, window=window, options=options)

    send(syn)

# Send 6 TCP probes to Generate SEQ, OPS, WIN and TI tests Result.
# Total time shall be 500ms so that we can reliably detect the common 2Hz
# TCP timestamp sequences.
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
            TCP_PROBES_TIMES.append(time.time())
            i += 1

# Computes OPS Result as explained by nmap.org.
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


# Computes WIN Result as explained by nmap.org
def get_win(responses):
    category, params = 'WIN', {}
    for i in range(len(responses)):
        current = 'W' + str(i + 1)
        if responses[i] is None:
            params[current] = ''
        else:
            params['W' + str(i + 1)] = hex(responses[i][TCP].window)[2:].upper()

    return Result(category, params)

# Given a TCP response list, computes SEQ, OPS, WIN and T1 Results.  
# Return a Result list.
def parse_tcp_responses(tcp_responses, icmp_responses):
    results = []

    #results.append(get_seq(tcp_responses, icmp_responses, TCP_PROBES_TIMES))
    results.append(get_ops(tcp_responses))
    results.append(get_win(tcp_responses))
    results.append(get_t1(tcp_responses[0]))

    return results
