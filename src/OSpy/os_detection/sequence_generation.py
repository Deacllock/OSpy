#   Send 6 TCP probes to Generate SEQ, OPS, WIN and TI tests Results   #

from scapy.all import *
import threading
from datetime import datetime
from datetime import timedelta
from fingerprints import Result

SEQ_START = 22000
ACK_START = 44000
SPORT_START = 63000

NB_RESPONSES = 6

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
    l_probes = len(tcp_probes)
    t0 = time.time()
    i = 0

    while (i < l_probes):
        if (time.time() - t0 >= 0.1 * i):
            send_tcp_probe(i, dst, dport, *tcp_probes[i])
            i += 1


# FOR ALL TESTS YOU NEED TO CHECK YOU HAVE EVERY PROBES OR ELSE SEND EMPTY

#  Makes SEQ tests as explained by nmap.org
#  Return Result object
def get_seq(responses):
    category, params = 'SEQ', {}
    p_names = ['SP', 'GCD', 'ISR', 'TI', 'II', 'SS', 'TS']

    return Result(category, params)


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
    for i in range(NB_RESPONSES):

        options = responses[i][TCP].options

        p_name, p_val = ('O' + str(i + 1)), ''
        for opt in options:
            p_val += opt2char[opt[0]]
            if (opt[0] == 'MSS'):
                p_val += hex(opt[1])[2:].upper()

            if (opt[0] == 'Timestamp'):
                for ts_val in opt[1]:
                    p_val += '0' if ts_val == 0 else '1'

            if (opt[0] == 'WScale'):
                p_val += hex(opt[1])[2:].upper()

        params[p_name] = p_val

    return Result(category, params)


#  Makes WIN tests as explained by nmap.org
#  Return Result object
def get_win(responses):
    category, params = 'WIN', {}
    for i in range(NB_RESPONSES):
        params['W' + str(i + 1)] = responses[i][TCP].window

    return Result(category, params)


#  Makes T1 tests as explained by nmap.org
#  Return Result object
def get_t1(responses):
    category, params = 'T1', {}

    r1 = responses[0]
    if (r1[TCP].ack != SEQ_START + 1):  # why seq and why +1?
        return Result(category, {'R': 'N'})
    params['R'] = 'Y'

    params['DF'] = 'Y' if (r1[IP].flags == 'DF') else 'N'
    # check if you don't have to do weird stuff
    params['T'] = hex(r1[IP].ttl)[2:].upper()
    params['TG'] = ''  # T/TG par compris pour le moment

    if (r1[TCP].seq == 0):
        params['S'] = 'Z'
    elif (r1[TCP].seq == r1[TCP].ack):
        params['S'] = 'A'
    elif (r1[TCP].seq == (r1[TCP].ack + 1)):
        params['S'] = 'A+'
    else:
        params['S'] = 'O'

    if (r1[TCP].ack == 0):
        params['A'] = 'Z'
    if (params['S'] == 'A'):
        params['A'] = 'S'
    if (r1[TCP].ack == (r1[TCP].seq + 1)):
        params['A'] = 'S+'
    else:
        params['A'] = 'O'

    params['F'] = ''
    for f in ['E', 'U', 'A', 'P', 'R', 'S', 'F']:
        if f in r1[TCP].flags:
            params['F'] += f

    params['F'] = 'N' if params['F'] == '' else params['F']  # check

    params['RD'] = ''  # perform CRC32 checksum on reset packet then report result

    params['Q'] = ''
    if r1[TCP].reserved != 0:
        params['Q'] += 'R'
    if r1[TCP].urgptr != 0:  # you need to check if a pointer is set when the flag is not set
        params['Q'] += 'U'

    return Result(category, params)


#  Given a TCP response list, makes SEQ, OPS, WIN and T1 tests
#  Return a Result list
def parse_tcp_responses(responses):
    responses[0].show()

    results_parsing, results = [get_seq, get_ops, get_win, get_t1], []
    for rp in results_parsing:
        results.append(rp(responses))

    for r in results:
        print(r)
