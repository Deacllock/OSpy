#  Makes SEQ tests as explained by nmap.org

from scapy.all import *
from fingerprints import Result
import math
import statistics

SEQ_START = 22000
ACK_START = 44000
SPORT_START = 63000

def get_diff1(responses):
    diff1 = []
    for i in range(1, len(responses)):
        r_prev = responses[i - 1][TCP].seq
        r = responses[i][TCP].seq

        if (r < r_prev):
            diff1.append(0xffffffff - r_prev + r)
        else:
            diff1.append(r - r_prev)
    return diff1

def get_seq_gcd(diff1):
    if len(diff1) == 0:
        return 0
    if len(diff1) == 1:
        return diff1[0]

    diff_gcd = gcd(diff1[0], diff1[1])
    for i in range(2, len(diff1)):
        diff_gcd = gcd(diff_gcd, diff1[i])

    return diff_gcd

def get_seq_rate(diff1):
    seq_rate = []
    for d in diff1:
        seq_rate.append(d/0.1)
    return seq_rate


def get_seq_isr(seq_rate):
    average = sum(seq_rate) / len(seq_rate)

    if average < 1:
        return 0

    return int(8 * math.log(average))
    
def get_seq_sp(responses, seq_rate, gcd):
    if (len(responses) < 4):
        return ''
    seq_rate_divided = []
    if (gcd > 9):
        for r in seq_rate:
            seq_rate_divided.append(r/gcd)

    standard_derivation = statistics.stdev(seq_rate_divided)
    if standard_derivation <= 1:
        return 0
    return int(8 * math.log(standard_derivation))

def get_seq_ti(responses):
    if (len(responses) < 3):
        return ''

def get_seq(responses):
    category, params = 'SEQ', {}
    
    diff1 = get_diff1(responses)
    seq_rate = get_seq_rate(diff1)
    params['GCD'] = get_seq_gcd(diff1)
    """
    params['SP'] = get_seq_sp(responses, seq_rate, params['GCD'])
    params['ISR'] = get_seq_isr(seq_rate)
    params['TI'] = '' #GNNNNN
    params['II'] = '' #based on ICMP probes
    params['SS'] = '' #based on TCP and ICMP probes
    params['TS'] = ''
    """
    return Result(category, params)
