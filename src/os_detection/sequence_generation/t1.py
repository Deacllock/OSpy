from scapy.all import *

from os_detection.fingerprints import Result
import os_detection.results_common_functions as commons

SEQ_START = 22000
ACK_START = 44000


def get_t1_s(seq, ack):
    if (seq == 0):
        return 'Z'
    elif (seq == ack):
        return 'A'
    elif (seq == (ack + 1)):
        return 'A+'
    else:
        return 'O'


def get_t1_a(seq, ack):
    if (ack == 0):
        return 'Z'
    if (seq == ack):
        return 'S'
    if (ack == (seq + 1)):
        return 'S+'
    else:
        return 'O'


def get_t1_f(flags):
    ret = ''
    for f in ['E', 'U', 'A', 'P', 'R', 'S', 'F']:
        if f in flags:
            ret += f

    return 'N' if ret == '' else ret  # check


def get_t1_rd(r1):
    if (r1[TCP].flags.R):
        return hex(binary.crc32(r1[TCP]))[2:].upper()
    return '0'


def get_t1_q(r1):
    q = ''
    if r1[TCP].reserved != 0:
        q += 'R'
    if not r1[TCP].flags.U and r1[TCP].urgptr != 0:
        q += 'U'
    return q

# Computes T1 Result as described in nmap.org.


def get_t1(r1):
    category, params = 'T1', {}

    if (r1 is None):
        return Result(category, {'R': 'N'})

    params['R'] = 'Y'
    params['DF'] = 'Y' if r1[IP].flags.DF else 'N'
    params['T'] = ''

    params['TG'] = commons.get_tg(r1[IP].ttl)

    seq, ack = r1[TCP].seq, r1[TCP].ack
    params['S'] = get_t1_s(seq, ACK_START)
    params['A'] = get_t1_a(SEQ_START, ack)

    params['F'] = get_t1_f(r1[TCP].flags)
    params['RD'] = get_t1_rd(r1)
    params['Q'] = get_t1_q(r1)
    return Result(category, params)
