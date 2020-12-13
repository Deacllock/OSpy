#  W send several probes to an open port of a distant device
#  We do some tests on the answers to create a "fingerprint"
#  Then we try to find it in the fingerprint database

from scapy.all import *
import threading
from scapy.arch import get_if_list

from parse_db import parse_db
from sequence_generation.sequence_generation import send_tcp_probes, parse_tcp_responses
from icmp_echo.icmp_echo import send_icmp_probes, parse_icmp_responses
from fingerprints import FingerPrint, Result

conf.L3socket = L3RawSocket

TCP_RESPONSES, ICMP_RESPONSES = [], []
TCP_SEQ_START, ICMP_SEQ_START = 22000, 295 


#  Add sniffed packet into responses list
def get_packet(packet):
    if TCP in packet and 'A' in packet[TCP].flags \
    and 'S' in packet[TCP].flags and not packet in TCP_RESPONSES:
        TCP_RESPONSES.append(packet)

    if ICMP in packet and packet[ICMP].type == 0 and not packet in ICMP_RESPONSES:
        ICMP_RESPONSES.append(packet)


#  Sniff the network to get the responses to packets we have send
def start_sniff(dst, src):
    filter = 'dst host %s and (src host %s' % (dst, src[0])
    for s in src[1:]:
        filter += ' or ' + s
    filter += ') and (tcp or icmp)'

    t = AsyncSniffer(
        iface=get_if_list(),
        filter=filter,
        prn=get_packet)  # prn=lambda x: x.summary())
    t.start()
    time.sleep(2)


#  Stop sniffing
def end_sniff(sniffer):
    sniffer.stop()


#  Find the OSs matching a specific Fingerprint
#  return a list of FingerPrints matching
def get_os_name(x):
    fp_db, os = parse_db('../db/nmap-os-db'), []
    for fp in fp_db:
        if x == fp:
            os.append(fp)
    return os


def check_results():
    tcp_responses, icmp_responses = [], []

    for tcp_seq_i in range(6):
        for i in range(len(TCP_RESPONSES)):
            if TCP_RESPONSES[i][TCP].ack != (TCP_SEQ_START + 10 * tcp_seq_i + 1):
                if i == len(TCP_RESPONSES) - 1:
                    tcp_responses.append(None)
                else:
                    continue
            else:
                tcp_responses.append(TCP_RESPONSES[i])
                break


    for icmp_seq_i in range(2):
        for i in range(len(ICMP_RESPONSES)):
            if ICMP_RESPONSES[i][ICMP].seq != (ICMP_SEQ_START + icmp_seq_i):
                if i == len(ICMP_RESPONSES) - 1:
                    icmp_responses.append(None)
                else:
                    continue
            else:
                icmp_responses.append(ICMP_RESPONSES[i])
                break

    return tcp_responses, icmp_responses


#  Start OS detection as specified above
def os_detection(dst, src, dport):
    sniffer = start_sniff(dst, src)

    send_tcp_probes(dst, dport)
    send_icmp_probes(dst, dport)

    tcp_responses, icmp_responses = check_results()
    tcp_r = parse_tcp_responses(tcp_responses)
    #icmp_r = parse_icmp_responses(icmp_responses)
    fp = FingerPrint('Who Am I', tcp_r)
    oss = get_os_name(fp)
    print(fp)
    print(len(oss))

    # end_sniff(sniffer)


os_detection('127.0.0.1', ['127.0.0.1'], 80)  # dst + open port
