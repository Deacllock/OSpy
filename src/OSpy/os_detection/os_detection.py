#  W send several probes to an open port of a distant device
#  We do some tests on the answers to create a "fingerprint"
#  Then we try to find it in the fingerprint database

from scapy.all import *
import threading
from scapy.arch import get_if_list

from parse_db import parse_db
from sequence_generation import send_tcp_probes, parse_tcp_responses

from fingerprints import FingerPrint, Result

conf.L3socket = L3RawSocket

responses = []


#  Add sniffed packet into responses list
def get_packet(packet):
    if packet not in responses:
        responses.append(packet)

#  Sniff the network to get the responses to packets we have send


def start_sniff(dst):
    filter = 'host %s and (dst port 63000 or dst port 63001 or dst port 63002 or dst port 63003 or dst port 63004 or dst port 63005)' % dst
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
    fp_db, oss = parse_db('../docs/nmap-os-db'), []
    for fp in fp_db:
        if x == fp:
            os.append(fp)
    return os


#  Start OS detection as specified above
def os_detection(dst, port):
    sniffer = start_sniff(dst)

    send_tcp_probes(dst, port)
    tcp_r = parse_tcp_responses(responses)

    fp = Fingerprint('Who Am I', tcp_r)
    oss = get_os_name(fp)
    print(oss)

    # end_sniff(sniffer)


os_detection('127.0.0.1', 80)  # dst + open port
