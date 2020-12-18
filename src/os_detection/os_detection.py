from scapy.all import *

from os_detection.parse_db import parse_db
from os_detection.sequence_generation.sequence_generation import send_tcp_probes, parse_tcp_responses
from os_detection.icmp_echo.icmp_echo import send_icmp_probes, get_ie

from os_detection.fingerprints import FingerPrint

conf.L3socket = L3RawSocket

TCP_RESPONSES, ICMP_RESPONSES = [], []
TCP_SEQ_START, ICMP_SEQ_START = 22000, 295

# Check if the sniffed packets are the ones expected.


def get_packet(packet):
    if TCP in packet and packet[TCP].flags.A \
            and packet[TCP].flags.S and packet not in TCP_RESPONSES:
        TCP_RESPONSES.append(packet)

    if ICMP in packet and packet[ICMP].type == 0 and packet not in ICMP_RESPONSES:
        ICMP_RESPONSES.append(packet)

# Start sniffing the network to get responses packets.


def start_sniff(dst, src):
    filter = 'src host %s and (dst host %s' % (dst, src[0])
    for s in src[1:]:
        filter += ' or dst host ' + s
    filter += ') and (tcp or icmp)'

    print(filter)
    sniffer = AsyncSniffer(
        iface=get_if_list(),
        filter=filter,
        prn=get_packet)
    sniffer.start()
    time.sleep(2)
    return sniffer

# Stop sniffing the network.


def end_sniff(sniffer):
    sniffer.stop()

# Print OS matching the constructed Fingerprint.


def choose_os(os_list, dst):
    if (len(os_list) == 0):
        print("No OS detected for %s." % dst)
    if (len(os_list) > 1):
        print("Several OS could match your device:")
    for os in os_list:
        print("%s matches %s." % (os.name, dst))

# Parse the nmap Fingerprints database and compares each entry with our
# Fingerprint.


def get_os_name(x, dst):
    fp_db, os = parse_db('db/nmap-os-db'), []
    for fp in fp_db:
        if x == fp:
            os.append(fp)
    choose_os(os, dst)

# Check if we have received every packet expected.  Else add a None in the
# packet list.


def check_results():
    tcp_responses, icmp_responses = [], []
    if TCP_RESPONSES == []:
        tcp_responses = [None, None, None, None, None, None]

    else:
        for tcp_seq_i in range(6):
            for i in range(len(TCP_RESPONSES)):
                if TCP_RESPONSES[i][TCP].ack != (
                        TCP_SEQ_START + 10 * tcp_seq_i + 1):
                    if i == len(TCP_RESPONSES) - 1:
                        tcp_responses.append(None)
                    
                    else:
                        continue

                else:
                    tcp_responses.append(TCP_RESPONSES[i])
                    break


    if ICMP_RESPONSES == []:
        icmp_responses = [None, None]

    else:
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

# Starts OS detection on a dst device, giving an open port.   Src is a
# list of src ip that can be use by the attacker.


def os_detection(dst, src, open_dport):
    sniffer = start_sniff(dst, src)

    send_tcp_probes(dst, open_dport)
    send_icmp_probes(dst, open_dport)
    tcp_responses, icmp_responses = check_results()
    results = parse_tcp_responses(tcp_responses, icmp_responses)
    results.append(get_ie(icmp_responses))

    fp = FingerPrint('Who Am I', results)
    get_os_name(fp, dst)

    end_sniff(sniffer)
