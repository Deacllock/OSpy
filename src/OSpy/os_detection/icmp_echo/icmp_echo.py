from scapy.all import *
import random

from fingerprints import Result
import results_common_functions as commons

def get_ie_dfi(responses):
    icmp1_df = responses[0][IP].flags.DF
    icmp2_df = responses[1][IP].flags.DF

    if icmp1_df:
        if icmp2_df:
            return 'Y'
        return 'S'

    if not icmp1_df and not icmp2_df:
        return 'N'

    return 'O'

def get_ie_cd(responses):
    icmp1_code = responses[0][ICMP].code
    icmp2_code = responses[1][ICMP].code

    if icmp2_code == 0:
        if icmp1_code == 0:
            return 'Z'

        if icmp1_code == 9:
            return 'S'

    if icmp1_code == icmp2_code:
        hex_code = hex(icmp1_code)[2:].upper()
        return hex_code + hex_code

    return 'O'

# Computes IE Result as described in nmap.org.
def get_ie(responses):
    if None in responses:
        return Result('IE', {'R': 'N'})
    
    category, params = 'IE', {}
    params['DFI'] = get_ie_dfi(responses) 
    params['T'] = '' # will not set it up, depends on u1
    params['TG'] = commons.get_tg(responses[0][IP].ttl)
    params['CD'] = get_ie_cd(responses) #first probe only and that is weird CHECK
    return Result(category, params)

# Sends 2 ICMP probes used to get IE and SS Results.
def send_icmp_probes(dst, dport):
    ip1_id, ip2_id  = random.getrandbits(16), random.getrandbits(16)
    icmp1_id = random.getrandbits(16)
    icmp2_id = icmp1_id + 1
    payload1, payload2 = 120 * b'\x00', 150 * b'\x00'

    send(IP(dst=dst, flags='DF', tos=0, id=ip1_id) / ICMP(code=9, seq=295, id=icmp1_id) / payload1)
    send(IP(dst=dst, tos=4, id=ip2_id) / ICMP(code=0, seq=296, id=icmp2_id) / payload2)
