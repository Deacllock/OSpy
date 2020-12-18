from scapy.all import *
import math
import statistics

from os_detection.fingerprints import Result

SEQ_START = 22000
ACK_START = 44000
SPORT_START = 63000

# Computes the hexa difference on a 32 bits integer.


def make_diff(v1, v2):
    if (v1 >= v2):
        return v1 - v2
    return (0xffffffff - v1 + v2)

# Computes the TCP sequence difference between every two responses packet.
# Adds each difference in diff1.


def get_diff1(responses):
    diff1 = []
    for i in range(1, len(responses)):
        r_prev = responses[i - 1][TCP].seq
        r = responses[i][TCP].seq

        diff1.append(make_diff(r_prev, r))
    return diff1

# Computes the gcd between every elements in diff1.


def get_seq_gcd(diff1):
    diff_gcd = gcd(diff1[0], diff1[1])
    for i in range(2, len(diff1)):
        diff_gcd = gcd(diff_gcd, diff1[i])

    return diff_gcd

# Computes the sequence rate of every element in diff1 depending on
# packets received time.


def get_seq_rate(times, diff):
    seq_rate = []
    for i in range(len(diff)):
        rate = times[i + 1] - times[i]
        seq_rate.append(diff[i] / rate)
    return seq_rate

# Computes the average of sequence rate to get ISR test value.


def get_seq_isr(seq_rate):
    average = sum(seq_rate) / len(seq_rate)
    print(average)
    if average < 1:
        return '0'
    return hex(int(8 * math.log2(average)))[2:].upper()

# Computes SP test as described in nmap.org.


def get_seq_sp(responses, seq_rate, gcd):
    if None in responses:
        nb_nones = 0
        for r in responses:
            if r is None:
                nb_nones += 1
        if nb_nones > 2:
            return None

    seq_rate_divided = []
    if (gcd > 9):
        for r in seq_rate:
            seq_rate_divided.append(r / gcd)
    else:
        seq_rate_divided = seq_rate

    standard_derivation = statistics.stdev(seq_rate_divided)
    if standard_derivation <= 1:
        return '0'

    return hex(int(8 * math.log2(standard_derivation)))[2:].upper()

# Computes the IP id difference between every two responses packet.
# Adds each difference in diff2.


def get_diff2(responses):
    diff2 = []
    for i in range(1, len(responses)):
        ip_prev = responses[i - 1][IP].id
        ip = responses[i][IP].id
        diff2.append(0xFFFF - ip + ip_prev + 1)

    return diff2

# Computes TI test as described in nmap.org


def get_seq_ti(responses):
    nb_nones = 0
    if None in responses:
        for r in responses:
            if r in None:
                nb_nones += 1
        if nb_nones >= 3:
            return None

    return get_seq_IP_ID(responses)

# Computes II test as described in nmap.org.


def get_seq_ii(responses):
    if None in responses:
        return None

    return get_seq_IP_ID(responses)

# Computes common operation between TI and II


def get_seq_IP_ID(responses):
    diff2 = get_diff2(responses)

    nb_zeros, identical = 0, 0
    divisible, gt5120, lt10 = 0, 0, 0
    for i in range(len(diff2)):
        if diff2[i] == 0:
            nb_zeros += 1

        if i + 1 < len(diff2):
            ip_increment = diff2[i + 1] - diff2[i]
            if (ip_increment >= 20000):
                return 'RD'

            if ip_increment > 1000:
                if p_increment % 256 != 0 or (
                        p_increment % 256 == 0 and ip_increment > 256000):
                    return 'RI'

            if (diff2[i] == diff2[i + 1]):
                identical += 1

            if diff2[i] > 5120:
                gt5120 += 1

            if diff2[i] % 256 == 0:
                divisible += 1

            if diff2[i] < 10:
                lt10 += 1

    if nb_zeros == len(diff2):
        return 'Z'

    if identical == len(diff2):
        return hex(diff2[0])[2:].upper()

    if divisible == len(diff2) and gt5120 == 0:
        return 'BI'

    if lt10 == len(diff2):
        return 'I'

    return None


# Computes the TCP Timestamp value difference between every two responses packet.
# Adds each difference in diff3.
def get_diff3(tsval_list):
    diff3 = []
    for i in range(1, len(tsval_list)):
        diff3.append(make_diff(tsval_list[i - 1], tsval_list[i]))

    return diff3

# Computes TS test as described in nmap.org


def get_seq_ts(responses, times):
    tsval_list = []
    for r in responses:
        tsval = None
        for opt in r[TCP].options:
            if opt[0] == "Timestamp":
                tsval = opt[1][0]
                tsval_list.append(tsval)

        if tsval is None:
            return 'U'

        if tsval == 0:
            return '0'

    diff3 = get_diff3(tsval_list)
    seq_rate = get_seq_rate(times, diff3)
    average = sum(seq_rate) / len(seq_rate)

    if average < 5.66:
        return '1'
    if average >= 70 and average <= 150:
        return '7'
    if average >= 150 and average <= 350:
        return '8'

    return hex(int(math.log2(average)))[2:].upper()

# Computes every tests that compose SEQ Result as described in nmap.org.


def get_seq(tcp_responses, icmp_responses, tcp_probes_times):
    category, params = 'SEQ', {}

    if None not in tcp_responses:
        diff1 = get_diff1(tcp_responses)
        gcd = get_seq_gcd(diff1)
        params['GCD'] = hex(gcd)[2:].upper()

        seq_rate = get_seq_rate(tcp_probes_times, diff1)
        #params['ISR'] = get_seq_isr(seq_rate)
        sp = get_seq_sp(tcp_responses, seq_rate, gcd)
        # if sp:
        #    params['SP'] = sp

       # params['TS'] = get_seq_ts(tcp_responses, tcp_probes_times)

    ti = get_seq_ti(tcp_responses)
    if ti is not None:
        params['TI'] = ti

    ii = get_seq_ii(icmp_responses)
    if ii is not None and ii != 'RD':
        params['II'] = ii

    # params['SS'] = '' #based on TCP and ICMP probes

    seq = Result(category, params)
    print(seq)
    return seq
