from scapy.all import ARP, Ether, srp


def hosts_list(network):
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]
    hosts = []

    for sent, received in result:
        hosts.append({'ip': received.psrc, 'mac': received.hwsrc})

    print("Available devices in the network: " + str(len(hosts)))
    print("IP" + " " * 18 + "MAC")
    for host in hosts:
        print("{:16}    {}".format(host['ip'], host['mac']))
    return hosts


class NmapError():
    pass


class TestError():
    pass


class Nmap:
    def __init__(self):
        self.network = self._network()
        self.hosts = hosts_list(self.network)
