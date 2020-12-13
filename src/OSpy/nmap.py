from scapy.all import ARP, Ether, srp
from host import Host
import sys
import os


class Nmap:
    def __init__(self):
        if os.getuid() != 0:
            print("You need to have root privileges to use this program. Please try again using 'sudo'.")
            sys.exit()
        self.network = self._network()
        self.hosts = []
        self.set_hosts(self._hosts_list(self.network))
        print("erro as occured shit appenr")
        print(self)

    def _network(self):
        return input("Enter your network with /24 (xxx.xxx.xxx.xxx/24):\n")

    def set_hosts(self, hosts_list):
        for host in hosts_list:
            self.hosts.append(Host(host['ip'], host['mac']))

    def _hosts_list(self, network):
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=0)[0]
        hosts = []

        for sent, received in result:
            ip = received.psrc
            hosts.append({'ip': ip, 'mac': received.hwsrc})
        return hosts

    def __repr__(self):
        msg = '\nnmap into %s\n' % self.network
        msg += "Available devices in the network: %d\n\n" % len(self.hosts)

        msg += "NAME" + " " * 18 + "IP" + " " * 18 + "MAC" + " " * 18 + "OS\n"
        for h in self.hosts:
            msg += str(h) + '\n'

        return msg
