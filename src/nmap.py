from scapy.all import ARP, Ether, srp
from host import Host


class Nmap:
    def __init__(self, network=None):
        if network is None:
            self.network = self._network()
        else:
            self.network = network

        self.hosts = []
        # Try catch the PermissionError (Operation not permitted)
        self.set_hosts(self._hosts_list(self.network))
        print(self)

    def _network(self):
        return input("Enter your network with mask:\n")

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

        msg += "NAME" + " " * 18 + "IP" + " " * 18 + "MAC" + " " * 18 + "\n"
        for h in self.hosts:
            msg += str(h) + '\n'

        return msg
