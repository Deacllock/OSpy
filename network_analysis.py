# Scan de ports
import socket
import time
import threading
from queue import Queue

from scapy.all import ARP, Ether, srp


def get_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"


def hosts_list(network):
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]
    hosts = []

    for sent, received in result:
        ip = received.psrc
        name = get_name(ip)
        hosts.append({'ip': ip, 'mac': received.hwsrc, 'name': name})

    print("Available devices in the network: " + str(len(hosts)))
    print("IP" + " " * 18 + "MAC")
    for host in hosts:
        print(host['name'])
        print("{:16}    {}".format(host['ip'], host['mac']))
    return hosts


hosts_list("192.168.86.1/24")