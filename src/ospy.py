import os
import sys
import random
import socket
import netifaces

#from bruteforce_wifi import bruteforce
from nmap import Nmap
from ports import get_ports
from os_detection.os_detection import os_detection

def is_ip_valid(ip):
    try:
        socket.inet_aton(ip)
        return True

    except socket.error:
        return False

def get_ips():
    interfaces = netifaces.interfaces()
    ips = []
    for i in interfaces:
        addr = netifaces.ifaddresses(i).get(netifaces.AF_INET, None)

        if addr is None:
            continue

        for a in addr:
            ips.append(a['addr'])

    return ips

if __name__ == "__main__":
    # Check sudo
    if os.getuid() != 0:
        print("You need to have root privileges to use this program. Please "
              "try again using 'sudo'.\n")
        sys.exit()


    # Does the user want to bruteforce?
    action = ""
    while action not in ["1", "2", "3"]:
        print("What do you want to do?")
        action = input("1) Bruteforce a specific network.\n" +
                "2) Scan a network.\n" +
                "3) Os detection on a device.\n\n")

    # Bruteforce wifi
    if action == "1":
        print("Bruteforce")
        #bruteforce()

    # Get devices on the Network
    if action == "2":
        n = Nmap()

        continue_scan = ""
        if len(n.hosts) == 0:
            continue_scan = "N"

        while continue_scan not in ["Y", "N"]:
            continue_scan = input("Do you want to continue with OS detection? Y/N\n")

        if continue_scan == "N":
            sys.exit()
        action = "3"
    
    if action == "3":
        # Choose a device
        device_ip = ""
        while not is_ip_valid(device_ip):
            device_ip = input("Please enter a valid device IP.\n")

        # Get open ports on the device
        ports = get_ports(device_ip)

        # Check if list is empty
        if len(ports) == 0:
            print("\nNo open ports on the choosen device. Exit.")
            sys.exit()

        # Choose an open port randomly
        open_port = ports[random.randint(0, len(ports) - 1)]

        # Get user IPs
        ips = get_ips()

        # OS detection on open port
        os_detection(device_ip, ips, open_port)
