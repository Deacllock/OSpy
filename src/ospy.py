from bruteforce_wifi import bruteforce
from nmap import Nmap
from ports import get_ports
from os_detection.os_detection import os_detection

if __name__ == "__main__":
    # Check sudo

    # Does the user want to bruteforcE?
    # Bruteforce wifi
    bruteforce()

    # Get devices on the Network
    n = Nmap()

    # Choose a device
    device_ip = ""

    # Get open port on the device
    ports = get_ports(device_ip)

    # Choose an open port randomly
    # Or ask for it
    open_port =

    # OS detection on open port
    os_detection(device_ip, ips, open_port)
