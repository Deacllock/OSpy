import socket
from ports import get_ports


class Host:
    # class HostError(ErrorType):
    #    pass

    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac
        self.dns_name = self._get_name(ip)
        self.os = self._get_os(ip)
        self.ports = []

    def _get_name(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]

        # Sometimes you can't find the hostnames nor offline neither online
        except socket.herror:
            return "Unknown"

    def _get_os(self, ip):
        # if os = windows -> netbios
        return "os"

    def add_ports(self, ports):
        self.ports = get_ports(self.ip)

    # add option for oppening ports
    def __repr__(self):
        return "{:18}   {:18}   {:18}".format(
            self.dns_name, self.ip, self.mac)
