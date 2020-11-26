import socket

class Host:    
    #class HostError(ErrorType):
    #    pass

    def __init__(self, ip):
        self.ip = ip
        self.dns_name = self._get_name(ip)
        self.os = self._get_os(ip)
        self.ports = []

    def _get_name(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]

        #Sometimes you can't find the hostnames nor offline neither online
        except socket.herror :
            return "Unknown"
    
    def _get_os(self, ip):
        #if os = windows -> netbios
        return "os"

    def add_ports(self, ports):
        self.ports.append(ports)

    def __repr__(self):
        return 'DNS Name : %s\nOS : %s\nIP : %s\n Open ports : %s' % (self.dns_name, 
                self.os, self.ip, self.ports)
