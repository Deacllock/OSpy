import socket
import threading
from queue import Queue


q = Queue()
ports_list = []
list_lock = threading.Lock()
ip = ""


def get_ports(host_ip):
    global ip
    ip = host_ip
    init_ports_scan()
    for x in range(100):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()
    q.join()
    return ports_list


def port_scan(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        con = s.connect((ip, port))
        with list_lock:
            ports_list.append(port)
            print(port, 'is open for host', ip)
        con.close()
    except BaseException:
        pass


def init_ports_scan():
    socket.setdefaulttimeout(0.25)
    for port in range(0, 65535):
        q.put(port)


def threader():
    while True:
        port = q.get()
        port_scan(port)
        q.task_done()
