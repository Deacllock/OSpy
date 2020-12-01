import socket
import time
import threading
from queue import Queue


def port_scan(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        con = s.connect((ip, port))
        with list_lock:
            ports_list.append(ip)
            print(port, 'is open for host', ip)
        con.close()
    except:
        pass


def init_ports_scan():
    socket.setdefaulttimeout(0.25)
    print('Starting scan on host: ', ip)
    for worker in range(0, 65535):
        q.put(worker)


def threader():
    while True:
        worker = q.get()
        port_scan(worker)
        q.task_done()


list_lock = threading.Lock()
q = Queue()
ports_list = []
target = input('Enter the host to be scanned: ')
ip = socket.gethostbyname(target)
startTime = time.time()
for x in range(100):
    t = threading.Thread(target=threader)
    t.daemon = True
    t.start()
init_ports_scan()
q.join()