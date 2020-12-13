import pywifi
from pywifi import const
import time
import sys
import os
import getopt



if os.getuid() != 0:
    print("You need to have root privileges to use this program. Please try again using 'sudo'.\n")
    sys.exit()

wifi = pywifi.PyWiFi()
ifaces = wifi.interfaces()[0]


wifi = pywifi.PyWiFi()
iface = wifi.interfaces()[0]

profile = pywifi.Profile()
profile.ssid = input("Enter the name of the wifi network you want to try to bruteforce:\n")
start_time = time.time()
profile.auth = const.AUTH_ALG_OPEN
profile.akm.append(const.AKM_TYPE_WPA2PSK)
profile.cipher = const.CIPHER_TYPE_CCMP
profile.key = "rba5829qaBdk"

iface.remove_all_network_profiles()
new_profile = iface.add_network_profile(profile)
time.sleep(1)
iface.connect(new_profile)

while ifaces.status() == const.IFACE_CONNECTING:
    print("connecting pls wait")
    time.sleep(1)

if ifaces.status() == const.IFACE_CONNECTED:
    print("Connected ! password for {} is {}\n".format(profile.ssid, profile.key))
    print("Execution took {} seconds.".format(time.time()-start_time))
    iface.disconnect()
    exit()
else:
    print("arf")
    exit()
