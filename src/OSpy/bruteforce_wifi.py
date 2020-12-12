import pywifi
from pywifi import const
import time


profile = pywifi.Profile()
profile.ssid = "Mute all"
profile.auth = const.AUTH_ALG_OPEN
profile.akm.append(const.AKM_TYPE_WPA2PSK)
profile.cipher = const.CIPHER_TYPE_CCMP
profile.key = "rba5829qaBdk"

wifi = pywifi.PyWiFi()
ifaces = wifi.interfaces()[0]


wifi = pywifi.PyWiFi()
iface = wifi.interfaces()[0]

iface.remove_all_network_profiles()
new_profile = iface.add_network_profile(profile)
time.sleep(1)
iface.connect(new_profile)

while ifaces.status() == const.IFACE_CONNECTING:
    print("connecting pls wait")
    time.sleep(1)

if ifaces.status() == const.IFACE_CONNECTED:
    print("youhou")
    exit()
else:
    print("arf")
    exit()
