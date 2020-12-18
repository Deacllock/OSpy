# This file contains common functions to several tests.

def get_t(initial_ttl, response_ttl): #CHECK
    diff = initial_ttl - response_ttl

    return hex(diff)[2:].upper()


def get_tg(ttl):
    ttl_sizes = [32, 60, 64, 128, 255]
    for s in ttl_sizes:
        if ttl <= s:
            return hex(s)[2:].upper()
    return hex(255)[2:].upper() #CHECK

