# Parse the given Fingerprints DB to get a list of Fingerprint objects
# used as templates

import os
from fingerprints import FingerPrint, Result

FINGERPRINTS = []
R_TYPES = ['SEQ', 'OPS', 'WIN', 'T1']


#  Parse tests results linked to a specific Fingerprint
def get_results(category, params_list):
    ret = {}
    params = params_list.split('%')
    for p in params:
        p_split = p.split('=')
        p_name = p_split[0]

        if len(p_split) == 1:
            p_val = ''
        else:
            p_val = p_split[1]

        if '|' in p_val:
            p_val = p_val.split('|')

        ret[p_name] = p_val

    return Result(category, ret)


#  Parse Fingerprint from the db
def add_fingerprint(name, i, len_db, db):
    results = []

    while i < len_db and db[i] != '\n':
        line = db[i]
        for r in R_TYPES:
            if line.startswith(r):
                results.append(get_results(r, line[len(r) + 1:-2]))
        i += 1
    FINGERPRINTS.append(FingerPrint(name, results))
    return i


#  Convert FingerPrints db to a python exploitable list of Fingerprints
def parse_db(os_db):
    with open(os_db, 'r') as f:
        db = f.readlines()
        len_db = len(db)
        matchpoints = False

        for i in range(len_db):
            line = db[i]
            if (line[0] == '#' or line[0] == '\n'):
                continue

            if (not matchpoints and line == "MatchPoints\n"):
                matchpoints = True
                i = add_fingerprint("Matchpoints", i, len_db, db)

            elif (line[:11] == "Fingerprint"):
                # see what to choose as a name
                i = add_fingerprint(line[12:-1], i, len_db, db)
    return FINGERPRINTS
