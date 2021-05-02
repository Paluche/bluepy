#!/usr/bin/env python3

import os
import random
import struct
from bluepy import btle


def rand_data(ad_type, data_len):
    return struct.pack("<BB", data_len + 1, ad_type) + os.urandom(data_len)


def main():
    while True:
        scanned = btle.ScanEntry(None, 0)
        data = b''

        while len(data) <= 28:
            adlen = random.randint(3, 31 - len(data))
            adtype = random.randint(0, 255)
            data += rand_data(adtype, adlen - 2)

        resp = {
            'type': [random.randint(1, 2)],
            'rssi': [random.randint(1, 127)],
            'flag': [4],
            'd' : [data],
        }

        scanned._update(resp)

        print("Result:", scanned.get_scan_data())


if __name__ == '__main__':
    main()
