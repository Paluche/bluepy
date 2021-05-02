#!/usr/bin/env python3

import argparse
import binascii
import os
import sys
import logging
from bluepy import btle


if os.getenv('C', '1') == '0':
    ANSI_RED = ''
    ANSI_GREEN = ''
    ANSI_YELLOW = ''
    ANSI_CYAN = ''
    ANSI_WHITE = ''
    ANSI_OFF = ''
else:
    ANSI_CSI = "\033["
    ANSI_RED = ANSI_CSI + '31m'
    ANSI_GREEN = ANSI_CSI + '32m'
    ANSI_YELLOW = ANSI_CSI + '33m'
    ANSI_CYAN = ANSI_CSI + '36m'
    ANSI_WHITE = ANSI_CSI + '37m'
    ANSI_OFF = ANSI_CSI + '0m'


def dump_services(dev):
    services = sorted(dev.services, key=lambda service: service.handle_start)
    for service in services:
        print("\t%04x: %s" % (service.handle_start, service))
        if service.handle_start == service.handle_end:
            continue

        chars = service.get_characteristics()
        for i, characteristic in enumerate(chars):
            props = characteristic.properties_to_string()
            handle = characteristic.get_handle()
            if 'READ' in props:
                val = characteristic.read()
                if characteristic.uuid == btle.assigned_numbers.device_name:
                    string = ANSI_CYAN + '\'' + \
                        val.decode('utf-8') + '\'' + ANSI_OFF
                elif characteristic.uuid == btle.assigned_numbers.device_information:
                    string = repr(val)
                else:
                    string = '<s' + binascii.b2a_hex(val).decode('utf-8') + '>'
            else:
                string = ''
            print("\t%04x:    %-59s %-12s %s" % (handle,
                                                 characteristic,
                                                 props,
                                                 string))

            while True:
                handle += 1
                if (handle > service.handle_end or
                    (i < len(chars) - 1 and
                     handle >= chars[i + 1].get_handle() - 1)):
                    break
                try:
                    val = dev.read_characteristic(handle)
                    print("\t%04x:     <%s>" %
                          (handle, binascii.b2a_hex(val).decode('utf-8')))
                except btle.BluepyError:
                    break


class ScanPrint(btle.DefaultDelegate):
    def __init__(self, opts):
        btle.DefaultDelegate.__init__(self)
        self.opts = opts

    def discovery_handler(self, dev, is_new_device, is_new_data):
        if is_new_device:
            status = "new"
        elif is_new_data:
            if self.opts.new:
                return
            status = "update"
        else:
            if not self.opts.all:
                return
            status = "old"

        if dev.rssi < self.opts.sensitivity:
            return

        print('    Device (%s): %s (%s), %d dBm %s' %
              (status,
                  ANSI_WHITE + dev.addr + ANSI_OFF,
                  dev.addr_type,
                  dev.rssi,
                  ('' if dev.connectable else '(not connectable)'))
              )

        for (sdid, desc, val) in dev.get_scan_data():
            if sdid in [8, 9]:
                print('\t' + desc + ': \'' + ANSI_CYAN + val + ANSI_OFF + '\'')
            else:
                print('\t' + desc + ': <' + val + '>')

        if not dev.scan_data:
            print('\t(no data)')

        print()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-i',
        '--hci',
        action='store',
        type=int,
        default=0,
        help='Interface number for scan'
    )
    parser.add_argument(
        '-t',
        '--timeout',
        action='store',
        type=int,
        default=4,
        help='Scan delay, 0 for continuous'
    )
    parser.add_argument(
        '-s',
        '--sensitivity',
        action='store',
        type=int,
        default=-128,
        help='dBm value for filtering far devices'
    )
    parser.add_argument(
        '-d',
        '--discover',
        action='store_true',
        help='Connect and discover service to scanned devices'
    )
    parser.add_argument(
        '-a',
        '--all',
        action='store_true',
        help='Display duplicate adv responses, by default show new + updated'
    )
    parser.add_argument(
        '-n',
        '--new',
        action='store_true',
        help='Display only new adv responses, by default show new + updated'
    )
    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='Increase output verbosity'
    )

    parsed = parser.parse_args(sys.argv[1:])

    if parsed.verbose:
        logging.getLogger('bluepy').setLevel(logging.DEBUG)

    scanner = btle.Scanner(parsed.hci, delegate=ScanPrint(parsed))

    print(ANSI_RED + "Scanning for devices..." + ANSI_OFF)
    devices = scanner.scan(parsed.timeout)

    if not parsed.discover:
        return

    print(ANSI_RED + "Discovering services..." + ANSI_OFF)

    for device in devices:
        if not device.connectable or device.rssi < parsed.sensitivity:
            continue

        print("    Connecting to", ANSI_WHITE + device.addr + ANSI_OFF + ":")

        try:
            dev = btle.Peripheral(device)
            dump_services(dev)
            dev.disconnect()
            print()
        except btle.BluepyError as bluepy_error:
            print(bluepy_error)

if __name__ == "__main__":
    main()
