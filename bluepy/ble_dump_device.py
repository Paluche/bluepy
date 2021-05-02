"""
Basic test script for the bluepy module. Connect to a device and read all the
readable characteristics.
"""

from argparse import ArgumentParser
from bluepy.btle import ADDR_TYPE_RANDOM, ADDR_TYPE_PUBLIC, Peripheral
from bluepy.btle import BluepyError


def main():
    """Script main method."""
    parser = ArgumentParser(description=__doc__)

    parser.add_argument(dest='mac_address',
                        help='MAC address of the device to connect to.')

    parser.add_argument(
        '--addr-type-random',
        dest='addr_type_random',
        action='store_true',
        help='Indicate that the device MAC address is of type random. By '
             'default we will consider the address type to be public'
    )

    parsed = parser.parse_args()

    print(
        'Connecting to: {}, address type: {}'.format(
            parsed.mac_address,
            'random' if parsed.addr_type_random else 'public'
        )
    )
    conn = Peripheral(
        parsed.mac_address,
        ADDR_TYPE_RANDOM if parsed.addr_type_random else ADDR_TYPE_PUBLIC
    )

    try:
        for svc in conn.services:
            print(str(svc), ':')
            for characteristic in svc.get_characteristics():
                print(
                    '    {}, hnd={}, supports {}'.format(
                        characteristic,
                        hex(characteristic.handle),
                        characteristic.properties_to_string()
                    )
                )
                if characteristic.supports_read():
                    try:
                        print('    ->', repr(characteristic.read()))
                    except BluepyError as bluepy_error:
                        print('    ->', bluepy_error)

    finally:
        conn.disconnect()


if __name__ == '__main__':
    main()
