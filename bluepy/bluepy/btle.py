"""Bluetooth Low Energy Python interface"""

import re
import sys
import os
import time
import subprocess
import binascii
import struct
import json
import signal
import logging
from queue import Queue, Empty
from threading import Thread


def preexec_function():
    # Ignore the SIGINT signal by setting the handler to the standard
    # signal handler SIG_IGN.
    signal.signal(signal.SIGINT, signal.SIG_IGN)


SCRIPT_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)))
HELPER_EXE = os.path.join(SCRIPT_PATH, 'bluepy-helper')

if not os.path.isfile(HELPER_EXE):
    raise ImportError(f'Cannot find required executable "{HELPER_EXE}"')

SEC_LEVEL_LOW = 'low'
SEC_LEVEL_MEDIUM = 'medium'
SEC_LEVEL_HIGH = 'high'

ADDR_TYPE_PUBLIC = 'public'
ADDR_TYPE_RANDOM = 'random'

logger = logging.getLogger('bluepy')


class _UUIDNameMap:
    # Constructor sets self.currentTimeService, self.txPower, and so on from
    # names.
    def __init__(self, id_list):
        self.id_map = {}

        for uuid in id_list:
            attr_name = re.sub(r'[ \(\)]', '_', uuid.common_name).rstrip('_')
            vars(self)[attr_name] = uuid
            self.id_map[uuid] = uuid

    def get_common_name(self, uuid):
        if uuid in self.id_map:
            return self.id_map[uuid].common_name
        return None

class BluepyError(Exception):
    """Base class for all Bluepy exceptions"""
    def __init__(self, message, resp_dict=None):
        self.message = message

        # optional messages from bluepy-helper
        self.estat = None
        self.emsg = None
        if resp_dict:
            self.estat = resp_dict.get('estat', None)
            if isinstance(self.estat, list):
                self.estat = self.estat[0]
            self.emsg = resp_dict.get('emsg', None)
            if isinstance(self.emsg, list):
                self.emsg = self.emsg[0]
        super().__init__()

    def __str__(self):
        msg = self.message
        if self.estat or self.emsg:
            msg = msg + ' ('
            if self.estat:
                msg = msg + f'code: {self.estat}'
            if self.estat and self.emsg:
                msg = msg + ', '
            if self.emsg:
                msg = msg + f'error: {self.emsg}'
            msg = msg + ')'

        return msg


class BluepyInternalError(BluepyError):
    def __init__(self, message, response=None):
        BluepyError.__init__(self, message, response)


class BluepyDisconnectError(BluepyError):
    def __init__(self, message, response=None):
        BluepyError.__init__(self, message, response)


class BluepyManagementError(BluepyError):
    def __init__(self, message, response=None):
        BluepyError.__init__(self, message, response)


class BluepyGattError(BluepyError):
    def __init__(self, message, response=None):
        BluepyError.__init__(self, message, response)


# TODO Use built-in module uuid.UUID, at least inherit from it.
class UUID:
    def __init__(self, val, common_name=None):
        """We accept: 32-digit hex strings, with and without '-' characters,
        4 to 8 digit hex strings, and integers.
        """
        if isinstance(val, int):
            if (val < 0) or (val > 0xFFFFFFFF):
                raise ValueError(
                    'Short form UUIDs must be in range 0..0xFFFFFFFF'
                )
            val = '%04X' % val
        elif isinstance(val, self.__class__):
            val = str(val)
        else:
            val = str(val)  # Do our best

        val = val.replace('-', '')
        if len(val) <= 8:  # Short form
            val = ('0' * (8 - len(val))) + val + '00001000800000805F9B34FB'

        self.bin_val = binascii.a2b_hex(val.encode('utf-8'))
        if len(self.bin_val) != 16:
            raise ValueError(
                f'UUID must be 16 bytes, got "{val}" (len={len(self.bin_val)})'
            )
        self.common_name = common_name

    def __str__(self):
        string = binascii.b2a_hex(self.bin_val).decode('utf-8')
        return '-'.join(
            [string[x:x + 8] for x in range(0, 32, 8)])

    def __eq__(self, other):
        return self.bin_val == UUID(other).bin_val

    def __cmp__(self, other):
        return self.bin_val != UUID(other).bin_val

    def __hash__(self):
        return hash(self.bin_val)

    def get_common_name(self):
        ret = assigned_numbers.get_common_name(self)
        if ret:
            return ret
        ret = str(self)
        if ret.endswith('-0000-1000-8000-00805f9b34fb'):
            ret = ret[0:8]
            if ret.startswith('0000'):
                ret = ret[4:]
        return ret


def get_json_uuid():
    with open(os.path.join(SCRIPT_PATH, 'uuids.json'), 'rb') as uuids_file:
        uuid_data = json.loads(uuids_file.read().decode('utf-8'))
    for key in uuid_data.keys():
        for number, cname, name in uuid_data[key]:
            yield UUID(number, cname)
            yield UUID(number, name)


assigned_numbers = _UUIDNameMap(get_json_uuid())


class Service:
    def __init__(self, peripheral, uuid_value, handle_start, handle_end):
        self.peripheral = peripheral
        self.uuid = UUID(uuid_value)
        self.handle_start = handle_start
        self.handle_end = handle_end
        self.chars = None
        self.descs = None

    def get_characteristics(self, for_uuid=None):
        if not self.chars:  # Unset, or empty
            if self.handle_end <= self.handle_start:
                self.chars = []
            else:
                self.chars = self.peripheral.get_characteristics(
                                 self.handle_start,
                                 self.handle_end
                             )
        if for_uuid is not None:
            uuid = UUID(for_uuid)
            return [char for char in self.chars if char.uuid == uuid]

        return self.chars

    def get_descriptors(self, for_uuid=None):
        if not self.descs:
            # Grab all descriptors in our range, except for the service
            # declaration descriptor
            all_descs = self.peripheral.get_descriptors(self.handle_start + 1,
                                                        self.handle_end)
            # Filter out the descriptors for the characteristic properties.
            # Note that this does not filter out characteristic value
            # descriptors.
            self.descs = [desc for desc in all_descs if desc.uuid != 0x2803]
        if for_uuid is not None:
            uuid = UUID(for_uuid)
            return [desc for desc in self.descs if desc.uuid == uuid]
        return self.descs

    def __str__(self):
        return 'Service <uuid={} handleStart={} handleEnd={}>'.format(
            self.uuid.get_common_name(),
            self.handle_start,
            self.handle_end
        )


class Characteristic:
    # Currently only READ is used in supports_read function,
    # the rest is included to facilitate supportsXXXX functions if required.
    props = {
        'BROADCAST': 0b00000001,
        'READ': 0b00000010,
        'WRITE_NO_RESP': 0b00000100,
        'WRITE': 0b00001000,
        'NOTIFY': 0b00010000,
        'INDICATE': 0b00100000,
        'WRITE_SIGNED': 0b01000000,
        'EXTENDED': 0b10000000,
    }

    prop_names = {
        0b00000001: 'BROADCAST',
        0b00000010: 'READ',
        0b00000100: 'WRITE NO RESPONSE',
        0b00001000: 'WRITE',
        0b00010000: 'NOTIFY',
        0b00100000: 'INDICATE',
        0b01000000: 'WRITE SIGNED',
        0b10000000: 'EXTENDED PROPERTIES',
    }

    def __init__(self,
                 peripheral,
                 uuid_value,
                 handle,
                 properties,
                 value_handle):
        self.peripheral = peripheral
        self.uuid = UUID(uuid_value)
        self.handle = handle
        self.properties = properties
        self.value_handle = value_handle
        self.descs = None

    def read(self):
        return self.peripheral.read_characteristic(self.value_handle)

    def write(self, val, with_response=False):
        return self.peripheral.write_characteristic(self.value_handle,
                                                    val,
                                                    with_response)

    def get_descriptors(self, for_uuid=None, handle_end=0xFFFF):
        if not self.descs:
            # Descriptors (not counting the value descriptor) begin after
            # the handle for the value descriptor and stop when we reach
            # the handle for the next characteristic or service
            self.descs = []
            for desc in self.peripheral.get_descriptors(self.value_handle + 1,
                                                        handle_end):
                if desc.uuid in (0x2800, 0x2801, 0x2803):
                    # Stop if we reach another characteristic or service
                    break
                self.descs.append(desc)
        if for_uuid is not None:
            uuid = UUID(for_uuid)
            return [desc for desc in self.descs if desc.uuid == uuid]
        return self.descs

    def __str__(self):
        return f'Characteristic <{self.uuid.get_common_name()}>'

    def supports_read(self):
        return bool(self.properties & Characteristic.props['READ'])

    def properties_to_string(self):
        prop_str = ''
        for prop_name in Characteristic.prop_names:
            if prop_name & self.properties:
                prop_str += Characteristic.prop_names[prop_name] + ' '
        return prop_str

    def get_handle(self):
        return self.value_handle


class Descriptor:
    def __init__(self, *args):
        (self.peripheral, uuid_value, self.handle) = args
        self.uuid = UUID(uuid_value)

    def __str__(self):
        return f'Descriptor <{self.uuid.get_common_name()}>'

    def read(self):
        return self.peripheral.read_characteristic(self.handle)

    def write(self, val, with_response=False):
        self.peripheral.write_characteristic(self.handle, val, with_response)


class DefaultDelegate:
    def notification_handler(self, handle, data):
        print(f'Notification: {handle} sent data {binascii.b2a_hex(data)}')

    def discovery_handler(self, scan_entry, is_new_device, is_new_data):
        print(
            'Discovered {}device {}{}'.format(
                'new ' if is_new_device else '',
                scan_entry.addr,
                  ' with new data' if is_new_data else ''
            )
        )


def _preexec_function():
    # Ignore the SIGINT signal by setting the handler to the standard
    # signal handler SIG_IGN.
    signal.signal(signal.SIGINT, signal.SIG_IGN)


class BluepyHelper:
    def __init__(self, delegate=None):
        self._helper = None
        self._lineq = None
        self._stderr = None
        self._mtu = 0
        self.delegate = delegate

    def _start_helper(self, iface=None):
        if self._helper is None:
            logger.debug('Running %s', HELPER_EXE)
            self._lineq = Queue()
            self._mtu = 0
            self._stderr = open(os.devnull, 'w')
            args = [HELPER_EXE]
            if iface is not None:
                args.append(str(iface))
            self._helper = subprocess.Popen(args,
                                            stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE,
                                            stderr=self._stderr,
                                            universal_newlines=True,
                                            preexec_fn=preexec_function)
            thread = Thread(target=self._read_to_queue)
            thread.daemon = True  # don't wait for it to exit
            thread.start()

    def _read_to_queue(self):
        """Thread to read lines from stdout and insert in queue."""
        while self._helper:
            line = self._helper.stdout.readline()
            if not line:                  # EOF
                break
            self._lineq.put(line)

    def _stop_helper(self):
        if self._helper is not None:
            logger.debug('Stopping %s', HELPER_EXE)
            self._helper.stdin.write('quit\n')
            self._helper.stdin.flush()
            self._helper.wait()
            self._helper = None
        if self._stderr is not None:
            self._stderr.close()
            self._stderr = None

    def _write_cmd(self, cmd):
        if self._helper is None:
            raise BluepyInternalError(
                'Helper not started (did you call connect()?)'
            )
        logger.debug('Sent: %s', cmd)
        self._helper.stdin.write(cmd)
        self._helper.stdin.flush()

    def _mgmt_cmd(self, cmd):
        self._write_cmd(cmd + '\n')
        response = self._wait_response('mgmt')
        if response['code'][0] != 'success':
            self._stop_helper()
            raise BluepyManagementError(
                f'Failed to execute management command "{cmd}"',
                response
            )

    @staticmethod
    def parse_response(line):
        response = {}
        for item in line.rstrip().split('\x1e'):
            (tag, tval) = item.split('=')
            if len(tval) == 0:
                val = None
            elif tval[0] == '$' or tval[0] == '\'':
                # Both symbols and strings as Python strings
                val = tval[1:]
            elif tval[0] == 'h':
                val = int(tval[1:], 16)
            elif tval[0] == 'b':
                val = binascii.a2b_hex(tval[1:].encode('utf-8'))
            else:
                raise BluepyInternalError(
                    f'Cannot understand response value {tval!r}'
                )
            if tag not in response:
                response[tag] = [val]
            else:
                response[tag].append(val)
        return response

    def _wait_response(self, wanted_type, timeout=None):
        if not isinstance(wanted_type, list):
            wanted_type = [wanted_type]

        while True:
            if self._helper.poll() is not None:
                raise BluepyInternalError('Helper exited')

            try:
                response = self._lineq.get(timeout=timeout)
            except Empty:
                logger.debug('Select timeout')
                return None

            logger.debug('Got: %s', repr(response))
            if response.startswith('#') or \
               response == '\n' or \
               len(response) == 0:
                continue

            response = self.parse_response(response)
            if 'rsp' not in response:
                raise BluepyInternalError('No response type indicator',
                                          response)

            response_type = response['rsp'][0]

            print(f'response_type {response_type}')

            # always check for MTU updates
            if 'mtu' in response and len(response['mtu']) > 0:
                new_mtu = int(response['mtu'][0])
                if self._mtu != new_mtu:
                    self._mtu = new_mtu
                    logger.debug('Updated MTU: %s', self._mtu)

            if response_type in wanted_type:
                return response

            print(f'response_type {response_type} not in wanted_type {wanted_type}')

            if response_type == 'stat':
                if 'state' in response and \
                   len(response['state']) > 0 and \
                   response['state'][0] == 'disc':
                    self._stop_helper()
                    raise BluepyDisconnectError('Device disconnected', response)
            elif response_type == 'err':
                errcode = response['code'][0]
                if errcode == 'nomgmt':
                    raise BluepyManagementError(
                        'Management not available (permissions problem?)',
                        response
                    )
                if errcode == 'atterr':
                    raise BluepyGattError('Bluetooth command failed', response)
                raise BluepyError(f'Error from bluepy-helper ({errcode})', response)

            if response_type == 'scan':
                # Scan response when we weren't interested. Ignore it.
                continue

            raise BluepyInternalError(f'Unexpected response ({response_type})',
                                      response)

    def status(self):
        self._write_cmd('stat\n')
        return self._wait_response('stat')


class Peripheral(BluepyHelper):
    def __init__(self,
                 device_address=None,
                 addr_type=ADDR_TYPE_PUBLIC,
                 iface=None,
                 timeout=None):
        BluepyHelper.__init__(self)
        self._service_map = None  # Indexed by UUID
        (self.device_address, self.addr_type, self.iface) = (None, None, None)

        if isinstance(device_address, ScanEntry):
            self._connect(device_address.addr,
                          device_address.addr_type,
                          device_address.iface,
                          timeout)
        elif device_address is not None:
            self._connect(device_address, addr_type, iface, timeout)

    def __enter__(self):
        return self

    def __exit__(self, type_, value, traceback):
        self.disconnect()

    def _get_resp(self, wanted_type, timeout=None):
        if not isinstance(wanted_type, list):
            wanted_type = [wanted_type]

        while True:
            response = self._wait_response(wanted_type + ['ntfy', 'ind'], timeout)
            if response is None:
                return None

            response_type = response['rsp'][0]
            if response_type in ('ntfy', 'ind'):
                hnd = response['hnd'][0]
                data = response['d'][0]
                if self.delegate is not None:
                    self.delegate.notification_handler(hnd, data)
            if response_type not in wanted_type:
                continue
            return response

    def _connect(self,
                 addr,
                 addr_type=ADDR_TYPE_PUBLIC,
                 iface=None,
                 timeout=None):
        if len(addr.split(':')) != 6:
            raise ValueError(f'Expected MAC address, got {addr!r}')

        if addr_type not in (ADDR_TYPE_PUBLIC, ADDR_TYPE_RANDOM):
            raise ValueError(
                f'Expected address type public or random, got {addr_type}'
            )

        self._start_helper(iface)
        self.addr = addr
        self.addr_type = addr_type
        self.iface = iface
        cmd = f'conn {addr} {addr_type}'
        if iface is not None:
            cmd += f' hci {iface}'

        self._write_cmd(cmd + '\n')
        response = self._get_resp('stat', timeout)
        if response is None:
            raise BluepyDisconnectError(
                f'Timed out while trying to connect to peripheral {addr}, '
                f'addr type: {addr_type}',
                response
            )
        while response['state'][0] == 'tryconn':
            response = self._get_resp('stat', timeout)
        if response['state'][0] != 'conn':
            self._stop_helper()
            raise BluepyDisconnectError(
                f'Failed to connect to peripheral {addr}, addr type: '
                f'{addr_type}',
                response
            )

    def connect(self,
                addr,
                addr_type=ADDR_TYPE_PUBLIC,
                iface=None,
                timeout=None):
        if isinstance(addr, ScanEntry):
            self._connect(addr.addr, addr.addr_type, addr.iface, timeout)
        elif addr is not None:
            self._connect(addr, addr_type, iface, timeout)

    def disconnect(self):
        if self._helper is None:
            return
        # Unregister the delegate first
        self.delegate = None

        self._write_cmd('disc\n')
        self._get_resp('stat')
        self._stop_helper()

    def discover_services(self):
        self._write_cmd('svcs\n')
        response = self._get_resp('find')
        starts = response['hstart']
        ends = response['hend']
        uuids = response['uuid']
        services_nb = len(uuids)
        assert(len(starts) == services_nb and len(ends) == services_nb)
        self._service_map = {}
        for i in range(services_nb):
            self._service_map[UUID(uuids[i])] = Service(self,
                                                        uuids[i],
                                                        starts[i],
                                                        ends[i])
        return self._service_map

    def get_state(self):
        status = self.status()
        return status['state'][0]

    @property
    def services(self):
        if self._service_map is None:
            self._service_map = self.discover_services()
        return self._service_map.values()

    def get_services(self):
        return self.services

    def get_service_by_uuid(self, uuid_value):
        uuid = UUID(uuid_value)
        if self._service_map is not None and uuid in self._service_map:
            return self._service_map[uuid]
        self._write_cmd(f'svcs {uuid}\n')
        response = self._get_resp('find')
        if 'hstart' not in response:
            raise BluepyGattError(
                f'Service {uuid.get_common_name()} not found',
                response
            )
        svc = Service(self, uuid, response['hstart'][0], response['hend'][0])

        if self._service_map is None:
            self._service_map = {}
        self._service_map[uuid] = svc
        return svc

    def _get_included_services(self, start_handle=1, end_handle=0xFFFF):
        # TODO: No working example of this yet
        self._write_cmd(f'incl {start_handle:X} {end_handle:X}\n')
        return self._get_resp('find')

    def get_characteristics(self,
                            start_handle=1,
                            end_handle=0xFFFF,
                            uuid=None):
        cmd = f'char {start_handle:X} {end_handle:X}'
        if uuid:
            cmd += f' {UUID(uuid)}'
        self._write_cmd(cmd + '\n')
        response = self._get_resp('find')
        chars_nb = len(response['hnd'])
        return [Characteristic(self,
                               response['uuid'][i],
                               response['hnd'][i],
                               response['props'][i],
                               response['vhnd'][i])
                for i in range(chars_nb)]

    def get_descriptors(self, start_handle=1, end_handle=0xFFFF):
        self._write_cmd(f'desc {start_handle:X]} {end_handle:X}\n')
        # Historical note:
        # Certain Bluetooth LE devices are not capable of sending back all
        # descriptors in one packet due to the limited size of MTU. So the
        # guest needs to check the response and make retries until all handles
        # are returned.
        # In bluez 5.25 and later, gatt_discover_desc() in attrib/gatt.c does
        # the retry so bluetooth_helper always returns a full list.
        # This was broken in earlier versions.
        response = self._get_resp('desc')
        ndesc = len(response['hnd'])
        return [Descriptor(self, response['uuid'][i], response['hnd'][i])
                for i in range(ndesc)]

    def read_characteristic(self, handle):
        self._write_cmd(f'rd {handle:X}\n')
        response = self._get_resp('rd')
        return response['d'][0]

    def _read_characteristic_by_uuid(self, uuid, start_handle, end_handle):
        # Not used at present
        self._write_cmd(f'rdu {UUID(uuid)} {start_handle:X} {end_handle:X}\n')
        return self._get_resp('rd')

    def write_characteristic(self,
                             handle,
                             val,
                             with_response=False,
                             timeout=None):
        # Without response, a value too long for one packet will be truncated,
        # but with response, it will be sent as a queued write
        cmd = 'wrr' if with_response else 'wr'
        self._write_cmd(
            '{} {:X} {}'.format(
                cmd,
                handle,
                binascii.b2a_hex(val).decode('utf-8')
            )
        )
        return self._get_resp('wr', timeout)

    def set_security_level(self, level):
        self._write_cmd(f'secu {level}\n')
        return self._get_resp('stat')

    def unpair(self):
        self._mgmt_cmd('unpair')

    def pair(self):
        self._mgmt_cmd('pair')

    def get_mtu(self):
        return self._mtu

    def set_mtu(self, mtu):
        self._write_cmd(f'mtu {mtu:x}\n')
        return self._get_resp('stat')

    def wait_for_notifications(self, timeout):
        return bool(self._get_resp(['ntfy', 'ind'], timeout))

    def _set_remote_oob(self, address, address_type, oob_data, iface=None):
        if self._helper is None:
            self._start_helper(iface)
        self.addr = address
        self.addr_type = address_type
        self.iface = iface
        cmd = 'remote_oob ' + address + ' ' + address_type
        if oob_data['C_192'] is not None and oob_data['R_192'] is not None:
            cmd += ' C_192 {} R_192 {}'.format(oob_data['C_192'],
                                               oob_data['R_192'])
        if oob_data['C_256'] is not None and oob_data['R_256'] is not None:
            cmd += ' C_256 {} R_256 {}'.format(oob_data['C_256'],
                                               oob_data['R_256'])
        if iface is not None:
            cmd += ' hci' + str(iface)
        self._write_cmd(cmd)

    def set_remote_oob(self, address, address_type, oob_data, iface=None):
        if len(address.split(':')) != 6:
            raise ValueError(f'Expected MAC address, got {addr!r}')

        if address_type not in (ADDR_TYPE_PUBLIC, ADDR_TYPE_RANDOM):
            raise ValueError(
                f'Expected address type public or random, got {address_type}'
            )

        if isinstance(address, ScanEntry):
            return self._set_remote_oob(address.addr,
                                        address.addr_type,
                                        oob_data,
                                        address.iface)

        if address is not None:
            return self._set_remote_oob(address, address_type, oob_data, iface)

        # Missing return here!

    def get_local_oob(self, iface=None):
        if self._helper is None:
            self._start_helper(iface)

        self.iface = iface
        cmd = 'local_oob'

        if iface is not None:
            cmd += ' hci' + str(iface)

        self._write_cmd(cmd + '\n')
        response = self._get_resp('oob')

        if response is None:
            raise BluepyManagementError('Failed to get local OOB response.')

        data = response.get('d', [''])[0]
        if data is None:
            raise BluepyManagementError('Failed to get local OOB data.')

        if struct.unpack_from('<B', data, 0)[0] != 8 or \
           struct.unpack_from('<B', data, 1)[0] != 0x1b:
            raise BluepyManagementError(
                'Malformed local OOB data (address).'
            )

        address = data[2:8]
        address_type = data[8:9]
        if struct.unpack_from('<B', data, 9)[0] != 2 or \
           struct.unpack_from('<B', data, 10)[0] != 0x1c:
            raise BluepyManagementError('Malformed local OOB data (role).')

        role = data[11:12]
        if struct.unpack_from('<B', data, 12)[0] != 17 or \
           struct.unpack_from('<B', data, 13)[0] != 0x22:
            raise BluepyManagementError(
                'Malformed local OOB data (confirm).'
            )
        confirm = data[14:30]
        if struct.unpack_from('<B', data, 30)[0] != 17 or \
           struct.unpack_from('<B', data, 31)[0] != 0x23:
            raise BluepyManagementError(
                            'Malformed local OOB data (random).')
        random = data[32:48]
        if struct.unpack_from('<B', data, 48)[0] != 2 or \
           struct.unpack_from('<B', data, 49)[0] != 0x1:
            raise BluepyManagementError(
                            'Malformed local OOB data (flags).')
        flags = data[50:51]
        return {
            'Address': ''.join(['%02X' % struct.unpack('<B', c)[0]
                                for c in address]),
            'Type': ''.join(['%02X' % struct.unpack('<B', c)[0]
                             for c in address_type]),
            'Role': ''.join(['%02X' % struct.unpack('<B', c)[0]
                             for c in role]),
            'C_256': ''.join(['%02X' % struct.unpack('<B', c)[0]
                              for c in confirm]),
            'R_256': ''.join(['%02X' % struct.unpack('<B', c)[0]
                              for c in random]),
            'Flags': ''.join(['%02X' % struct.unpack('<B', c)[0]
                              for c in flags]),
        }

    def __del__(self):
        self.disconnect()


class ScanEntry:
    addr_types = {
        1: ADDR_TYPE_PUBLIC,
        2: ADDR_TYPE_RANDOM
    }

    FLAGS = 0x01
    INCOMPLETE_16B_SERVICES = 0x02
    COMPLETE_16B_SERVICES = 0x03
    INCOMPLETE_32B_SERVICES = 0x04
    COMPLETE_32B_SERVICES = 0x05
    INCOMPLETE_128B_SERVICES = 0x06
    COMPLETE_128B_SERVICES = 0x07
    SHORT_LOCAL_NAME = 0x08
    COMPLETE_LOCAL_NAME = 0x09
    TX_POWER = 0x0A
    SERVICE_SOLICITATION_16B = 0x14
    SERVICE_SOLICITATION_32B = 0x1F
    SERVICE_SOLICITATION_128B = 0x15
    SERVICE_DATA_16B = 0x16
    SERVICE_DATA_32B = 0x20
    SERVICE_DATA_128B = 0x21
    PUBLIC_TARGET_ADDRESS = 0x17
    RANDOM_TARGET_ADDRESS = 0x18
    APPEARANCE = 0x19
    ADVERTISING_INTERVAL = 0x1A
    MANUFACTURER = 0xFF

    dataTags = {
        FLAGS: 'Flags',
        INCOMPLETE_16B_SERVICES: 'Incomplete 16b Services',
        COMPLETE_16B_SERVICES: 'Complete 16b Services',
        INCOMPLETE_32B_SERVICES: 'Incomplete 32b Services',
        COMPLETE_32B_SERVICES: 'Complete 32b Services',
        INCOMPLETE_128B_SERVICES: 'Incomplete 128b Services',
        COMPLETE_128B_SERVICES: 'Complete 128b Services',
        SHORT_LOCAL_NAME: 'Short Local Name',
        COMPLETE_LOCAL_NAME: 'Complete Local Name',
        TX_POWER: 'Tx Power',
        SERVICE_SOLICITATION_16B: '16b Service Solicitation',
        SERVICE_SOLICITATION_32B: '32b Service Solicitation',
        SERVICE_SOLICITATION_128B: '128b Service Solicitation',
        SERVICE_DATA_16B: '16b Service Data',
        SERVICE_DATA_32B: '32b Service Data',
        SERVICE_DATA_128B: '128b Service Data',
        PUBLIC_TARGET_ADDRESS: 'Public Target Address',
        RANDOM_TARGET_ADDRESS: 'Random Target Address',
        APPEARANCE: 'Appearance',
        ADVERTISING_INTERVAL: 'Advertising Interval',
        MANUFACTURER: 'Manufacturer',
    }

    def __init__(self, addr, iface):
        self.addr = addr
        self.iface = iface
        self.addr_type = None
        self.rssi = None
        self.connectable = False
        self.raw_data = None
        self.scan_data = {}
        self.update_count = 0

    def _update(self, response):
        addr_type = self.addr_types.get(response['type'][0], None)
        if (self.addr_type is not None) and (addr_type != self.addr_type):
            raise BluepyInternalError(
                f'Address type changed during scan, for address {self.addr}'
            )
        self.addr_type = addr_type
        self.rssi = -response['rssi'][0]
        self.connectable = ((response['flag'][0] & 0x4) == 0)
        data = response.get('d', [''])[0]
        self.raw_data = data

        # Note: bluez is notifying devices twice: once with advertisement data,
        # then with scan response data. Also, the device may update the
        # advertisement or scan data
        is_new_data = False
        while len(data) >= 2:
            sdlen, sdid = struct.unpack_from('<BB', data)
            val = data[2:sdlen + 1]
            if (sdid not in self.scan_data) or (val != self.scan_data[sdid]):
                is_new_data = True
            self.scan_data[sdid] = val
            data = data[sdlen + 1:]

        self.update_count += 1
        return is_new_data

    def _decode_uuid(self, val, nbytes):
        if len(val) < nbytes:
            return None
        bval = bytearray(val)
        ret = ''
        # Bytes are little-endian; convert to big-endian string
        for i in range(nbytes):
            ret = ('%02X' % bval[i]) + ret
        return UUID(ret)

    def _decode_uuid_list(self, val, nbytes):
        result = []
        for i in range(0, len(val), nbytes):
            if len(val) >= (i+nbytes):
                result.append(self._decode_uuid(val[i:i+nbytes], nbytes))
        return result

    def get_description(self, sdid):
        return self.dataTags.get(sdid, hex(sdid))

    def get_value(self, sdid):
        val = self.scan_data.get(sdid, None)
        if val is None:
            return None

        if sdid in [ScanEntry.SHORT_LOCAL_NAME, ScanEntry.COMPLETE_LOCAL_NAME]:
            try:
                # Beware! Vol 3 Part C 18.3 doesn't give an encoding. Other
                # references to 'local name' (e.g. vol 3 E, 6.23) suggest it is
                # UTF-8 but in practice devices sometimes have garbage here.
                # See #259, #275, #292.
                return val.decode('utf-8')
            except UnicodeDecodeError:
                bbval = bytearray(val)
                return ''.join([(chr(x) if (32 <= x <= 127) else '?')
                                for x in bbval])

        if sdid in [ScanEntry.INCOMPLETE_16B_SERVICES,
                    ScanEntry.COMPLETE_16B_SERVICES]:
            return self._decode_uuid_list(val, 2)

        if sdid in [ScanEntry.INCOMPLETE_32B_SERVICES,
                    ScanEntry.COMPLETE_32B_SERVICES]:
            return self._decode_uuid_list(val, 4)

        if sdid in [ScanEntry.INCOMPLETE_128B_SERVICES,
                    ScanEntry.COMPLETE_128B_SERVICES]:
            return self._decode_uuid_list(val, 16)

        return val

    def get_value_text(self, sdid):
        val = self.get_value(sdid)
        if val is None:
            return None

        if sdid in [ScanEntry.SHORT_LOCAL_NAME, ScanEntry.COMPLETE_LOCAL_NAME]:
            return val

        if isinstance(val, list):
            return ', '.join(str(v) for v in val)

        return binascii.b2a_hex(val).decode('ascii')

    def get_scan_data(self):
        """Returns list of tuples [(tag, description, value)]"""
        return [(sdid, self.get_description(sdid), self.get_value_text(sdid))
                for sdid in self.scan_data]


class Scanner(BluepyHelper):
    def __init__(self, iface=0, delegate=None):
        self.scanned = {}
        self.iface = iface
        self.passive = False
        super().__init__(delegate=delegate)

    def _cmd(self):
        return 'pasv' if self.passive else 'scan'

    def start(self, passive=False):
        self.passive = passive
        self._start_helper(iface=self.iface)
        self._mgmt_cmd('le on')
        self._write_cmd(self._cmd() + '\n')
        response = self._wait_response('mgmt')
        if response['code'][0] == 'success':
            return
        # Sometimes previous scan still ongoing
        if response['code'][0] == 'busy':
            self._mgmt_cmd(self._cmd() + 'end')
            response = self._wait_response('stat')
            assert response['state'][0] == 'disc'
            self._mgmt_cmd(self._cmd())

    def stop(self):
        self._mgmt_cmd(self._cmd()+'end')
        self._stop_helper()

    def clear(self):
        self.scanned = {}

    def process(self, timeout=10.0):
        if self._helper is None:
            raise BluepyInternalError(
                'Helper not started (did you call start()?)'
            )
        start = time.time()
        while True:
            if timeout:
                remain = start + timeout - time.time()
                if remain <= 0.0:
                    break
            else:
                remain = None
            response = self._wait_response(['scan', 'stat'], remain)
            if response is None:
                break

            response_type = response['rsp'][0]
            if response_type == 'stat':
                # if scan ended, restart it
                if response['state'][0] == 'disc':
                    self._mgmt_cmd(self._cmd())

            elif response_type == 'scan':
                addr = binascii.b2a_hex(response['addr'][0]).decode('utf-8')
                addr = ':'.join([addr[i:i + 2] for i in range(0, 12, 2)])
                if addr in self.scanned:
                    print(f'device found {addr} NOK')
                    dev = self.scanned[addr]
                else:
                    print(f'device found {addr} OK')
                    dev = ScanEntry(addr, self.iface)
                    self.scanned[addr] = dev
                is_new_data = dev._update(response)
                if self.delegate is not None:
                    self.delegate.discovery_handler(dev,
                                                    (dev.update_count <= 1),
                                                    is_new_data)
            else:
                raise BluepyInternalError(
                    'Unexpected response: ' + response_type,
                    response
                )

    def get_devices(self):
        print(*self.scanned.keys())
        return self.scanned.values()

    def scan(self, timeout=10, passive=False):
        self.clear()
        self.start(passive=passive)
        self.process(timeout)
        self.stop()
        return self.get_devices()
