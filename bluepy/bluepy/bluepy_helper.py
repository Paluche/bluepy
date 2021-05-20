"""
Interface with the bluepy_helper executable.
"""

import signal
import os
import logging
import subprocess
from queue import Queue, Empty
from threading import Thread
from . import BluepyError, BluepyGattError

SCRIPT_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)))
HELPER_EXE = os.path.join(SCRIPT_PATH, 'bluepy-helper')

logger = logging.getLogger('bluepy')

if not os.path.isfile(HELPER_EXE):
    raise ImportError(f'Cannot find required executable "{HELPER_EXE}"')


def preexec_function():
    """ Pre-execution function when running the bluepy-helper executable. """
    # Ignore the SIGINT signal by setting the handler to the standard signal
    # handler SIG_IGN.
    signal.signal(signal.SIGINT, signal.SIG_IGN)


class BluepyHelper:
    """

    """
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
