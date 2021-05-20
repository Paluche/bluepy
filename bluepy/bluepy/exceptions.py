"""
Exceptions for the bluepy module.
"""


class BluepyError(Exception):
    """Base class for all Bluepy exceptions."""
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
    """Internal bluepy error."""
    def __init__(self, message, response=None):
        BluepyError.__init__(self, message, response)


class BluepyDisconnectError(BluepyError):
    """BLE service has disconnected."""
    def __init__(self, message, response=None):
        BluepyError.__init__(self, message, response)


class BluepyManagementError(BluepyError):
    """BLE Management error."""
    def __init__(self, message, response=None):
        BluepyError.__init__(self, message, response)


class BluepyGattError(BluepyError):
    """BLE GATT error."""
    def __init__(self, message, response=None):
        BluepyError.__init__(self, message, response)
