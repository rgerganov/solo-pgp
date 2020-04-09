#!/usr/bin/env python3
import os
import sys
from fido2.hid import CtapHidDevice
from common import SoloPGP

if __name__ == '__main__':
    # check if this is sign operation
    for arg in sys.argv[1:]:
        if arg == '--sign' or (arg.startswith('-') and not arg.startswith('--') and 's' in arg):
            hid_devices = list(CtapHidDevice.list_devices())
            dev = hid_devices[0]
            solo = SoloPGP(dev)
            # assume the key ID is the last argument, this might be wrong ...
            key_id = sys.argv[-1]
            data = sys.stdin.buffer.read()
            solo.sign(key_id, data)
            break
    else:
        # not a sign operation, delegate to gpg
        os.execvp('gpg', ['gpg'] + sys.argv[1:])
