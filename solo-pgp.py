#!/usr/bin/env python3
import argparse
import os
import sys

from common import SoloPGP
from fido2.hid import CtapHidDevice


if __name__=='__main__':
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--gen-key', action='store_true', help='Generate new PGP key')
    group.add_argument('--list', action='store_true', help='List existing keys')
    group.add_argument('--export', nargs=1, help='Export public key', metavar=('keyid'))
    group.add_argument('--sign', nargs=1, help='Create detached signature', metavar=('keyid'))
    args = parser.parse_args()

    hid_devices = list(CtapHidDevice.list_devices())
    if not hid_devices:
        print("Device not found")
        sys.exit(1)
    dev = hid_devices[0]
    if not os.getenv('SOLOPIN'):
        print("SOLOPIN is not set")
        sys.exit(1)
    solo = SoloPGP(dev)
    if args.gen_key:
        solo.gen_key()
    elif args.list:
        solo.list()
    elif args.export:
        solo.export(*args.export)
    elif args.sign:
        solo.sign(*args.sign, sys.stdin.buffer.read())
