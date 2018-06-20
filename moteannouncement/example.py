"""example.py: Device Announcement protocol example application."""
from __future__ import print_function

import signal
import threading
import time
import sys
import os

from .deva_receiver import DAReceiver
from .utils import strtime

import logging
import logging.config
log = logging.getLogger(__name__)

__author__ = "Kaarel Ratas, Raido Pahtma"
__license__ = "MIT"


def print_red(s):
    if sys.platform == 'win32':
        print(s)
    else:
        print("\033[91m{}\033[0m".format(s))


def print_green(s):
    if sys.platform == 'win32':
        print(s)
    else:
        print("\033[92m{}\033[0m".format(s))


def setup_logging(default_path="", default_level=logging.INFO, env_key='LOG_CFG'):
    path = os.getenv(env_key, None)
    if path is None:
        path = default_path

    if len(path) > 0:
        config = None
        if os.path.exists(path):
            if path.endswith("yaml"):
                with open(path, 'rt') as f:
                    import yaml
                    config = yaml.load(f.read())
            elif path.endswith("json"):
                with open(path, 'rt') as f:
                    import json
                    config = json.load(f)

        if config is not None and len(config) > 0:
            logging.config.dictConfig(config)
            print("Configured logging with settings from from {}".format(path))
        else:
            raise Exception("Unable to load specified logging configuration file {}".format(path))
    else:
        console = logging.StreamHandler()
        console.setLevel(default_level)
        console.setFormatter(logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s'))
        logging.getLogger().addHandler(console)  # add the handler to the root logger
        logging.getLogger().setLevel(default_level)


def main():
    import argparse

    def arg_hex2int(v):
        return int(v, 0)

    parser = argparse.ArgumentParser(
        description="DEVA Receiver",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("destination", default=None, nargs="?", type=arg_hex2int, help="Query destination")
    parser.add_argument("--connection", default="sf@localhost:9002",
                        help="Connection string, like sf@localhost:9002 or serial@/dev/ttyUSB0:115200")
    parser.add_argument("--address", default=0x1234, type=arg_hex2int, help="Own address")
    parser.add_argument("--period", default=10, type=int, help="Request period")
    parser.add_argument("--logging", default=None)
    args = parser.parse_args()

    setup_logging(default_level=logging.NOTSET)

    interrupted = threading.Event()

    def kbi_handler(sig, frm):
        interrupted.set()

    signal.signal(signal.SIGINT, kbi_handler)

    with DAReceiver(args.connection, args.address, args.period) as dar:

        if args.destination is not None:
            dar.query(addr=args.destination,
                      info=False, description=False, features=True)

        while not interrupted.is_set():
            time.sleep(0.01)
            response = dar.poll()
            if response is not None:
                print_green("{}| {}".format(strtime(time.time()), response))


if __name__ == "__main__":
    main()
