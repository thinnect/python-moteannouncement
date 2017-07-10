from __future__ import print_function

import signal
import threading
import time

from argconfparse.argconfparse import arg_hex2int
from simpledaemonlog.logsetup import setup_console, setup_file

from .deva_receiver import DAReceiver
from .utils import strtime


def print_red(s):
    print("\033[91m{}\033[0m".format(s))


def print_green(s):
    print("\033[92m{}\033[0m".format(s))


def main():

    import argparse
    parser = argparse.ArgumentParser(
        description="DEVA Receiver",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("connection", help="Connection string, like sf@localhost:9002 or serial@/dev/ttyUSB0:115200")

    parser.add_argument("--source", default=0x0314, type=arg_hex2int, help="Own address")
    parser.add_argument("--destination", default=None, type=arg_hex2int, help="Ping destination")
    parser.add_argument("--period", default=10, type=int, help="Request period")
    parser.add_argument("--logging", default=None)
    args = parser.parse_args()

    setup_console(color=True, settings=args.logging)
    setup_file("deva_receiver", settings=args.logging)

    interrupted = threading.Event()

    def kbi_handler(sig, frm):
        interrupted.set()

    signal.signal(signal.SIGINT, kbi_handler)

    with DAReceiver(args.connection, args.source, args.period) as dar:

        if args.destination is not None:
            dar.query(
                "70B3D5589001{:04X}".format(args.destination),
                info=False, description=False, features=True
            )

        while not interrupted.is_set():
            time.sleep(0.01)
            packets = dar.poll()
            if packets is not None:
                for packet in packets:
                    print_green("{}| {}| {}".format(strtime(time.time()), packet.__class__.__name__, packet))
                    print_green(dar.announcements)


if __name__ == "__main__":
    main()
