"""deva_receiver.py: DeviceAnnouncement receiver with query capabilities"""
import Queue
import signal
import threading
import time

from argconfparse.argconfparse import arg_hex2int
from moteconnection.connection import Connection
from moteconnection.message import MessageDispatcher, Message
from simpledaemonlog.logsetup import setup_console, setup_file

from moteannouncement.deva_packets import DeviceAnnouncementPacket, DeviceRequestPacket, DeviceDescriptionPacket,\
    DeviceFeaturesPacket, DeviceFeatureRequestPacket, strtime

import logging
log = logging.getLogger(__name__)


__author__ = "Raido Pahtma"
__license__ = "MIT"


def print_red(s):
    print("\033[91m{}\033[0m".format(s))


def print_green(s):
    print("\033[92m{}\033[0m".format(s))


class DAReceiver(object):

    def __init__(self, connection, address, period):
        self.address = address

        self._incoming = Queue.Queue()
        self._dispatcher = MessageDispatcher(self.address, 0xFF)
        self._dispatcher.register_receiver(0xDA, self._incoming)

        self._connection = connection
        self._connection.register_dispatcher(self._dispatcher)

        self._timestamp = time.time()

        self.state = "disabled"
        self._destination = None
        self._offset = 0

        self.period = period

    def poll(self, jump=False):
        if self._destination is not None:
            if time.time() - self._timestamp > self.period:
                if self.state == "query":
                    d = DeviceRequestPacket()
                elif self.state == "describe":
                    d = DeviceRequestPacket(DeviceRequestPacket.DEVA_DESCRIBE)
                elif self.state == "list_features":
                    d = DeviceFeatureRequestPacket(self._offset)
                else:
                    d = None

                if d is not None:
                    msg = Message(0xDA, self._destination, d.serialize())
                    log.debug(msg)
                    self._connection.send(msg)

                self._timestamp = time.time()

        try:
            p = self._incoming.get(timeout=0.1)
            log.debug(p)
            if self._destination is None or self._destination == p.source:
                if len(p.payload) > 0:
                    ptp = ord(p.payload[0])
                    if ptp == DeviceAnnouncementPacket.DEVA_ANNOUNCEMENT:
                        m = DeviceAnnouncementPacket()
                        m.deserialize(p.payload)
                        print_green("{}| {}".format(strtime(time.time()), m))

                        if self.state == "query":
                            self.state = "describe"
                    elif ptp == DeviceDescriptionPacket.DEVA_DESCRIPTION:
                        m = DeviceDescriptionPacket()
                        m.deserialize(p.payload)
                        print_green("{}| {}".format(strtime(time.time()), m))

                        if self.state == "describe":
                            self.state = "list_features"
                            self._offset = 0
                    elif ptp == DeviceFeaturesPacket.DEVA_FEATURES:
                        m = DeviceFeaturesPacket()
                        m.deserialize(p.payload)
                        print_green("{}| {}".format(strtime(time.time()), m))

                        if self.state == "list_features":
                            self._offset = m.offset + len(m.features) / 16  # TODO remove 16 when no longer arr

                            # if self.offset >= m.total:
                            if len(m.features) == 0:
                                self.state = "query"
                    else:
                        log.warning("header {}".format(ptp))
                else:
                    log.error("len 0")

        except Queue.Empty:
            pass

    def query(self, destination):
        self._destination = destination
        self.state = "query"
        self._timestamp = 0


def main():

    import argparse
    parser = argparse.ArgumentParser(description="DEVA Receiver", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
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

    con = Connection()
    con.connect(args.connection, reconnect=10)

    dar = DAReceiver(con, args.source, args.period)

    if args.destination is not None:
        dar.query(args.destination)

    while not interrupted.is_set():
        time.sleep(0.01)
        dar.poll()

    con.disconnect()
    con.join()

if __name__ == "__main__":
    main()
