"""deva_receiver.py: DeviceAnnouncement receiver with query capabilities"""
from __future__ import print_function

import time

from enum import Enum
from six.moves import queue as Queue

from moteconnection.message import MessageDispatcher, Message
from moteconnection.connection import Connection

from .deva_packets import (
    DeviceAnnouncementPacket, DeviceFeaturesPacket, DeviceDescriptionPacket,
    DeviceRequestPacket, DeviceFeatureRequestPacket
)

import logging
log = logging.getLogger(__name__)


__author__ = "Raido Pahtma"
__license__ = "MIT"


class Query(object):

    class State(Enum):
        __order__ = 'query describe list_features done'     # only needed in 2.x
        query = "query"
        describe = "describe"
        list_features = "list_features"
        done = "done"

    def __init__(self, destination, requests, retry=10):
        self._retry = retry
        self._states = requests
        self._destination = destination
        self.state = self._states.pop(0) if self._states else self.State.done
        self._offset = 0
        self._outgoing_buffer = [self._construct_message()]

    @property
    def destination(self):
        return self._destination

    @property
    def destination_address(self):
        # TODO: destination network address discovery
        return int(self._destination[-4:], 16)

    def get_message(self):
        """
        Returns an outgoing message

        :return: Message to be sent
        :rtype: moteconnection.message.Message | None
        """
        try:
            outgoing = self._outgoing_buffer[0]
            if outgoing["taken_at"] < time.time() - self._retry:
                return outgoing["message"]
            else:
                return None
        except IndexError:
            return None

    def _construct_message(self):
        """
        Returns the correct outgoing message or None

        :return:
        """
        # TODO: RETRIES!
        if self.state == self.State.query:
            d = DeviceRequestPacket()
        elif self.state == self.State.describe:
            d = DeviceRequestPacket(DeviceRequestPacket.DEVA_DESCRIBE)
        elif self.state == self.State.list_features:
            d = DeviceFeatureRequestPacket(self._offset)
        else:
            d = None
        if d is not None:
            return {
                "message": Message(0xDA, self.destination_address, d.serialize()),
                "taken_at": 0
            }

    def receive_packet(self, packet):
        """

        :param DeviceAnnouncementPacket | DeviceDescriptionPacket | DeviceFeaturesPacket packet:
        """

        if (
                isinstance(packet, DeviceAnnouncementPacket) and
                packet.header == DeviceAnnouncementPacket.DEVA_ANNOUNCEMENT
        ):
            if self.state is self.State.query:
                self.state = self._states.pop(0) if self._states else self.State.done
        elif (
                isinstance(packet, DeviceDescriptionPacket) and
                packet.header == DeviceDescriptionPacket.DEVA_DESCRIPTION
        ):
            if self.state is self.State.describe:
                self.state = self._states.pop(0) if self._states else self.State.done
                self._offset = 0
        elif (
                isinstance(packet, DeviceFeaturesPacket) and
                packet.header == DeviceFeaturesPacket.DEVA_FEATURES
        ):

            if self.state is self.State.list_features:
                self._offset = packet.offset + len(packet.features) / 16  # TODO remove 16 when no longer arr

                # if self.offset >= m.total:
                if len(packet.features) == 0:
                    self.state = self._states.pop(0) if self._states else self.State.done
        else:
            raise ValueError("Unknown packet {}".format(packet.__class__.__name__))

        if self.state is not self.State.done:
            m = self._construct_message()
            if m is not None:
                self._outgoing_buffer[0] = m


class DAReceiver(object):
    """
    :type address: six.text_type
    :type _pending_queries: dict[int, Query]
    """

    def __init__(self, connection_string, address, period):
        self.address = address
        self._connection_string = connection_string

        self._connection = None
        self._dispatcher = None

        self._incoming = Queue.Queue()

        self._timestamp = time.time()

        self.period = period

        self._pending_queries = {}

    @property
    def connection(self):
        if self._connection is None:
            self._connection = Connection()
            self._connection.connect(self._connection_string, reconnect=10)
            self._connection.register_dispatcher(self.dispatcher)
        return self._connection

    @property
    def dispatcher(self):
        if self._dispatcher is None:
            self._dispatcher = MessageDispatcher(self.address, 0xFF)
            self._dispatcher.register_receiver(0xDA, self._incoming)
        return self._dispatcher

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.connection.join()

    def poll(self, jump=False):
        # Remove queries that are done
        for destination, query in dict(self._pending_queries).items():
            if query.state is Query.State.done:
                del self._pending_queries[destination]

        # Select a semi-random query to
        if self._pending_queries:
            if time.time() - self._timestamp > self.period:
                out_message = None
                for query in self._pending_queries.values():
                    out_message = query.get_message()
                    if out_message is not None:
                        break

                if out_message is not None:
                    log.debug(out_message)
                    self.connection.send(out_message)

                self._timestamp = time.time()

        try:
            incoming_message = self._incoming.get(timeout=0.1)
            log.debug(incoming_message)
            if len(incoming_message.payload) > 0:
                ptp = ord(incoming_message.payload[0])
                if ptp == DeviceAnnouncementPacket.DEVA_ANNOUNCEMENT:
                    packet = DeviceAnnouncementPacket()
                elif ptp == DeviceDescriptionPacket.DEVA_DESCRIPTION:
                    packet = DeviceDescriptionPacket()
                elif ptp == DeviceFeaturesPacket.DEVA_FEATURES:
                    packet = DeviceFeaturesPacket()

                else:
                    log.warning("header {}".format(ptp))
                    return

                try:
                    packet.deserialize(incoming_message.payload)
                except ValueError:
                    log.exception("Malformed packet: %s", incoming_message)
                else:
                    if incoming_message.source in self._pending_queries:
                        self._pending_queries[incoming_message.source].receive_packet(packet)

                    return packet
            else:
                log.error("len 0")

        except Queue.Empty:
            pass

    def query(self, destination, query_types):
        if (
                destination not in self._pending_queries or
                self._pending_queries[destination].state is not Query.State.done
        ):
            requests = []
            if query_types["info"]:
                requests.append(Query.State.query)
            if query_types["description"]:
                requests.append(Query.State.describe)
            if query_types["features"]:
                requests.append(Query.State.list_features)

            query = Query(destination, requests, self.period)
            self._pending_queries[query.destination_address] = query
        else:
            log.warning("Active query already exists for %s", destination)

    @property
    def active_queries(self):
        return {
            destination: query
            for destination, query in self._pending_queries.items()
            if query.state is not Query.State.done
        }
