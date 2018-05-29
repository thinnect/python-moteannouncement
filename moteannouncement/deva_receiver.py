"""deva_receiver.py: DeviceAnnouncement receiver with query capabilities"""
from __future__ import print_function, unicode_literals

import time
from itertools import chain
from collections import OrderedDict

from enum import Enum
from six.moves import queue as Queue
import six

from moteconnection.message import MessageDispatcher, Message
from moteconnection.connection import Connection

from .deva_packets import (
    DeviceAnnouncementPacket, DeviceFeaturesPacket, DeviceDescriptionPacket,
    DeviceRequestPacket, DeviceFeatureRequestPacket, DeviceAnnouncementPacketV2,
    ANNOUNCEMENT_PACKETS
)

import logging
log = logging.getLogger(__name__)


__author__ = "Raido Pahtma"
__license__ = "MIT"


class NetworkAddressTranslator(dict):
    """
    An object to hold a guid to network address mappings.
    """
    def __init__(self):
        super(NetworkAddressTranslator, self).__init__()
        # FIXME: This should not hold that much memory, but will not be cleared, ever
        self._original_data = {}

    def __getitem__(self, key):
        assert isinstance(key, six.string_types) and len(key) == 16

        try:
            return super(NetworkAddressTranslator, self).__getitem__(key)
        except KeyError:
            log.warning(
                "Unknown GUID {}. Using default mapping of last four digits: {}".format(
                    key, key[-4:]
                )
            )
            return int(key[-4:], 16)

    def add_info(self, source, packet):
        assert isinstance(packet, ANNOUNCEMENT_PACKETS)
        guid = six.binary_type(packet.guid.serialize()).encode("hex").upper()
        if guid not in self or self[guid] != source:
            self[guid] = source
        self._original_data[guid] = packet      # Can be used to display latest uptime, announcement etc.

    @property
    def announcements(self):
        """
        :rtype: dict[six.text_type, DeviceAnnouncementPacket]
        """
        return dict(self._original_data)


@six.python_2_unicode_compatible
class Query(object):

    class State(Enum):
        __order__ = 'query describe list_features done'     # only needed in 2.x
        query = "query"
        describe = "describe"
        list_features = "list_features"
        done = "done"

    def __init__(self, destination, requests, mapping, retry=10):
        self._retry = retry
        # TODO: seems like a hack that obfuscates what's going on
        # if we have no device information from said node, we should request it first
        if destination not in mapping:
            if Query.State.query not in requests:
                requests = [Query.State.query] + requests
        self._states = requests
        self._request = list(requests)
        self._destination = destination
        self._mapping = mapping
        self.state = self._states.pop(0) if self._states else self.State.done
        self._offset = 0
        self._outgoing_buffer = [self._construct_message()]
        self._incoming_messages = []
        self._last_contact = (
            mapping.announcements[destination].arrived
            if destination in mapping.announcements else
            None
        )

    @property
    def destination(self):
        return self._destination

    @property
    def destination_address(self):
        return self._mapping[self._destination]

    @property
    def last_contact(self):
        return self._last_contact.isoformat() if self._last_contact is not None else None

    def get_message(self):
        """
        Returns an outgoing message

        :return: Message to be sent
        :rtype: moteconnection.message.Message | None
        """
        if self.state is not Query.State.done:
            now = time.time()
            try:
                outgoing = self._outgoing_buffer[0]
            except IndexError:
                return None

            if outgoing["taken_at"] <= now - self._retry:
                outgoing["taken_at"] = now
                return outgoing["message"]

        return None

    def _construct_message(self):
        """
        Returns the correct outgoing message or None

        :return:
        """
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

        :param packet:
        :type packet: DeviceAnnouncementPacket | DeviceAnnouncementPacketV2 | DeviceDescriptionPacket | DeviceFeaturesPacket
        :return: List of packets to emit
        :rtype: None | list[DeviceAnnouncementPacket | DeviceAnnouncementPacketV2 | DeviceDescriptionPacket | DeviceFeaturesPacket]
        """

        if (
                isinstance(packet, ANNOUNCEMENT_PACKETS) and
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

        if not isinstance(packet, ANNOUNCEMENT_PACKETS):
            if not self._incoming_messages:
                self._incoming_messages = [self._mapping.announcements[self._destination]]
        self._incoming_messages.append(packet)
        self._last_contact = packet.arrived

        if self.state is not self.State.done:
            m = self._construct_message()
            if m is not None:
                self._outgoing_buffer[0] = m
        else:
            return self._incoming_messages

    def __str__(self):
        states = " -> ".join(
            "<{}>".format(s.name) if s == self.state else "{}".format(s.name)
            for s in chain(self._request, [Query.State.done])
        )
        return 'Query(destination={}, state=[{}])'.format(self._destination, states)


class DAReceiver(object):
    """
    :type address: six.text_type
    :type _pending_queries: dict[int, Query]
    """

    def __init__(self, connection_string, address, period, mapping=NetworkAddressTranslator()):
        """

        :param six.text_type connection_string: Connection string, like sf@localhost:9002 or
                serial@/dev/ttyUSB0:115200
        :param int address: The network address of the MURP on the gateway (eg 0x0310)
        :param int period: The period of
        :param mapping:
        """
        self.address = address
        self._connection_string = connection_string

        self._connection = None
        self._dispatcher = None

        self._incoming = Queue.Queue()

        self._timestamp = time.time()

        self.period = period
        self._last_pass_received = False

        self._pending_queries = OrderedDict()
        self._network_address_mapping = mapping

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
        assert self.connection is not None  # creates and establishes the connection
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.connection.join()

    def poll(self):
        """

        :return:
        :rtype: None | list[DeviceAnnouncementPacket | DeviceDescriptionPacket | DeviceFeaturesPacket]
        """
        # Remove queries that are done
        for destination, query in dict(self._pending_queries).items():
            if query.state is Query.State.done:
                del self._pending_queries[destination]

        # Select a semi-random query to
        if self._pending_queries:
            if time.time() - self._timestamp > self.period or self._last_pass_received:
                out_message = None
                for destination_address, query in self._pending_queries.items():
                    # rotate the queries
                    del self._pending_queries[destination_address]
                    self._pending_queries[destination_address] = query

                    # check if the query has an outgoing message ready
                    out_message = query.get_message()
                    if out_message is not None:
                        break

                if out_message is not None:
                    log.debug(out_message)
                    self.connection.send(out_message)

                self._timestamp = time.time()
            self._last_pass_received = False

        try:
            incoming_message = self._incoming.get(timeout=0.1)
        except Queue.Empty:
            pass
        else:
            log.debug(incoming_message)
            try:
                packet = self._deserialize(incoming_message)
            except ValueError:
                log.exception("Error deserializing incoming packet: %s", incoming_message)
            else:

                if isinstance(packet, ANNOUNCEMENT_PACKETS):
                    self._network_address_mapping.add_info(incoming_message.source, packet)

                # if this packet belongs to a pending query, let it decide
                if incoming_message.source in self._pending_queries:
                    return_value = self._pending_queries[incoming_message.source].receive_packet(packet)
                    self._last_pass_received = True
                    if return_value is not None:
                        del self._pending_queries[incoming_message.source]
                # otherwise emit it
                else:
                    #  Should be a DeviceAnnouncementPacket, but other agents may also be requesting data
                    if isinstance(packet, ANNOUNCEMENT_PACKETS):
                        return_value = [packet]
                    else:
                        return_value = None

                return return_value

    def query(self, destination, info=False, description=False, features=False):
        if (
                destination not in self._pending_queries or
                self._pending_queries[destination].state is not Query.State.done
        ):
            requests = []
            if info:
                requests.append(Query.State.query)
            if description:
                requests.append(Query.State.describe)
            if features:
                requests.append(Query.State.list_features)

            query = Query(destination, requests, self._network_address_mapping, self.period)
            self._pending_queries[query.destination_address] = query
        else:
            log.warning("Active query already exists for %s", destination)

    @property
    def active_queries(self):
        return OrderedDict([
            (query.destination, query)
            for query in self._pending_queries.values()
            if query.state is not Query.State.done
        ])

    @property
    def announcements(self):
        return self._network_address_mapping.announcements

    @staticmethod
    def _deserialize(message):
        """

        :param moteconnection.message.Message message: incoming message
        :raises ValueError: When unable to deserialize
        :rtype: DeviceAnnouncementPacket | DeviceAnnouncementPacketV2 | DeviceDescriptionPacket | DeviceFeaturesPacket
        :returns: Deserialized packet
        """
        if len(message.payload) > 0:
            ptp = ord(message.payload[0])
            if ptp == DeviceAnnouncementPacket.DEVA_ANNOUNCEMENT:
                version = ord(message.payload[1])
                if version == 1:
                    packet = DeviceAnnouncementPacket()
                elif version == 2:
                    packet = DeviceAnnouncementPacketV2()
                else:
                    raise ValueError('Unknown packet %s', message)
            elif ptp == DeviceDescriptionPacket.DEVA_DESCRIPTION:
                packet = DeviceDescriptionPacket()
            elif ptp == DeviceFeaturesPacket.DEVA_FEATURES:
                packet = DeviceFeaturesPacket()

            else:
                log.warning("header %s", ptp)
                raise ValueError("header {}".format(ptp))

            try:
                packet.deserialize(message.payload)
            except ValueError:
                log.exception("Malformed packet: %s", message)
                raise
        else:
            raise ValueError("len 0")

        return packet
