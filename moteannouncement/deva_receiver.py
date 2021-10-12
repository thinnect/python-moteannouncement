"""deva_receiver.py: DeviceAnnouncement receiver with query capabilities"""

__copyright__ = "Thinnect Inc. 2021"
__author__ = "Raido Pahtma, Kaarel Ratas"
__license__ = "MIT"

from codecs import decode, encode
from collections import OrderedDict
import time

import queue

from mistconnection.connection import Connection as MistConnection
from mistconnection.message import Message as MistMessage

from moteconnection.message import MessageDispatcher, Message as MoteMessage
from moteconnection.connection import Connection as MoteConnection
from serdepa.exceptions import DeserializeError

from mistconnection.eui64 import EUI64

from .announcer import Announcer
from .deva_packets import deserialize, DeviceAnnouncementPacketBase
from .deva_packets.v2 import DeviceAnnouncementPacket
from .query import Query
from .response import Response
from .utils import FeatureMap

import logging
log = logging.getLogger(__name__)


class NetworkAddressTranslator(dict):
    """
    An object to hold a guid to network address mappings and latest packet that
    updated the mapping.
    """
    def __init__(self):
        super(NetworkAddressTranslator, self).__init__()
        # FIXME: This should not hold that much memory, but will not be cleared, ever
        self._original_data = {}

    def __getitem__(self, key):
        if isinstance(key, EUI64):
            try:
                return super(NetworkAddressTranslator, self).__getitem__(key)
            except KeyError:
                log.warning("Unknown GUID %s. Using default mapping of last four digits: %s", key, str(key)[-4:])
                return int(str(key)[-4:], 16)
        elif isinstance(key, int):
            try:
                return super(NetworkAddressTranslator, self).__getitem__(key)
            except KeyError:
                log.warning("Unknown address %04X. Returning None", key)
                return None
        raise TypeError("Address translator requires GUID or integer address!")

    def add_info(self, source, packet):
        assert isinstance(packet, DeviceAnnouncementPacketBase)

        guid = EUI64(packet.guid.serialize().hex())  # FIXME there should be an easier way?
        if guid not in self or self[guid] != source:
            self[guid] = source
            self[source] = guid
        self._original_data[guid] = packet      # Can be used to display latest uptime, announcement etc.

    @property
    def announcements(self):
        """
        :rtype: dict[EUI64, DeviceAnnouncementPacket | DeviceAnnouncementPacketV2]
        """
        return dict(self._original_data)


class MistAddressTranslator(dict):
    """
    An object to use in place of NetworkAddressTranslator when translation not needed.
    """
    def __init__(self):
        super(MistAddressTranslator, self).__init__()
        self._original_data = {}

    def __getitem__(self, key):
        return key

    def add_info(self, source, packet):
        assert isinstance(packet, DeviceAnnouncementPacketBase)
        self._original_data[source] = packet

    @property
    def announcements(self):
        return dict(self._original_data)


class DAReceiver(object):
    """
    :type address: int, EUI64
    :type _pending_queries: dict[int, Query]
    """

    def __init__(self, connection, address, group, period, mapping=None):
        """
        :param ??? connection: A connection object.
        :param int address: The network address of the MURP on the gateway (eg 0x0310)
        :param int period: The period of
        :param mapping:
        """

        self.address = address
        self.group = group

        self._incoming = queue.Queue()

        if isinstance(connection, MistConnection):
            connection.register_receiver(0x3FDA, self._incoming)
            self._dispatcher = connection
            if mapping is None:
                mapping = MistAddressTranslator()
        elif isinstance(connection, MoteConnection):
            self._dispatcher = MessageDispatcher(self.address, self.group)
            self._dispatcher.register_receiver(0xDA, self._incoming)
            connection.register_dispatcher(self._dispatcher)
            if mapping is None:
                mapping = NetworkAddressTranslator()
        else:
            raise ValueError("Connection type not recognized!")

        self._connection = connection

        self._timestamp = time.time()

        self.period = period
        self._last_pass_received = False

        self._pending_queries = OrderedDict()
        self._network_address_mapping = mapping
        self.feature_map = FeatureMap()

        self._announcer = Announcer()

        self._connected = True   # FIXME register connect event

    @property
    def mapping(self):
        return self._network_address_mapping

    @property
    def connection_established(self):
        return self._connected

    def connected(self):
        self._connected = True

    def disconnected(self):
        self._connected = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def poll(self):
        """
        :return:
        :rtype: None | moteannouncement.response.Response
        """
        # Skip everything if connection is down.
        if not self.connection_established:
            log.debug('Connection not established. Waiting.')
            time.sleep(0.1)
            return

        # Handle self announcement
        try:
            announcement_message = self._announcer.announce()
        except Exception:
            log.exception('Exception while generating self-announcement for the Mist(tm) network.')
        else:
            pass
            # TODO fixme addressing etc
            if announcement_message is not None:
                log.info('Sending announcement to the Mist(tm) network.')
                self._connection.send(announcement_message)

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
                        if isinstance(self._connection, MistConnection):
                            mm = MistMessage()
                            mm.amid = 0x3FDA
                            mm.destination = out_message[0]
                            mm.payload = out_message[1]
                            out_message = mm
                        else:
                            out_message = MoteMessage(0xDA, out_message[0], out_message[1])
                        break

                if out_message is not None:
                    log.debug("Outgoing message: %s", out_message)
                    self._connection.send(out_message)

                self._timestamp = time.time()
            self._last_pass_received = False

        try:
            incoming_message = self._incoming.get(timeout=0.1)
        except queue.Empty:
            pass
        else:
            log.debug("Incoming message: %s", incoming_message)
            try:
                packet = self._deserialize(incoming_message)
            except (ValueError, DeserializeError):
                log.exception("Error deserializing incoming packet: %s", incoming_message)
            else:

                log.debug("Incoming packet: (%s) %s", packet.__class__.__name__, packet)
                if isinstance(packet, DeviceAnnouncementPacketBase):
                    self._network_address_mapping.add_info(incoming_message.source, packet)

                response = None
                guid = EUI64(packet.guid.serialize().hex())
                # if this packet belongs to a pending query, let it decide
                if guid in self._pending_queries:
                    log.debug("guid")
                    response = self._pending_queries[guid].receive_packet(packet)
                # Fall back to the source address as key
                elif incoming_message.source in self._pending_queries:
                    log.debug("source")
                    response = self._pending_queries[incoming_message.source].receive_packet(packet)
                # otherwise emit it
                # Should be a DeviceAnnouncementPacket, but other agents may also be requesting data
                elif isinstance(packet, DeviceAnnouncementPacketBase):
                    log.debug("random")
                    response = Response([packet])

                # Make sure to remember the feature_list_hash -> features combination for future reference
                if response is not None and response.features is not None:
                    self.feature_map[response.feature_list_hash] = response.features

                return response

    def query(self, guid=None, addr=None, info=False, description=False, features=False):
        if guid is None and addr is None or guid is not None and addr is not None:
            raise ValueError("Provide either guid or address.")

        if guid is not None:
            guid = EUI64(guid)

        destination = guid if guid is not None else addr
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

            query = Query(guid, addr, requests, self._network_address_mapping, self.feature_map, self.period)
            if destination not in self._pending_queries or not self._pending_queries[destination].is_equivalent(query):
                log.debug('Adding query %s.', query)
                self._pending_queries[destination] = query
        else:
            log.warning("Active query already exists for %s", destination)

    def setup_announcement(self, guid, uuid,
                           position_type=None, latitude=None, longitude=None, elevation=None,
                           radio_technology=None, feature_list=None,
                           radio_channel=None, ident_timestamp=None):
        """
        Sends out an announcement packet to the network.
        :param str guid: EUI64 of the radio module
        :param uuid.UUID uuid: The UUID of the device
        :param str position_type: The position type (F:fix, C:central(special F), G:gps, L:local, A:area, U:unknown)
        :param int latitude: Millionths of degrees latitude
        :param int longitude: Millionths of degrees longitude
        :param int elevation: Metres elevation
        :param moteannouncement.RadioTechnologies radio_technology: The radio technology of the radio module
        :param int radio_channel: The radio channel of the radio module
        :param int ident_timestamp: The identification timestamp of this device
        :param list[uuid.UUID] feature_list: The feature list
        :return:
        """
        if self._announcer.guid is None:
            self._announcer.guid = EUI64(guid)
            self._announcer.uuid = uuid
            if position_type is not None:
                self._announcer.position_type = position_type
            if latitude is not None:
                self._announcer.latitude = latitude
            if longitude is not None:
                self._announcer.longitude = longitude
            if elevation is not None:
                self._announcer.elevation = elevation
            if radio_technology is not None:
                self._announcer.radio_technology = radio_technology
            if radio_channel is not None:
                self._announcer.radio_channel = radio_channel
            if ident_timestamp is not None:
                self._announcer.ident_timestamp = ident_timestamp
            if feature_list is not None:
                self._announcer.features = feature_list

        return self._announcer

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
            try:
                packet = deserialize(message.payload)
            except (ValueError, DeserializeError):
                log.exception("Malformed packet: %s", message)
                raise
        else:
            raise ValueError("len 0")

        return packet
