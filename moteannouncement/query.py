from itertools import chain
import time
import logging

import six
from enum import Enum

from moteconnection.message import Message

from .deva_packets import (
    DeviceAnnouncementPacketBase, DeviceDescriptionPacketBase, DeviceFeaturesPacketBase,
    DeviceRequestPacketBase, v2
)
from .response import Response


logger = logging.getLogger(__name__)


@six.python_2_unicode_compatible
class Query(object):

    class State(Enum):
        __order__ = 'query describe list_features done'     # only needed in 2.x
        query = "query"
        describe = "describe"
        list_features = "list_features"
        done = "done"

    def __init__(self, guid, addr, requests, mapping, feature_map, retry=10):
        self._retry = retry
        # TODO: seems like a hack that obfuscates what's going on
        # if we have no device information from said node, we should request it first
        if guid is None or guid not in mapping:
            if Query.State.query not in requests:
                requests = [Query.State.query] + requests
        self._states = requests
        self._request = list(requests)
        self._destination = guid
        self._destination_address = addr
        self._mapping = mapping
        self.state = self._states.pop(0) if self._states else self.State.done
        self._offset = 0
        self._outgoing_buffer = [self._construct_message()]
        self._incoming_messages = []
        self._last_contact = (
            mapping.announcements[guid].arrived
            if guid in mapping.announcements else
            None
        )
        self._feature_map = feature_map
        self._known_features = None

    def is_equivalent(self, other):
        """
        Checks whether two Query objects request the same data.
        :param Query other: The other query
        :return: Returns whether the two queries are the same.
        """
        return self._request == other._request

    @property
    def destination(self):
        return self._destination

    @property
    def destination_address(self):
        if self._destination_address is None:
            return self._mapping[self._destination]
        else:
            return self._destination_address

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
        if self.destination_address is not None:
            if self.state is self.State.query:
                d = v2.DeviceRequestPacket()
            elif self.state is self.State.describe:
                d = v2.DeviceRequestPacket(DeviceRequestPacketBase.DEVA_DESCRIBE)
            elif self.state is self.State.list_features:
                d = v2.DeviceFeatureRequestPacket(self._offset)
            else:
                d = None
            if d is not None:
                return {
                    "message": Message(0xDA, self.destination_address, d.serialize()),
                    "taken_at": 0
                }

        return None

    def _advance_state(self):
        self.state = self._states.pop(0) if self._states else self.State.done

    def receive_packet(self, packet):
        """

        :param packet:
        :type packet: DeviceAnnouncementPacketBase | DeviceAnnouncementPacketV2 | DeviceDescriptionPacket |
        DeviceFeaturesPacket
        :return: List of packets to emit
        :rtype: None | Response
        """

        known_packets = (DeviceAnnouncementPacketBase, DeviceDescriptionPacketBase, DeviceFeaturesPacketBase)
        if isinstance(packet, known_packets):
            if (
                    isinstance(packet, DeviceAnnouncementPacketBase) and
                    packet.header == DeviceAnnouncementPacketBase.DEVA_ANNOUNCEMENT and
                    self.state is self.State.query
            ):
                self._advance_state()
            elif (
                    isinstance(packet, DeviceDescriptionPacketBase) and
                    packet.header == DeviceDescriptionPacketBase.DEVA_DESCRIPTION and
                    self.state is self.State.describe
            ):
                self._advance_state()
            elif (
                    isinstance(packet, DeviceFeaturesPacketBase) and
                    packet.header == DeviceFeaturesPacketBase.DEVA_FEATURES and
                    self.state is self.State.list_features
            ):
                self._offset = packet.offset + len(packet.features) / 16  # TODO remove 16 when no longer arr

                # if self.offset >= m.total:
                logger.debug('len(features): %s', len(packet.features))
                if len(packet.features) == 0:
                    self._advance_state()
                logger.debug('self: %s', self)
        else:
            raise ValueError("Unknown packet {}".format(packet.__class__.__name__))

        if not isinstance(packet, DeviceAnnouncementPacketBase) and not self._incoming_messages:
            self._incoming_messages = [self._mapping.announcements[self._destination]]
        self._incoming_messages.append(packet)
        self._last_contact = packet.arrived

        return self._construct_response()

    def _construct_response(self):
        response = None
        # Special case for when we already know the features of the `feature_list_hash`
        if self.state is self.State.list_features:
            if isinstance(self._incoming_messages[0], DeviceAnnouncementPacketBase):
                announcement = self._incoming_messages[0]
            else:
                announcement = self._mapping.announcements[self._destination]
            feature_list_hash = "{:x}".format(announcement.feature_list_hash)
            if feature_list_hash in self._feature_map:
                self._known_features = self._feature_map[feature_list_hash]
                self._advance_state()
        # End special case
        if self.state is not self.State.done:
            m = self._construct_message()
            if m is not None:
                self._outgoing_buffer[0] = m
        else:
            response = Response(self._incoming_messages)
            if self._known_features is not None and response.features is None:
                response.features = self._known_features
        return response

    def __str__(self):
        states = " -> ".join(
            "<{}>".format(s.name) if s == self.state else "{}".format(s.name)
            for s in chain(self._request, [Query.State.done])
        )
        return 'Query(dst={}, state=[{}])'.format(self._destination, states)
