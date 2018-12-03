from codecs import decode
import logging
import time

from moteconnection.message import Message
from uptime import uptime

from moteannouncement.deva_packets.v2 import DeviceAnnouncementPacket, RadioTechnologies


logger = logging.getLogger(__name__)


class Announcer(object):
    """
    Manages the sending and responsing to announcement requests.

    :type guid: str
    :type uuid: uuid.UUID
    :type elevation: int
    :type radio_technology: moteannouncement.RadioTechnologies
    :type radio_channel: int
    :type ident_timestamp: int | float
    :return:
    """
    required_fields = ['guid', 'uuid']

    def __init__(self, announcement_interval=1800):
        self.guid = None

        self.uuid = None

        self._position_type = None
        self._latitude = 0
        self._longitude = 0
        self.elevation = 0

        self.radio_technology = RadioTechnologies.IEEE_802_15_4
        self.radio_channel = 0

        self.ident_timestamp = 0

        self.announcement_interval = announcement_interval

        self._last_announcement = 0
        self._announcement_counter = 1

        self.features = []

    @property
    def boot_number(self):
        """
        The boot number for the device
        :rtype: int
        """
        return 0

    @property
    def boot_time(self):
        """
        The boot time of the device
        :rtype: int
        """
        return time.time() - uptime()

    @property
    def uptime(self):
        """
        Seconds since boot
        :rtype: int
        """
        return uptime()

    @property
    def lifetime(self):
        """
        Cumulative seconds of uptime
        :rtype: int
        """
        return 0

    @property
    def announcement(self):
        """
        The number of announcements since boot
        :rtype: int
        """
        return self._announcement_counter

    @property
    def latitude(self):
        """
        Degrees latitude
        :rtype: float
        """
        return self._latitude / float(1E6)

    @latitude.setter
    def latitude(self, value):
        """
        :param float value: Degrees latitude
        """
        self._latitude = int(value * 1E6)

    @property
    def longitude(self):
        """
        Degrees longitude
        :rtype: float
        """
        return self._longitude / float(1E6)

    @longitude.setter
    def longitude(self, value):
        """
        :param float value: Degrees longitude
        """
        self._longitude = int(value * 1E6)

    @property
    def position_type(self):
        """
        The position type of the device
        :rtype: str
        """
        if self._position_type is None:
            if any([self._latitude, self._longitude, self.elevation]):
                return 'F'
            else:
                return 'U'
        else:
            return self._position_type

    @position_type.setter
    def position_type(self, value):
        """
        :param str value: The position information type [0:unknown(channel info invalid), 1:802.15.4, 2:BLE,
            3:BLE+802.15.4(15.4 channel info), 4:802.11]
        """
        self._position_type = value

    @property
    def feature_list_hash(self):
        value = 0
        # for feature in self.features:
        #     value = crc(value, feature)
        return value

    def announce(self):
        if any(getattr(self, a) is None for a in self.required_fields):
            return
        if time.time() > self._last_announcement + self.announcement_interval:
            packet = DeviceAnnouncementPacket()
            guidstring = decode(self.guid, 'hex')
            for i in range(len(guidstring)):
                try:
                    packet.guid[i] = ord(guidstring[i:i+1])
                except IndexError:
                    packet.guid.append(ord(guidstring[i:i+1]))
            # packet.guid = [ord(byte) for byte in decode(self.guid, 'hex')]
            packet.boot_number = self.boot_number
            packet.boot_time = self.boot_time
            packet.uptime = self.uptime
            packet.lifetime = self.lifetime
            packet.announcement = self.announcement
            for i in range(len(self.uuid.bytes)):
                try:
                    packet.uuid[i] = ord(self.uuid.bytes[i:i+1])
                except IndexError:
                    packet.uuid.append(ord(self.uuid.bytes[i:i+1]))
            packet.position_type = self.position_type
            packet.latitude = self._latitude
            packet.longitude = self._longitude
            packet.elevation = self.elevation
            packet.radio_technology = self.radio_technology
            packet.radio_channel = self.radio_channel
            packet.ident_timestamp = self.ident_timestamp
            packet.feature_list_hash = self.feature_list_hash

            self._announcement_counter += 1
            self._last_announcement = time.time()
            message = Message(0xDA, 0xFFFF, packet.serialize())
            logger.debug('Constructed announcement message: %s', message)
            return message

    def respond(self, incoming_message):
        pass
