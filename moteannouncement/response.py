from codecs import encode
import uuid
from collections import namedtuple, OrderedDict
import datetime
import json

import six

from .deva_packets import (
    DeviceAnnouncementPacketBase, DeviceDescriptionPacketBase, DeviceFeaturesPacketBase, v2
)
from .utils import strtime


DeviceInfo = namedtuple(
    'DeviceInfo',
    [
        'guid', 'application',
        'position_type', 'latitude', 'longitude', 'elevation',
        'radio_technology', 'radio_channel',
        'ident_timestamp'
    ]
)
BootInfo = namedtuple(
    'BootInfo',
    ['boot_number', 'boot_time', 'uptime', 'lifetime', 'announcement']
)
DeviceDescription = namedtuple(
    'DeviceDescription',
    ['platform', 'manufacturer', 'production', 'software_version', 'hardware_version']
)


class Response(object):
    """
    :type version: str
    :type arrival: datetime.datetime
    :type device: DeviceInfo
    :type boot: BootInfo
    :type feature_list_hash: str
    :type description: DeviceDescription | None
    :type features: list[str] | None
    """
    def __init__(self, packets):
        """
        :param list[serdepa.SerdepaPacket] packets: A list of Device Announcement packets
        """
        self.version = '0.2.1'
        self.arrival = datetime.datetime.utcnow()
        self.device = None
        self.boot = None
        self.feature_list_hash = None
        self.description = None
        self.features = None
        for packet in packets:
            if isinstance(packet, DeviceAnnouncementPacketBase):
                self._init_default_announcement_message(packet)
            elif isinstance(packet, DeviceDescriptionPacketBase):
                self.description = self._construct_description(packet)
            elif isinstance(packet, DeviceFeaturesPacketBase):
                if self.features is None:
                    self.features = []
                self.features.extend(packet.feature_uuids)
            else:
                raise ValueError("Unknown packet: {}".format(packet))

    def _init_default_announcement_message(self, packet):
        is_v2 = isinstance(packet, v2.DeviceAnnouncementPacket)
        self.device = DeviceInfo(
            guid=encode(packet.guid.serialize(), "hex").decode().upper(),
            application=_get_uuid(packet.uuid.serialize()),
            position_type=packet.position_type if is_v2 else 'U',
            latitude=packet.latitude / 1E6,
            longitude=packet.longitude / 1E6,
            elevation=packet.elevation / 100,
            radio_technology=packet.radio_technology.pretty_name if is_v2 else 'unknown',
            radio_channel=packet.radio_channel if is_v2 else 0,
            ident_timestamp='{:x}'.format(packet.ident_timestamp)
        )
        self.boot = BootInfo(
            boot_number=packet.boot_number,
            boot_time=strtime(packet.boot_time),
            uptime=packet.uptime,
            lifetime=packet.lifetime,
            announcement=packet.announcement
        )
        self.feature_list_hash = '{:x}'.format(packet.feature_list_hash)

    @staticmethod
    def _construct_description(packet):
        is_v2 = isinstance(packet, v2.DeviceDescriptionPacket)
        return DeviceDescription(
            platform=_get_uuid(packet.platform.serialize()),
            manufacturer=_get_uuid(packet.manufacturer.serialize()),
            production=strtime(packet.production),
            software_version=packet.sw_version,
            hardware_version=packet.hw_version if is_v2 else None,

        )

    @property
    def as_dict(self):
        ret = OrderedDict([
            ('version', self.version),
            ('arrival', self.arrival.replace(tzinfo=None).isoformat()),
            ('device', self.device._asdict()),
            ('boot', self.boot._asdict()),
            ('feature_list_hash', self.feature_list_hash),
        ])
        if self.description is not None:
            ret['description'] = self.description._asdict()
        if self.features is not None:
            ret['features'] = self.features
        return ret

    def __str__(self):
        return json.dumps(self.as_dict)


def _get_uuid(byte_string):
    return six.text_type(uuid.UUID(encode(byte_string, "hex").decode()))
