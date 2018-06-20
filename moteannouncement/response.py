from codecs import encode
import uuid
from collections import namedtuple, OrderedDict
import datetime
import json

import six

from .deva_packets import (
    DeviceAnnouncementPacket, DeviceAnnouncementPacketV2, DeviceDescriptionPacket, DeviceFeaturesPacket,
    ANNOUNCEMENT_PACKETS
)
from .utils import strtime


DeviceInfo = namedtuple(
    'DeviceInfo',
    ['guid', 'application', 'position_type', 'latitude', 'longitude', 'elevation', 'ident_timestamp']
)
BootInfo = namedtuple(
    'BootInfo',
    ['boot_number', 'boot_time', 'uptime', 'lifetime', 'announcement']
)
DeviceDescription = namedtuple(
    'DeviceDescription',
    ['platform', 'manufacturer', 'production', 'software_version']
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
        self.version = '0.2.0'
        self.arrival = datetime.datetime.utcnow()
        self.device = None
        self.boot = None
        self.feature_list_hash = None
        self.description = None
        self.features = None
        for packet in packets:
            if isinstance(packet, ANNOUNCEMENT_PACKETS):
                self._init_default_announcement_message(packet)
            elif isinstance(packet, DeviceDescriptionPacket):
                self.description = DeviceDescription(
                    platform=_get_uuid(packet.platform.serialize()),
                    manufacturer=_get_uuid(packet.manufacturer.serialize()),
                    production=strtime(packet.production),
                    software_version="{0.sw_major_version}.{0.sw_minor_version}.{0.sw_patch_version}".format(packet)
                )
            elif isinstance(packet, DeviceFeaturesPacket):
                if self.features is None:
                    self.features = []
                self.features.extend(packet.feature_uuids)
            else:
                raise ValueError("Unknown packet: {}".format(packet))

    def _init_default_announcement_message(self, packet):
        is_v2 = isinstance(packet, DeviceAnnouncementPacketV2)
        self.device = DeviceInfo(
            guid=encode(packet.guid.serialize(), "hex").decode().upper(),
            application=_get_uuid(packet.uuid.serialize()),
            position_type=packet.position_type if is_v2 else 'U',
            latitude=packet.latitude / 1E6,
            longitude=packet.longitude / 1E6,
            elevation=packet.elevation / 100,
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
