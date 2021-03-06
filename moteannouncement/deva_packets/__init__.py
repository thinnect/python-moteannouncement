__author__ = "Raido Pahtma, Kaarel Ratas"
__license__ = "MIT"


from . import v1
from . import v2
from .base import (
    DeviceAnnouncementPacketBase, DeviceDescriptionPacketBase, DeviceFeaturesPacketBase,
    DeviceRequestPacketBase, DeviceFeatureRequestPacketBase
)


def deserialize(payload):
    packet_map = {
        # Version 1 packets
        b'\x00\x01': v1.DeviceAnnouncementPacket,
        b'\x01\x01': v1.DeviceDescriptionPacket,
        b'\x02\x01': v1.DeviceFeaturesPacket,
        b'\x10\x01': v1.DeviceRequestPacket,
        b'\x11\x01': v1.DeviceRequestPacket,
        b'\x12\x01': v1.DeviceFeatureRequestPacket,
        # Version 2 packets
        b'\x00\x02': v2.DeviceAnnouncementPacket,
        b'\x01\x02': v2.DeviceDescriptionPacket,
        b'\x02\x02': v2.DeviceFeaturesPacket,
        b'\x10\x02': v2.DeviceRequestPacket,
        b'\x11\x02': v2.DeviceRequestPacket,
        b'\x12\x02': v2.DeviceFeatureRequestPacket,
    }
    key = payload[:2]
    if key in packet_map:
        packet = packet_map[key]()
    else:
        raise ValueError('Invalid packet {}'.format(payload))
    packet.deserialize(payload)
    return packet
