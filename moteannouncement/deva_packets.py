"""deva_packets.py: DeviceAnnouncement packets."""

from datetime import datetime

from serdepa import SerdepaPacket, nx_uint8, Array, nx_uint32, nx_int32, nx_int64, List

import uuid

import six

from .utils import strtime, chunk

__author__ = "Raido Pahtma"
__license__ = "MIT"


class TimestampMixin(object):
    def deserialize(self, *args, **kwargs):
        self.arrived = datetime.utcnow().replace(tzinfo=None)
        super(TimestampMixin, self).deserialize(*args, **kwargs)


@six.python_2_unicode_compatible
class DeviceAnnouncementPacket(TimestampMixin, SerdepaPacket):
    DEVA_ANNOUNCEMENT = 0x00
    _fields_ = [
        ("header", nx_uint8),
        ("version", nx_uint8),
        ("guid", Array(nx_uint8, 8)),
        ("boot_number", nx_uint32),

        ("boot_time", nx_int64),
        ("uptime", nx_uint32),
        ("lifetime", nx_uint32),
        ("announcement", nx_uint32),

        ("uuid", Array(nx_uint8, 16)),

        ("latitude", nx_int32),
        ("longitude", nx_int32),
        ("elevation", nx_int32),

        ("ident_timestamp", nx_int64),

        ("feature_list_hash", nx_uint32)
    ]

    def __init__(self, **kwargs):
        super(DeviceAnnouncementPacket, self).__init__(**kwargs)
        self.header = self.DEVA_ANNOUNCEMENT
        self.version = 0x01

    @classmethod
    def sample(cls):
        dap = DeviceAnnouncementPacket()
        for i in range(0, 8):
            dap.guid.append(i)
            # dap.guid[i] = i
        dap.boot_number = 8
        dap.boot_time = 1496995442
        dap.uptime = 100
        dap.lifetime = dap.boot_number * dap.uptime
        dap.announcement = 1
        for i in range(0, 15):
            dap.uuid.append(i)
            # dap.uuid[i] = i
        dap.latitude = 58*1000000
        dap.longitude = -24*1000000
        dap.elevation = 1000
        dap.ident_timestamp = 1415463675
        dap.feature_list_hash = 0x12345678
        return dap

    def __str__(self):
        return "{:02X}:{:02X} {} b:{}@{} {}+{} ({}) a:{} [{};{};{}] {}({:x}) <{:08x}>".format(
            self.header, self.version,
            bytes(self.guid.serialize()).encode("hex").upper(),
            self.boot_number, strtime(self.boot_time),
            self.lifetime, self.uptime,
            self.announcement,
            uuid.UUID(bytes(self.uuid.serialize()).encode("hex")),
            self.latitude, self.longitude, self.elevation,
            strtime(self.ident_timestamp), self.ident_timestamp, self.feature_list_hash
        )


@six.python_2_unicode_compatible
class DeviceAnnouncementPacketV2(TimestampMixin, SerdepaPacket):
    DEVA_ANNOUNCEMENT = 0x00
    _fields_ = [
        ("header", nx_uint8),
        ("version", nx_uint8),
        ("guid", Array(nx_uint8, 8)),
        ("boot_number", nx_uint32),

        ("boot_time", nx_int64),
        ("uptime", nx_uint32),
        ("lifetime", nx_uint32),
        ("announcement", nx_uint32),

        ("uuid", Array(nx_uint8, 16)),

        ("_position_type", nx_uint8),
        ("latitude", nx_int32),
        ("longitude", nx_int32),
        ("elevation", nx_int32),

        ("ident_timestamp", nx_int64),

        ("feature_list_hash", nx_uint32)
    ]

    def __init__(self, **kwargs):
        super(DeviceAnnouncementPacketV2, self).__init__(**kwargs)
        self.header = self.DEVA_ANNOUNCEMENT
        self.version = 0x02

    @property
    def position_type(self):
        return chr(self._position_type)

    @position_type.setter
    def position_type(self, value):
        self._position_type = ord(value)

    @classmethod
    def sample(cls):
        dap = DeviceAnnouncementPacket()
        for i in range(0, 8):
            dap.guid.append(i)
            # dap.guid[i] = i
        dap.boot_number = 8
        dap.boot_time = 1496995442
        dap.uptime = 100
        dap.lifetime = dap.boot_number * dap.uptime
        dap.announcement = 1
        for i in range(0, 15):
            dap.uuid.append(i)
            # dap.uuid[i] = i
        dap.latitude = 58*1000000
        dap.longitude = -24*1000000
        dap.elevation = 1000
        dap.ident_timestamp = 1415463675
        dap.feature_list_hash = 0x12345678
        return dap

    def __str__(self):
        return "{:02X}:{:02X} {} b:{}@{} {}+{} ({}) a:{} [{}:{};{};{}] {}({:x}) <{:08x}>".format(
            self.header, self.version,
            bytes(self.guid.serialize()).encode("hex").upper(),
            self.boot_number, strtime(self.boot_time),
            self.lifetime, self.uptime,
            self.announcement,
            uuid.UUID(bytes(self.uuid.serialize()).encode("hex")),
            self.position_type, self.latitude, self.longitude, self.elevation,
            strtime(self.ident_timestamp), self.ident_timestamp, self.feature_list_hash
        )


@six.python_2_unicode_compatible
class DeviceDescriptionPacket(TimestampMixin, SerdepaPacket):
    DEVA_DESCRIPTION = 0x01
    _fields_ = [
        ("header", nx_uint8),
        ("version", nx_uint8),
        ("guid", Array(nx_uint8, 8)),
        ("boot_number", nx_uint32),

        ("platform", Array(nx_uint8, 16)),
        ("manufacturer", Array(nx_uint8, 16)),
        ("production", nx_int64),

        ("ident_timestamp", nx_int64),
        ("sw_major_version", nx_uint8),
        ("sw_minor_version", nx_uint8),
        ("sw_patch_version", nx_uint8),
    ]

    def __init__(self, **kwargs):
        super(DeviceDescriptionPacket, self).__init__(**kwargs)
        self.header = self.DEVA_DESCRIPTION
        self.version = 0x01

    def __str__(self):
        return "{:02X}:{:02X} {} b:{} p:{} m:{} @{} {}.{}.{} {}({:x})".format(
            self.header, self.version,
            bytes(self.guid.serialize()).encode("hex").upper(),
            self.boot_number,
            uuid.UUID(bytes(self.platform.serialize()).encode("hex")),
            uuid.UUID(bytes(self.manufacturer.serialize()).encode("hex")),
            strtime(self.production),
            self.sw_major_version, self.sw_minor_version, self.sw_patch_version,
            strtime(self.ident_timestamp), self.ident_timestamp
        )


@six.python_2_unicode_compatible
class DeviceFeaturesPacket(TimestampMixin, SerdepaPacket):
    DEVA_FEATURES = 0x02
    _fields_ = [
        ("header", nx_uint8),
        ("version", nx_uint8),
        ("guid", Array(nx_uint8, 8)),
        ("boot_number", nx_uint32),

        ("total", nx_uint8),
        ("offset", nx_uint8),

        ("features", List(nx_uint8))  # List(Array(nx_uint8, 16))
    ]

    def __init__(self, **kwargs):
        super(DeviceFeaturesPacket, self).__init__(**kwargs)
        self.header = self.DEVA_FEATURES
        self.version = 0x01

    def __str__(self):
        s = "{:02X}:{:02X} {} b:{} features {}/{}".format(
            self.header, self.version,
            bytes(self.guid.serialize()).encode("hex").upper(),
            self.boot_number,
            self.offset, self.total
        )
        return "{} {}".format(s, str(self.feature_uuids))

    @property
    def feature_uuids(self):
        ftrs = six.binary_type(self.features.serialize()).encode("hex")
        return [str(uuid.UUID(u)) for u in chunk(ftrs, 32)]


class DeviceRequestPacket(SerdepaPacket):
    DEVA_QUERY = 0x10
    DEVA_DESCRIBE = 0x11
    _fields_ = [
        ("header", nx_uint8),
        ("version", nx_uint8)
    ]

    def __init__(self, request=DEVA_QUERY, **kwargs):
        super(DeviceRequestPacket, self).__init__(**kwargs)
        self.header = request
        self.version = 0x01


class DeviceFeatureRequestPacket(SerdepaPacket):
    DEVA_LIST_FEATURES = 0x12
    _fields_ = [
        ("header", nx_uint8),
        ("version", nx_uint8),
        ("offset", nx_uint8)
    ]

    def __init__(self, offset=0, **kwargs):
        super(DeviceFeatureRequestPacket, self).__init__(**kwargs)
        self.header = self.DEVA_LIST_FEATURES
        self.version = 0x01
        self.offset = offset


ANNOUNCEMENT_PACKETS = (DeviceAnnouncementPacket, DeviceAnnouncementPacketV2)
