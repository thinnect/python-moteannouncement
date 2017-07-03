"""deva_packets.py: DeviceAnnouncement packets."""

from serdepa import SerdepaPacket, uint8, Array, nx_uint32, nx_int32, nx_int64, List

import uuid

from six import python_2_unicode_compatible

from .utils import strtime, chunk

__author__ = "Raido Pahtma"
__license__ = "MIT"


@python_2_unicode_compatible
class DeviceAnnouncementPacket(SerdepaPacket):
    DEVA_ANNOUNCEMENT = 0x00
    _fields_ = [
        ("header", uint8),
        ("version", uint8),
        ("guid", Array(uint8, 8)),
        ("boot_number", nx_uint32),

        ("boot_time", nx_int64),
        ("uptime", nx_uint32),
        ("lifetime", nx_uint32),
        ("announcement", nx_uint32),

        ("uuid", Array(uint8, 16)),

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


@python_2_unicode_compatible
class DeviceDescriptionPacket(SerdepaPacket):
    DEVA_DESCRIPTION = 0x01
    _fields_ = [
        ("header", uint8),
        ("version", uint8),
        ("guid", Array(uint8, 8)),
        ("boot_number", nx_uint32),

        ("platform", Array(uint8, 16)),
        ("manufacturer", Array(uint8, 16)),
        ("production", nx_int64),

        ("ident_timestamp", nx_int64),
        ("sw_major_version", uint8),
        ("sw_minor_version", uint8),
        ("sw_patch_version", uint8),
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


@python_2_unicode_compatible
class DeviceFeaturesPacket(SerdepaPacket):
    DEVA_FEATURES = 0x02
    _fields_ = [
        ("header", uint8),
        ("version", uint8),
        ("guid", Array(uint8, 8)),
        ("boot_number", nx_uint32),

        ("total", uint8),
        ("offset", uint8),

        ("features", List(uint8))  # List(Array(uint8, 16))
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
        ftrs = bytes(self.features.serialize()).encode("hex")
        ftrs = [str(uuid.UUID(u)) for u in chunk(ftrs, 32)]
        return "{} {}".format(s, str(ftrs))


@python_2_unicode_compatible
class DeviceRequestPacket(SerdepaPacket):
    DEVA_QUERY = 0x10
    DEVA_DESCRIBE = 0x11
    _fields_ = [
        ("header", uint8),
        ("version", uint8)
    ]

    def __init__(self, request=DEVA_QUERY, **kwargs):
        super(DeviceRequestPacket, self).__init__(**kwargs)
        self.header = request
        self.version = 0x01


@python_2_unicode_compatible
class DeviceFeatureRequestPacket(SerdepaPacket):
    DEVA_LIST_FEATURES = 0x12
    _fields_ = [
        ("header", uint8),
        ("version", uint8),
        ("offset", uint8)
    ]

    def __init__(self, offset=0, **kwargs):
        super(DeviceFeatureRequestPacket, self).__init__(**kwargs)
        self.header = self.DEVA_LIST_FEATURES
        self.version = 0x01
        self.offset = offset
