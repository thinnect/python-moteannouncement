import uuid
from codecs import decode, encode

from serdepa import Array, List, nx_uint8, nx_uint32, nx_int32, nx_int64

from moteannouncement.deva_packets import base
from moteannouncement.utils import chunk, strtime


class DeviceAnnouncementPacket(base.DeviceAnnouncementPacketBase):
    VERSION = 0x01
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
            decode(encode(self.guid.serialize(), "hex")).upper(),
            self.boot_number, strtime(self.boot_time),
            self.lifetime, self.uptime,
            self.announcement,
            uuid.UUID(decode(encode(self.uuid.serialize(), "hex"))),
            self.latitude, self.longitude, self.elevation,
            strtime(self.ident_timestamp), self.ident_timestamp, self.feature_list_hash
        )


class DeviceDescriptionPacket(base.DeviceDescriptionPacketBase):
    VERSION = 0x01
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

    @property
    def sw_version(self):
        return "{0.sw_major_version}.{0.sw_minor_version}.{0.sw_patch_version}".format(self)

    def __str__(self):
        return "{:02X}:{:02X} {} b:{} p:{} m:{} @{} {} {}({:x})".format(
            self.header, self.version,
            decode(encode(self.guid.serialize(), "hex")).upper(),
            self.boot_number,
            uuid.UUID(decode(encode(self.platform.serialize(), "hex"))),
            uuid.UUID(decode(encode(self.manufacturer.serialize(), "hex"))),
            strtime(self.production),
            self.sw_version,
            strtime(self.ident_timestamp), self.ident_timestamp
        )


class DeviceFeaturesPacket(base.DeviceFeaturesPacketBase):
    VERSION = 0x01
    _fields_ = [
        ("header", nx_uint8),
        ("version", nx_uint8),
        ("guid", Array(nx_uint8, 8)),
        ("boot_number", nx_uint32),

        ("total", nx_uint8),
        ("offset", nx_uint8),

        ("features", List(nx_uint8))  # List(Array(nx_uint8, 16))
    ]

    def __str__(self):
        s = "{:02X}:{:02X} {} b:{} features {}/{}".format(
            self.header, self.version,
            decode(encode(self.guid.serialize(), "hex")).upper(),
            self.boot_number,
            self.offset, self.total
        )
        return "{} {}".format(s, str(self.feature_uuids))

    @property
    def feature_uuids(self):
        ftrs = decode(encode(self.features.serialize(), "hex"))
        return [str(uuid.UUID(u)) for u in chunk(ftrs, 32)]


class DeviceRequestPacket(base.DeviceRequestPacketBase):
    VERSION = 0x01
    _fields_ = [
        ("header", nx_uint8),
        ("version", nx_uint8)
    ]


class DeviceFeatureRequestPacket(base.DeviceFeatureRequestPacketBase):
    VERSION = 0x01
    _fields_ = [
        ("header", nx_uint8),
        ("version", nx_uint8),
        ("offset", nx_uint8)
    ]

    def __init__(self, offset=0, **kwargs):
        super(DeviceFeatureRequestPacket, self).__init__(**kwargs)
        self.offset = offset
