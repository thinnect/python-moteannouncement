import uuid
from codecs import decode, encode

from enum import Enum

from serdepa import Array, List, nx_uint8, nx_uint32, nx_int32, nx_int64

from moteannouncement.deva_packets import base
from moteannouncement.utils import chunk, strtime


class RadioTechnologies(Enum):
    UNKNOWN = 0
    IEEE_802_15_4 = 1
    BLE = 2
    BLE_PLUS_IEEE_802_15_4 = 3
    IEEE_802_11 = 4

    @property
    def pretty_name(self):
        if self is RadioTechnologies.UNKNOWN:
            return 'unknown'
        elif self is RadioTechnologies.IEEE_802_15_4:
            return '802.15.4'
        elif self is RadioTechnologies.BLE:
            return 'BLE'
        elif self is RadioTechnologies.BLE_PLUS_IEEE_802_15_4:
            return 'BLE+802.15.4'
        elif self is RadioTechnologies.IEEE_802_11:
            return "802.11"
        else:
            raise ValueError('Unknown radio technology value: {}'.format(self))


class DeviceAnnouncementPacket(base.DeviceAnnouncementPacketBase):
    VERSION = 0x02
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

        ("_radio_technology", nx_uint8),
        ("radio_channel", nx_uint8),

        ("ident_timestamp", nx_int64),

        ("feature_list_hash", nx_uint32)
    ]

    @property
    def radio_technology(self):
        """
        :rtype: RadioTechnologies
        """
        try:
            return RadioTechnologies(self._radio_technology)
        except ValueError:
            return RadioTechnologies.UNKNOWN

    @radio_technology.setter
    def radio_technology(self, value):
        """
        :type value: RadioTechnologies
        """
        self._radio_technology = value.value

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
        dap.position_type = 'G'
        dap.latitude = 58 * 1000000
        dap.longitude = -24 * 1000000
        dap.elevation = 1000
        dap.ident_timestamp = 1415463675
        dap.feature_list_hash = 0x12345678
        return dap

    def __str__(self):
        return "{:02X}:{:02X} {} b:{}@{} {}+{} ({}) a:{} [{}:{};{};{}] {}({:x}) <{:08x}>".format(
            self.header, self.version,
            decode(encode(self.guid.serialize(), "hex")).upper(),
            self.boot_number, strtime(self.boot_time),
            self.lifetime, self.uptime,
            self.announcement,
            uuid.UUID(decode(encode(self.uuid.serialize(), "hex"))),
            self.position_type, self.latitude, self.longitude, self.elevation,
            strtime(self.ident_timestamp), self.ident_timestamp, self.feature_list_hash
        )


class DeviceDescriptionPacket(base.DeviceDescriptionPacketBase):
    VERSION = 0x02
    _fields_ = [
        ("header", nx_uint8),
        ("version", nx_uint8),
        ("guid", Array(nx_uint8, 8)),
        ("boot_number", nx_uint32),

        ("platform", Array(nx_uint8, 16)),
        ("hw_major_version", nx_uint8),
        ("hw_minor_version", nx_uint8),
        ("hw_assem_version", nx_uint8),

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

    @property
    def hw_version(self):
        return "{0.hw_major_version}.{0.hw_minor_version}.{0.hw_assem_version}".format(self)

    def __str__(self):
        return "{:02X}:{:02X} {} b:{} p:{} m:{} @{} sw:{} hw:{} {}({:x})".format(
            self.header, self.version,
            decode(encode(self.guid.serialize(), "hex")).upper(),
            self.boot_number,
            uuid.UUID(decode(encode(self.platform.serialize(), "hex"))),
            uuid.UUID(decode(encode(self.manufacturer.serialize(), "hex"))),
            strtime(self.production),
            self.sw_version, self.hw_version,
            strtime(self.ident_timestamp), self.ident_timestamp
        )


class DeviceFeaturesPacket(base.DeviceFeaturesPacketBase):
    VERSION = 0x02
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
    VERSION = 0x02
    _fields_ = [
        ("header", nx_uint8),
        ("version", nx_uint8)
    ]


class DeviceFeatureRequestPacket(base.DeviceFeatureRequestPacketBase):
    VERSION = 0x02
    _fields_ = [
        ("header", nx_uint8),
        ("version", nx_uint8),
        ("offset", nx_uint8)
    ]

    def __init__(self, offset=0, **kwargs):
        super(DeviceFeatureRequestPacket, self).__init__(**kwargs)
        self.offset = offset
