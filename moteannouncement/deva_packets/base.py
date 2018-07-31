from serdepa import SerdepaPacket, nx_uint8

from moteannouncement.deva_packets.utils import TimestampMixin


class DeviceAnnouncementPacketBase(TimestampMixin, SerdepaPacket):
    DEVA_ANNOUNCEMENT = 0x00
    VERSION = NotImplemented

    def __init__(self, **kwargs):
        super(DeviceAnnouncementPacketBase, self).__init__(**kwargs)
        self.header = self.DEVA_ANNOUNCEMENT
        self.version = self.VERSION


class DeviceDescriptionPacketBase(TimestampMixin, SerdepaPacket):
    DEVA_DESCRIPTION = 0x01
    VERSION = NotImplemented

    def __init__(self, **kwargs):
        super(DeviceDescriptionPacketBase, self).__init__(**kwargs)
        self.header = self.DEVA_DESCRIPTION
        self.version = self.VERSION


class DeviceFeaturesPacketBase(TimestampMixin, SerdepaPacket):
    DEVA_FEATURES = 0x02
    VERSION = NotImplemented

    def __init__(self, **kwargs):
        super(DeviceFeaturesPacketBase, self).__init__(**kwargs)
        self.header = self.DEVA_FEATURES
        self.version = self.VERSION


class DeviceRequestPacketBase(SerdepaPacket):
    DEVA_QUERY = 0x10
    DEVA_DESCRIBE = 0x11
    VERSION = NotImplemented

    def __init__(self, request=DEVA_QUERY, **kwargs):
        super(DeviceRequestPacketBase, self).__init__(**kwargs)
        self.header = request
        self.version = self.VERSION


class DeviceFeatureRequestPacketBase(SerdepaPacket):
    DEVA_LIST_FEATURES = 0x12
    VERSION = NotImplemented

    def __init__(self, **kwargs):
        super(DeviceFeatureRequestPacketBase, self).__init__(**kwargs)
        self.header = self.DEVA_LIST_FEATURES
        self.version = self.VERSION
