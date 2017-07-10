from unittest import TestCase

from mock import patch

from ..deva_packets import DeviceAnnouncementPacket, DeviceFeaturesPacket, DeviceDescriptionPacket


@patch('moteannouncement.deva_packets.datetime')
class TimestampMixingTester(TestCase):
    announcement = (
        b'\x00'
        b'\x01'
        b'\x01\xA7\xD3\x6F\x15\x00\x00\x81'
        b'\x00\x00\x00\x06'
        b'\x00\x00\x00\x00\x59\x43\xE1\x00'
        b'\x00\x1A\x0D\xB1'
        b'\x01\x3A\x46\x3B'
        b'\x00\x00\x03\xFB'
        b'\x09\xFB\xDA\x66\xC4\xDF\x43\xC7\xB1\x08\xF9\xF2\xE6\xA7\xB8\xE8'
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x59\x40\xFE\xA3'
        b'\xAF\x90\xAF\x90'
    )

    def test_announcement_timestamp(self, datetime_mock):
        unique_value = 0x2134
        datetime_mock.utcnow.return_value.replace.return_value = unique_value
        packet = DeviceAnnouncementPacket()
        packet.deserialize(self.announcement)
        self.assertEqual(packet.header, 0)
        self.assertEqual(packet.version, 1)
        datetime_mock.utcnow.return_value.replace.assert_called_with(tzinfo=None)
        self.assertIs(packet.arrived, unique_value)
