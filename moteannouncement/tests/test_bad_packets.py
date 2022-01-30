from unittest import TestCase

from moteannouncement.deva_packets import deserialize


class BadPacketTester(TestCase):

    def test_announcement_timestamp(self):
    	self.assertRaises(ValueError, deserialize, b'')

    	self.assertRaises(ValueError, deserialize, b'\x00')

    	self.assertRaises(ValueError, deserialize, b'\x00\x01')

    	self.assertRaises(ValueError, deserialize, 128*b'\x01')
