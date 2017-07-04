from __future__ import unicode_literals

from unittest import TestCase

from mock import patch, MagicMock
import six
from six.moves import queue

from moteconnection.message import Message

from ..deva_receiver import NetworkAddressTranslator, Query, DAReceiver
from ..deva_packets import DeviceAnnouncementPacket, DeviceDescriptionPacket, DeviceFeaturesPacket


class NetworkAddressTranslatorTester(TestCase):
    def setUp(self):
        self.network_address_translator = NetworkAddressTranslator()

    def tearDown(self):
        del self.network_address_translator

    def test_invalid_getitem(self):
        self.assertRaises(AssertionError, lambda x, y: x[y], self.network_address_translator, '0123456789ABCDEF9')
        self.assertRaises(AssertionError, lambda x, y: x[y], self.network_address_translator, 0x2002)

    @patch('moteannouncement.deva_receiver.log')
    def test_default_mapping(self, logger):
        self.assertEqual(self.network_address_translator['0011223344556677'], 0x6677)
        self.assertTrue(logger.warning.called)

    def test_add_info(self):
        packet = MagicMock(spec=DeviceAnnouncementPacket)
        packet.guid.serialize.return_value = six.binary_type(b'\x00\x00\x00\x00\x00\x00\xAA\xFF')
        self.assertEqual(self.network_address_translator['000000000000AAFF'], 0xAAFF)
        self.network_address_translator.add_info(0xAABB, packet)
        self.assertIs(self.network_address_translator.announcements['000000000000AAFF'], packet)
        self.assertEqual(self.network_address_translator['000000000000AAFF'], 0xAABB)


# noinspection PyTypeChecker
@patch('moteannouncement.deva_receiver.time')
class QueryTester(TestCase):
    def setUp(self):
        self.mapping = MagicMock(spec=NetworkAddressTranslator)
        self.mapping.__getitem__.return_value = 0x0101

    def test_info_query(self, time_mock):
        time_mock.time.side_effect = [1, 1, 2, 10]
        requests = [Query.State.query]
        query = Query('000000000000AAFF', requests, self.mapping, retry=1)

        self.assertIs(query.state, Query.State.query)

        # time.time() is called for the first time - result = 1
        message = query.get_message()
        self.assertEqual(message.destination, 0x0101)
        self.assertEqual(message.payload, b'\x10\x01')

        # time.time() is called for the second time - result = 1
        self.assertIs(query.get_message(), None)

        # time.time() is called for the third time - result = 2
        message = query.get_message()
        self.assertEqual(message.destination, 0x0101)
        self.assertEqual(message.payload, b'\x10\x01')

        packet = MagicMock(spec=DeviceAnnouncementPacket, header=DeviceAnnouncementPacket.DEVA_ANNOUNCEMENT)
        query.receive_packet(packet)

        self.assertIs(query.state, Query.State.done)

        # no more messages should come out once the state is at `done`
        self.assertIs(query.get_message(), None)

    def test_description_query(self, time_mock):
        time_mock.time.side_effect = [1]
        requests = [Query.State.describe]
        query = Query('000000000000AAFF', requests, self.mapping, retry=1)

        self.assertIs(query.state, Query.State.describe)

        # time.time() is called for the first time - result = 1
        message = query.get_message()
        self.assertEqual(message.destination, 0x0101)
        self.assertEqual(message.payload, b'\x11\x01')

        packet = MagicMock(spec=DeviceDescriptionPacket, header=DeviceDescriptionPacket.DEVA_DESCRIPTION)
        query.receive_packet(packet)

        self.assertIs(query.state, Query.State.done)

        # no more messages should come out once the state is at `done`
        self.assertIs(query.get_message(), None)

    def test_features_query_single(self, time_mock):
        time_mock.time.side_effect = [1, 2, 3]
        requests = [Query.State.list_features]
        query = Query('000000000000AAFF', requests, self.mapping, retry=1)

        self.assertIs(query.state, Query.State.list_features)

        # time.time() is called for the first time - result = 1
        message = query.get_message()
        self.assertEqual(message.destination, 0x0101)
        self.assertEqual(message.payload, b'\x12\x01\x00')

        packet = MagicMock(
            spec=DeviceFeaturesPacket,
            header=DeviceFeaturesPacket.DEVA_FEATURES,
            features=b'\x12\x54\xF2\x45\x12\x54\xF2\x45\x12\x54\xF2\x45\x12\x54\xF2\x45',
            offset=0
        )
        query.receive_packet(packet)

        self.assertIs(query.state, Query.State.list_features)

        # time.time() is called for the second time - result = 2
        message = query.get_message()
        self.assertEqual(message.destination, 0x0101)
        self.assertEqual(message.payload, b'\x12\x01\x01')

        packet = MagicMock(
            spec=DeviceFeaturesPacket,
            header=DeviceFeaturesPacket.DEVA_FEATURES,
            features=b'\x12\x54\xF2\x45\x12\x54\xF2\x45\x12\x54\xF2\x45\x12\x54\xF2\x45',
            offset=1
        )
        query.receive_packet(packet)

        self.assertIs(query.state, Query.State.list_features)

        # time.time() is called for the third time - result = 3
        message = query.get_message()
        self.assertEqual(message.destination, 0x0101)
        self.assertEqual(message.payload, b'\x12\x01\x02')

        packet = MagicMock(
            spec=DeviceFeaturesPacket,
            header=DeviceFeaturesPacket.DEVA_FEATURES,
            features=b'',
            offset=2
        )
        query.receive_packet(packet)

        self.assertIs(query.state, Query.State.done)

        # no more messages should come out once the state is at `done`
        self.assertIs(query.get_message(), None)

    def test_features_query_multiple(self, time_mock):
        time_mock.time.side_effect = [1, 2]
        requests = [Query.State.list_features]
        query = Query('000000000000AAFF', requests, self.mapping, retry=1)

        self.assertIs(query.state, Query.State.list_features)

        # time.time() is called for the first time - result = 1
        message = query.get_message()
        self.assertEqual(message.destination, 0x0101)
        self.assertEqual(message.payload, b'\x12\x01\x00')

        packet = MagicMock(
            spec=DeviceFeaturesPacket,
            header=DeviceFeaturesPacket.DEVA_FEATURES,
            features=(
                b'\x12\x54\xF2\x45\x12\x54\xF2\x45\x12\x54\xF2\x45\x12\x54\xF2\x45'
                b'\x12\x54\xF2\x45\x12\x54\xF2\x45\x12\x54\xF2\x45\x12\x54\xF2\x45'
            ),
            offset=0
        )
        query.receive_packet(packet)

        self.assertIs(query.state, Query.State.list_features)

        # time.time() is called for the second time - result = 2
        message = query.get_message()
        self.assertEqual(message.destination, 0x0101)
        self.assertEqual(message.payload, b'\x12\x01\x02')

        packet = MagicMock(
            spec=DeviceFeaturesPacket,
            header=DeviceFeaturesPacket.DEVA_FEATURES,
            features=b'',
            offset=2
        )
        query.receive_packet(packet)

        self.assertIs(query.state, Query.State.done)

        # no more messages should come out once the state is at `done`
        self.assertIs(query.get_message(), None)

    def test_all_query(self, time_mock):
        time_mock.time.side_effect = [1, 2, 3, 4]
        requests = [Query.State.query, Query.State.describe, Query.State.list_features]
        query = Query('000000000000AAFF', requests, self.mapping, retry=1)

        self.assertIs(query.state, Query.State.query)

        # time.time() is called for the first time - result = 1
        message = query.get_message()
        self.assertEqual(message.destination, 0x0101)
        self.assertEqual(message.payload, b'\x10\x01')

        packet = MagicMock(spec=DeviceAnnouncementPacket, header=DeviceAnnouncementPacket.DEVA_ANNOUNCEMENT)
        query.receive_packet(packet)

        self.assertIs(query.state, Query.State.describe)

        # time.time() is called for the second time - result = 2
        message = query.get_message()
        self.assertEqual(message.destination, 0x0101)
        self.assertEqual(message.payload, b'\x11\x01')

        packet = MagicMock(spec=DeviceDescriptionPacket, header=DeviceDescriptionPacket.DEVA_DESCRIPTION)
        query.receive_packet(packet)

        self.assertIs(query.state, Query.State.list_features)

        # time.time() is called for the first time - result = 1
        message = query.get_message()
        self.assertEqual(message.destination, 0x0101)
        self.assertEqual(message.payload, b'\x12\x01\x00')

        packet = MagicMock(
            spec=DeviceFeaturesPacket,
            header=DeviceFeaturesPacket.DEVA_FEATURES,
            features=(
                b'\x12\x54\xF2\x45\x12\x54\xF2\x45\x12\x54\xF2\x45\x12\x54\xF2\x45'
                b'\x12\x54\xF2\x45\x12\x54\xF2\x45\x12\x54\xF2\x45\x12\x54\xF2\x45'
            ),
            offset=0
        )
        query.receive_packet(packet)

        self.assertIs(query.state, Query.State.list_features)

        # time.time() is called for the second time - result = 2
        message = query.get_message()
        self.assertEqual(message.destination, 0x0101)
        self.assertEqual(message.payload, b'\x12\x01\x02')

        packet = MagicMock(
            spec=DeviceFeaturesPacket,
            header=DeviceFeaturesPacket.DEVA_FEATURES,
            features=b'',
            offset=2
        )
        query.receive_packet(packet)

        self.assertIs(query.state, Query.State.done)

        # no more messages should come out once the state is at `done`
        self.assertIs(query.get_message(), None)


@patch('moteannouncement.deva_receiver.Query')
@patch('moteannouncement.deva_receiver.MessageDispatcher')
@patch('moteannouncement.deva_receiver.Connection')
@patch('moteannouncement.deva_receiver.Queue')
class DeviceAnnouncementReceiverTester(TestCase):

    def test_receive(self, queue_mock, connection_mock, message_dispatcher_mock, query_mock):
        message_mock = MagicMock(
            spec=Message,
            payload=(
                b'\x00'                                                                 # header
                b'\x01'                                                                 # version
                b'\x70\xB3\xD5\x58\x90\x01\x06\x23'                                     # guid
                b'\x00\x00\x00\x04'                                                     # boot_number
                b'\x00\x00\x00\x00\x59\x43\xF1\xB8'                                     # boot_time
                b'\x00\x17\x93\x58'                                                     # uptime
                b'\x00\x3F\xB2\x5B'                                                     # lifetime
                b'\x00\x00\x03\x9B'                                                     # announcement
                b'\x5B\x86\x5C\x5B\x7E\xD0\x47\xC0\x97\x57\x52\x60\x5F\x89\xC0\x95'     # uuid
                b'\x00\x00\x00\x00'                                                     # latitude
                b'\x00\x00\x00\x00'                                                     # longitude
                b'\x00\x00\x00\x00'                                                     # elevation
                b'\x00\x00\x00\x00\x59\x43\xEC\x33'                                     # ident_timestamp
                b'\xAF\x90\xAF\x90'                                                     # feature_list_hash
            )
        )
        queue_mock.Queue.return_value.get.side_effect = [message_mock, queue.Empty()]
        queue_mock.Empty = queue.Empty
        receiver = DAReceiver('', 0x0001, 1)
        message = receiver.poll()
        self.assertIsInstance(message, DeviceAnnouncementPacket)
        message = receiver.poll()
        self.assertIs(message, None)

    def test_with_statement_exit(self, queue_mock, connection_mock, message_dispatcher_mock, query_mock):

        try:
            with DAReceiver('', 0x0001, 1):
                raise AssertionError()
        except AssertionError:
            pass

        message_dispatcher_mock.assert_called_with(0x0001, 0xFF)
        message_dispatcher_mock.return_value.register_receiver.assert_called_with(0xDA, queue_mock.Queue.return_value)

        connection_mock.assert_called()
        connection_mock.return_value.connect.assert_called_with('', reconnect=10)
        connection_mock.return_value.join.assert_called_with()

    def test_query_creation(self, queue_mock, connection_mock, message_dispatcher_mock, query_mock):
        receiver = DAReceiver('', 0x0001, 1)
        receiver.query('0000000000000101', info=True, features=True)

        query_mock.assert_called_with(
            '0000000000000101',
            [query_mock.State.query, query_mock.State.list_features],
            receiver._network_address_mapping, 1
        )
