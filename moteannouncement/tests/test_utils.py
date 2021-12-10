from __future__ import unicode_literals

from unittest import TestCase

from ..utils import strtime, chunk


class TimeFormatTester(TestCase):
    def test_strtime(self):
        self.assertEqual(str(strtime(0)), '1970-01-01T00:00:00')


class ChunkTester(TestCase):
    def test_chunk_str(self):
        test_string = '0123456789'
        self.assertEqual(list(chunk(test_string, 2)), ['01', '23', '45', '67', '89'])
        self.assertEqual(list(chunk(test_string, 3)), ['012', '345', '678', '9'])

    def test_chunk_list(self):
        test_list = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        self.assertEqual(list(chunk(test_list, 4)), [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9]])

    def test_chunk_truncate(self):
        test_string = '0123456789'
        self.assertEqual(list(chunk(test_string, 2, truncate=True)), ['01', '23', '45', '67', '89'])
        self.assertEqual(list(chunk(test_string, 3, truncate=True)), ['012', '345', '678'])
