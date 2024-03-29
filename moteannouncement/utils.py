"""
Utilities used in the moteannouncement package.
"""

import datetime
import pytz
import time
from warnings import warn
from collections import namedtuple


GenericPacket = namedtuple("GenericPacket", ("destination", "payload"))


def strtime(utc_timestamp):
    try:
        tpl = (datetime.datetime.fromtimestamp(0, tz=pytz.utc) + datetime.timedelta(seconds=utc_timestamp)).timetuple()
    except OverflowError:
        warn("Failed to handle utc_timestamp {}, replaced with (-1)".format(utc_timestamp), RuntimeWarning)
        tpl = (datetime.datetime.fromtimestamp(0, tz=pytz.utc) + datetime.timedelta(seconds=-1)).timetuple()
    return time.strftime("%Y-%m-%dT%H:%M:%S", tpl)


def chunk(sequence, length, truncate=False):
    """
    Return an iterator that yields `length` sized chunks of `sequence`. If `truncate` is True, omits the last
    member if not full length.

    :param collections.Sequence[T] sequence: input sequence
    :param int length: length of output chunks
    :param bool truncate: truncate sequence if `len(sequence)` is not a multiple of `length`
    :return: A generator of chunks of length `length` from `sequence`
    :rtype: collections.Iterator[collections.Sequence[T]]
    """
    # TODO: This slices the sequence twice if truncate=True. Could change this into a generator and use a variable.
    # Probably over-optimizing here though...
    return (
        sequence[i:i+length]
        for i in range(0, len(sequence), length)
        if not truncate or len(sequence[i:i+length]) == length
    )


class FeatureMap(dict):
    def __setitem__(self, key, value):
        if key in self and self[key] != value:
            warn("Overwriting existing feature_list_hash", RuntimeWarning)
        return super(FeatureMap, self).__setitem__(key, value)
