"""
Utilities used in the moteannouncement package.
"""

import datetime
import pytz
import time


def strtime(utc_timestamp):
    tpl = (datetime.datetime.fromtimestamp(0, tz=pytz.utc) + datetime.timedelta(seconds=utc_timestamp)).timetuple()
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
