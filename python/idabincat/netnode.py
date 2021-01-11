# This file is Copyright 2016 Willi Ballenthin
# It was downloaded from
# https://github.com/williballenthin/ida-netnode
# and is Licensed under the Apache 2 licence

import sys
import zlib
import json
import logging
import struct
import idaapi
# Python 2/3 compat
if sys.version_info > (2, 8):
    long = int

BLOB_SIZE = 1024
OUR_NETNODE = "$ com.bincat"
INT_KEYS_TAG = 'M'
STR_KEYS_TAG = 'N'
STR_TO_INT_MAP_TAG = 'O'
INT_TO_INT_MAP_TAG = 'P'
logger = logging.getLogger(__name__)

# get the IDA version number
ida_major, ida_minor = list(map(int, idaapi.get_kernel_version().split(".")))
using_ida7api = (ida_major > 6)


class NetnodeCorruptError(RuntimeError):
    pass


class Netnode(object):
    """
    A netnode is a way to persistently store data in an IDB database.
    The underlying interface is a bit weird, so you should read the IDA
      documentation on the subject. Some places to start:

      - https://www.hex-rays.com/products/ida/support/sdkdoc/netnode_8hpp.html
      - The IDA Pro Book, version 2

    Conceptually, this netnode class represents is a key-value store
      uniquely identified by a namespace.

    This class abstracts over some of the peculiarities of the low-level
      netnode API. Notably, it supports indexing data by strings or
      numbers, and allows values to be larger than 1024 bytes in length.

    This class supports keys that are numbers or strings.
    Values must be JSON-encodable. They can not be None.

    Implementation:
     (You don't have to worry about this section if you just want to
        use the library. Its here for potential contributors.)

      The major limitation of the underlying netnode API is the fixed
        maximum length of a value. Values must not be larger than 1024
        bytes. Otherwise, you must use the `blob` API. We do that for you.

      The first enhancement is transparently zlib-encoding all values.

      To support arbitrarily sized values with keys of either int or str types,
        we store the values in different places:

        - integer keys with small values: stored in default supval table
        - integer keys with large values: the data is stored in the blob
           table named 'M' using an internal key. The link from the given key
           to the internal key is stored in the supval table named 'P'.
        - string keys with small values: stored in default hashval table
        - string keys with large values: the data is stored in the blob
           table named 'N' using an integer key. The link from string key
           to int key is stored in the supval table named 'O'.
    """

    def __init__(self, netnode_name=OUR_NETNODE):
        self._netnode_name = netnode_name
        # self._n = idaapi.netnode(netnode_name, namelen=0, do_create=True)
        self._n = idaapi.netnode(netnode_name, 0, True)

    @staticmethod
    def _decompress(data):
        if sys.version_info < (2, 8):
            return zlib.decompress(data)
        return zlib.decompress(data).decode('utf8')

    @staticmethod
    def _compress(data):
        if sys.version_info < (2, 8):
            data_ = data
        else:
            data_ = bytes(data, encoding='utf8')
        return zlib.compress(data_)

    @staticmethod
    def _encode(data):
        return json.dumps(data)

    @staticmethod
    def _decode(data):
        return json.loads(data)

    def _intdel(self, key):
        assert isinstance(key, (int, long))

        did_del = False
        storekey = self._n.supval(key, INT_TO_INT_MAP_TAG)
        if storekey is not None:
            storekey = int(storekey)
            self._n.delblob(storekey, INT_KEYS_TAG)
            self._n.supdel(key)
            did_del = True
        if self._n.supval(key) is not None:
            self._n.supdel(key)
            did_del = True

        if not did_del:
            raise KeyError("'{}' not found".format(key))

    def _get_next_slot(self, tag):
        '''
        get the first unused supval table key, or 0 if the
         table is empty.
        useful for filling the supval table sequentially.
        '''
        slot = self._n.suplast(tag)
        if slot is None or slot == idaapi.BADNODE:
            return 0
        else:
            return slot + 1

    def _intset(self, key, value):
        assert isinstance(key, (int, long))
        assert value is not None

        try:
            self._intdel(key)
        except KeyError:
            pass

        if len(value) > BLOB_SIZE:
            storekey = self._get_next_slot(INT_KEYS_TAG)
            self._n.setblob(value, storekey, INT_KEYS_TAG)
            self._n.supset(key, str(storekey), INT_TO_INT_MAP_TAG)
        else:
            self._n.supset(key, value)

    def _intget(self, key):
        assert isinstance(key, (int, long))

        storekey = self._n.supval(key, INT_TO_INT_MAP_TAG)
        if storekey is not None:
            storekey = int(storekey)
            v = self._n.getblob(storekey, INT_KEYS_TAG)
            if v is None:
                raise NetnodeCorruptError()
            return v

        v = self._n.supval(key)
        if v is not None:
            return v

        raise KeyError("'{}' not found".format(key))

    def _strdel(self, key):
        assert isinstance(key, (str))

        did_del = False
        storekey = self._n.hashval(key, STR_TO_INT_MAP_TAG)
        if storekey is not None and len(storekey) == 4:
            storekey, = struct.unpack('>I', storekey)
            self._n.delblob(storekey, STR_KEYS_TAG)
            self._n.hashdel(key)
            did_del = True
        if self._n.hashval(key):
            self._n.hashdel(key)
            did_del = True

        if not did_del:
            raise KeyError("'{}' not found".format(key))

    def _strset(self, key, value):
        assert isinstance(key, (str))
        assert value is not None

        try:
            self._strdel(key)
        except KeyError:
            pass

        if len(value) > BLOB_SIZE:
            storekey = self._get_next_slot(STR_KEYS_TAG)
            self._n.setblob(value, storekey, STR_KEYS_TAG)
            self._n.hashset(key, struct.pack('>I', storekey), STR_TO_INT_MAP_TAG)
        else:
            self._n.hashset(key, bytes(value))

    def _strget(self, key):
        assert isinstance(key, (str))

        storekey = self._n.hashval(key, STR_TO_INT_MAP_TAG)
        if storekey is not None and len(storekey) == 4:
            storekey, = struct.unpack('>I', storekey)
            v = self._n.getblob(storekey, STR_KEYS_TAG)
            if v is None:
                raise NetnodeCorruptError()
            return v

        v = self._n.hashval(key)
        if v is not None:
            return v

        raise KeyError("'{}' not found".format(key))

    def __getitem__(self, key):
        if isinstance(key, str):
            v = self._strget(key)
        elif isinstance(key, (int, long)):
            v = self._intget(key)
        else:
            raise TypeError("cannot use {} as key".format(type(key)))

        data = self._decompress(v)
        return self._decode(data)

    def __setitem__(self, key, value):
        '''
        does not support setting a value to None.
        value must be json-serializable.
        key must be a string or integer.
        '''
        assert value is not None

        v = self._compress(self._encode(value))
        if isinstance(key, str):
            self._strset(key, v)
        elif isinstance(key, (int, long)):
            self._intset(key, v)
        else:
            raise TypeError("cannot use {} as key".format(type(key)))

    def __delitem__(self, key):
        if isinstance(key, str):
            self._strdel(key)
        elif isinstance(key, (int, long)):
            self._intdel(key)
        else:
            raise TypeError("cannot use {} as key".format(type(key)))

    def get(self, key, default=None):
        try:
            return self[key]
        except (KeyError, zlib.error):
            return default

    def __contains__(self, key):
        try:
            if self[key] is not None:
                return True
            return False
        except (KeyError, zlib.error, ValueError):
            return False

    def iterkeys(self):
        # integer keys for all small values
        i = None
        if using_ida7api:
            i = self._n.supfirst()
        else:
            i = self._n.sup1st()
        while i != idaapi.BADNODE:
            yield i
            if using_ida7api:
                i = self._n.supnext(i)
            else:
                i = self._n.supnxt(i)

        # integer keys for all big values
        if using_ida7api:
            i = self._n.supfirst(INT_TO_INT_MAP_TAG)
        else:
            i = self._n.sup1st(INT_TO_INT_MAP_TAG)
        while i != idaapi.BADNODE:
            yield i
            if using_ida7api:
                i = self._n.supnext(i, INT_TO_INT_MAP_TAG)
            else:
                i = self._n.supnxt(i, INT_TO_INT_MAP_TAG)

        # string keys for all small values
        if using_ida7api:
            i = self._n.hashfirst()
        else:
            i = self._n.hash1st()
        while i != idaapi.BADNODE and i is not None:
            yield i
            if using_ida7api:
                i = self._n.hashnext(i)
            else:
                i = self._n.hashnxt(i)

        # string keys for all big values
        if using_ida7api:
            i = self._n.hashfirst(STR_TO_INT_MAP_TAG)
        else:
            i = self._n.hash1st(STR_TO_INT_MAP_TAG)
        while i != idaapi.BADNODE and i is not None:
            yield i
            if using_ida7api:
                i = self._n.hashnext(i, STR_TO_INT_MAP_TAG)
            else:
                i = self._n.hashnxt(i, STR_TO_INT_MAP_TAG)

    def keys(self):
        return [k for k in list(self.keys())]

    def itervalues(self):
        for k in list(self.keys()):
            yield self[k]

    def values(self):
        return [v for v in list(self.values())]

    def iteritems(self):
        for k in list(self.keys()):
            yield k, self[k]

    def items(self):
        return [(k, v) for k, v in list(self.items())]

    def kill(self):
        self._n.kill()
        self._n = idaapi.netnode(self._netnode_name, 0, True)
