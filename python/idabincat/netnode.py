# This file is Copyright 2016 Willi Ballenthin
# It was downloaded from
# https://github.com/williballenthin/ida-netnode
# and is Licensed under the Apache 2 licence

import zlib
import json
import logging

import idaapi


CHUNK_SIZE = 1024
OUR_NETNODE = "$ com.bincat"
CHUNK_INDEX_TAG = "M"
CHUNK_TAG = "N"
g_logger = logging.getLogger("netnode")
g_logger.setLevel(logging.INFO)


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
    Values must be JSON-encodable.
   
    Implementation:
      The major limitation of the underlying netnode API is the fixed
        maximum length of a value. Values must not be larger than 1024
        bytes.
    
      The first enhancement is transparently zlib-encoding all values.

      To support arbitrarily sized values, we split the value data into
        chunks (each of length 1024), and store them in a separate
        "chunk store". The locations of these chunks are stored in a
        "index store". If a fetch operation encounters a value with length
        1024 bytes, it also checks the index store to recover the remaining
        data.
    
      The chunk and index stores are implemented using non-standard netnode
        hashes/arrays (read the netnode.hpp documentation). The primary
        key-value data is stored in the default supval or hashval.
      The chunk store is the supval array identified by the character "N".
        Chunks are always stored as contiguous runs of supval indices.
        Data is always stored at LAST_INDEX + 1.
      The chunk index store is the hashval or supval index indentified by the
        character "M". The key is the primary key used in the set operation.
        the value is the json-encoded tuple (start_index, end_index) for the
        chunk data in the chunk store.


        netnode: NAMESPACE
        +------------------------+
        | default hashval/supval | ---> { KEY: VALUE[:1024] }
        +------------------------+
        | hashval/supval "M"     | ---> { KEY: (4444, 5555) }
        +------------------------+
        | supval "N"             | ---> { 
        |                        |         4444: VALUE[1024:2048]
        |                        |         4445: VALUE[2048:3092]
        |                        |          ... 
        |                        |         5555: VALUE[...:...]
        |                        |      }
        +------------------------+
    """
    def __init__(self, netnode_name=OUR_NETNODE):
        self._netnode_name = netnode_name
        #self._n = idaapi.netnode(netnode_name, namelen=0, do_create=True)
        self._n = idaapi.netnode(netnode_name, 0, True)

    @staticmethod
    def _decompress(data):
        return zlib.decompress(data)

    @staticmethod
    def _compress(data):
        return zlib.compress(data)

    @staticmethod
    def _encode(data):
        return json.dumps(data)

    @staticmethod
    def _decode(data):
        return json.loads(data)

    def __getitem__(self, key):
        fget = None
        if isinstance(key, basestring):
            fget = self._n.hashval
        elif isinstance(key, (int, long)):
            fget = self._n.supval
        else:
            raise TypeError("cannot use {} as key".format(type(key)))

        try:
            v = fget(key)
        except TypeError:
            raise KeyError("'{}' not found".format(key))
        if v is None:
            raise KeyError("'{}' not found".format(key))

        if len(v) == CHUNK_SIZE:
            chunks = [v]
            index_refs = fget(key, CHUNK_INDEX_TAG)
            if index_refs is not None:
                first, last = self._decode(self._decompress(index_refs))
                g_logger.debug("get: chunk run: 0x%x to 0x%x (0x%x chunks)",
                               first, last, last-first+1)
                for index_ref in range(first, last + 1):
                    chunk = self._n.supval(index_ref, CHUNK_TAG)
                    chunks.append(chunk)
            g_logger.debug("get: fetched 0x%x chunks", len(chunks))
            g_logger.debug("get: data length: 0x%x", len("".join(chunks)))
            return self._decode(self._decompress("".join(chunks)))
        else:
            return self._decode(self._decompress(v))

    def __setitem__(self, key, value):
        fset = None
        fget = None
        flast = None
        if isinstance(key, basestring):
            fset = self._n.hashset
            fget = self._n.hashval
            flast = self._n.hashlast
        elif isinstance(key, (int, long)):
            fset = self._n.supset
            fget = self._n.supval
            flast = self._n.suplast
        else:
            raise TypeError("cannot use {} as key".format(type(key)))

        d = self._compress(self._encode(value))
        g_logger.debug("set: data length: 0x%x", len(d))
 
        # always store first chunk in the hashval table
        fset(key, d[:CHUNK_SIZE])

        # store remaining chunks in the supval table CHUNK_TAG.
        # indices are stored in the hashval table CHUNK_INDEX_TAG
        # using `key`.
        if len(d) > 1024:
            # delete existing chunks
            index_refs = fget(key, CHUNK_INDEX_TAG)
            if index_refs is not None:
                first, last = self._decode(self._decompress(index_refs))
                for index_ref in range(first, last + 1):
                    self._n.supdel(index_ref, CHUNK_TAG)

            # add each chunk of data to the next available supval slot
            chunk_refs = []
            for i in range(CHUNK_SIZE, len(d), CHUNK_SIZE):
                chunk = d[i:i+CHUNK_SIZE]

                # race, but we're already dealing with writing to the IDB...
                # note: we assume all these allocations are continuous!
                chunk_ref = self._n.suplast(CHUNK_TAG)
                if chunk_ref == idaapi.BADNODE or chunk_ref is None:
                    chunk_ref = 0
                chunk_ref += 1

                self._n.supset(chunk_ref, chunk, CHUNK_TAG)
                chunk_refs.append(chunk_ref)

            first = chunk_refs[0]
            last = chunk_refs[-1]
            g_logger.debug("set: chunk run: 0x%x to 0x%x (0x%x chunks)",
                           first, last, last-first+1)
            refs = self._compress(self._encode((first, last)))
            
            if len(refs) > CHUNK_SIZE:
                raise BufferError()

            fset(key, refs, CHUNK_INDEX_TAG)

    def __delitem__(self, key):
        if key not in self:
            raise KeyError("'{}' not found".format(key))

        fdel = None
        fget = None
        if isinstance(key, basestring):
            fdel = self._n.hashdel
            fget = self._n.hashval
        elif isinstance(key, (int, long)):
            fdel = self._n.supdel
            fget = self._n.supval
        else:
            raise TypeError("cannot use {} as key".format(type(key)))

        fdel(key)
        
        # delete existing chunks
        index_refs = fget(key, CHUNK_INDEX_TAG)
        if index_refs is not None:
            first, last = self._decode(self._decompress(index_refs))
            for index_ref in range(first, last + 1):
                self._n.supdel(index_ref, CHUNK_TAG)
            fdel(key, CHUNK_INDEX_TAG)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key):
        try:
            if self[key] is not None:
                return True
            return False
        except KeyError:
            return False

    def iterkeys(self):
        ret = []
        i = self._n.sup1st()
        while i != idaapi.BADNODE:
            yield i
            i = self._n.supnxt(i)

        i = self._n.hash1st()
        while i != idaapi.BADNODE and i is not None:
            yield i
            i = self._n.hashnxt(i)

    def keys(self):
        return [k for k in self.iterkeys()]

    def itervalues(self):
        for k in self.iterkeys():
            yield self[k]

    def values(self):
        return [v for v in self.itervalues()]

    def iteritems(self):
        for k in self.iterkeys():
            yield k, self[k]

    def items(self):
        return [(k, v) for k, v in self.iteritems()]

    def kill(self):
        self._n.kill()
        self._n = idaapi.netnode(self._netnode_name, 0, True)

