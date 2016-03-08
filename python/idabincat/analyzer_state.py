#!/usr/bin/env python2
"""
This file contains classes to manipulate the analyzer's state (output .ini
file) using python classes.
"""
# This file contains

import ConfigParser
import logging
import sys


class AnalyzerState(object):
    """
    TODO move to separate file, re-use in IDA plugin
    """
    def __init__(self):
        #: self.eip[EIP value] contains a State object
        self.stateAtEip = {}

    def setBinaryFromString(self, string):
        # TODO
        pass

    def setStatesFromAnalyzerOutput(self, filename):
        # Parse output ini file
        config = ConfigParser.ConfigParser()
        config.read(filename)
        for section in config.sections():
            if section == ('edges'):
                continue
            elif not section.startswith('address = '):
                logging.error("Unrecognized section in output file: %s",
                              section)
                sys.exit(1)
            addrtxt, nodeid = section[10:].rsplit(',', 1)
            address = ConcretePtrValue.fromAnalyzerOutput(addrtxt)
            state = State(address)
            state.setFromAnalyzerOutput(config.items(section))
            self.stateAtEip[address] = state

    def getStateAt(self, eip):
        if type(eip) is int:
            addr = ConcretePtrValue("global", eip)
        else:
            addr = eip
        return self.stateAtEip[addr]

    def exportToFile(self, filename, eip):
        # TODO
        pass


class State(object):
    """
    TODO move to separate file, re-use in IDA plugin
    TODO separate computed state from user-set state
    """
    def __init__(self, address):
        self.address = ""
        #: self.ptrs['reg' or 'mem'][name or ConcretePtrValue object] =
        #: ("memory region", int address)
        self.ptrs = {'mem': {}, 'reg': {}}
        #: self.tainting['reg' or 'mem'][name or ConcretePtrValue object] =
        #: taint value (object)?
        self.tainting = {'mem': {}, 'reg': {}}
        #: self.stmts = [statement of the intermediate language]
        self.stmts = ""

    def __eq__(self, other):
        for region in 'mem', 'reg':
            ptrKeys = set(self.ptrs[region].keys())
            otherPtrKeys = set(other.ptrs[region].keys())
            taintingKeys = set(self.tainting[region].keys())
            otherTaintingKeys = set(other.tainting[region].keys())
            allKeys = ptrKeys | otherPtrKeys | taintingKeys | otherTaintingKeys
            if ptrKeys != otherPtrKeys:
                # might have to be refined
                logging.error(
                    "different set of %s keys between states : %s vs %s",
                    region, self.ptrs[region].keys(),
                    other.ptrs[region].keys())
                return False
            if taintingKeys != otherTaintingKeys:
                # might have to be refined
                logging.error(
                    "different set of tainting keys between states. Unique key: %s",
                    taintingKeys.symmetric_difference(otherTaintingKeys))
                return False
            for key in allKeys:
                if (self.ptrs[region][key] != other.ptrs[region][key]):
                    logging.error("different ptr values between states %s %s",
                                  region, key)
                    return False
            for t in allKeys:
                if self.tainting[region][t] != other.tainting[region][t]:
                    return False
        return True

    def setFromAnalyzerOutput(self, outputkv):
        """
        :param outputkv: list of (key, value) tuples for each property set by
            the analyzer at this EIP
        """
        for k, v in outputkv:
            if k.startswith('tainting '):
                ptrloc = k[9:]
                if ptrloc.startswith('mem ['):
                    region = 'mem'
                    key = ConcretePtrValue.fromAnalyzerOutput(ptrloc[6:-2])
                elif ptrloc.startswith('reg ['):
                    region = 'reg'
                    key = ptrloc[5:-1]
                else:
                    raise NotImplementedError('Unsupported ptrtype')
                self.tainting[region][key] = Tainting.fromAnalyzerOutput(v)
            elif k.startswith('pointer '):
                ptrloc = k[8:]
                if ptrloc.startswith('mem ['):
                    region = 'mem'
                    key = ConcretePtrValue.fromAnalyzerOutput(ptrloc[6:-2])
                elif ptrloc.startswith('reg ['):
                    region = 'reg'
                    key = ptrloc[5:-1]
                else:
                    raise NotImplementedError('Unsupported region')
                self.ptrs[region][key] = PtrValue.fromAnalyzerOutput(v)
            elif k.startswith('statements'):
                self.stmts = Stmt.fromAnalyzerOutput(v)
            else:
                logging.error("Unrecognized key while parsing state: %s", k)
                sys.exit(1)


class Stmt(object):
    def __init__(self, stmts):
        self.stmts = stmts

    def __ne__(self, other):
            return not self.__eq__(other)

    def __eq__(self, other):
        return self.stmts == other.stmts

    @classmethod
    def fromAnalyzerOutput(cls, s):
        return cls(s)


class PtrValue(object):
    def __ne__(self, other):
        return not self.__eq__(other)

    @classmethod
    def fromAnalyzerOutput(cls, s):
        if s.startswith('('):
            return ConcretePtrValue.fromAnalyzerOutput(s[1:-1])
        else:
            return AbstractPtrValue.fromAnalyzerOutput(s)


class ConcretePtrValue(PtrValue):
    def __init__(self, region, address):
        self.region = region.lower()
        self.address = address

    def __repr__(self):
        return "ConcretePtrValue(%s, %d)" % (self.region, self.address)

    def __hash__(self):
        return hash((type(self), self.region, self.address))

    def __eq__(self, other):
        return self.region == other.region and self.address == other.address

    def __add__(self, other):
        if type(other) is not int:
            raise NotImplemented
        return ConcretePtrValue(self.region, self.address + other)

    def __sub__(self, other):
        return self + (-other)

    @classmethod
    def fromAnalyzerOutput(cls, s):
        if s[0] == '(' and s[-1] == ')':
            s = s[1:-1]
        z, v = s.split(',')
        v = int(v, 16)
        return cls(z, v)


class AbstractPtrValue(PtrValue):
    def __init__(self, value):
        self.value = value

    def __eq__(self, other):
        return self.value == other.value

    @classmethod
    def fromAnalyzerOutput(cls, s):
        return cls(s)


class Tainting(object):
    def __init__(self, tainting):
        self.tainting = tainting

    def __ne__(self, other):
        return not self.__eq__(other)

    def __eq__(self, other):
        return self.tainting == other.tainting

    @classmethod
    def fromAnalyzerOutput(cls, s):
        return cls(s)
