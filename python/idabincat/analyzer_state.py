#!/usr/bin/env python2
"""
This file contains classes to manipulate the analyzer's state (output .ini
file) using python classes.
"""

import ConfigParser
import logging
import sys
from collections import defaultdict
import mlbincat


class AnalyzerState(object):
    def __init__(self):
        #: self.eip[EIP value] contains a State object
        self.stateAtEip = {}
        #: self.edges[nodeid] = [target node ids]
        self.edges = defaultdict(list)
        #: self.idaddr[nodeid] = (region, addr)
        self.nodeidaddr = {}

    @classmethod
    def run_analyzer(cls, initfile, outputfile, logfile):
        """
        Runs the analyzer using the given parameters.
        Returns an AnalyzerState instance based on the analyzer's output.
        """
        mlbincat.process(initfile, outputfile, logfile)
        ac = cls()
        ac.setStatesFromAnalyzerOutput(outputfile)
        return ac

    def setBinaryFromString(self, string):
        # TODO
        pass

    def setStatesFromAnalyzerOutput(self, filename):
        # Parse output ini file
        config = ConfigParser.ConfigParser()
        config.read(filename)
        for section in config.sections():
            if section == 'edges':
                for edgename, edge in config.items(section):
                    src, dst = edge.split(' -> ')
                    self.edges[src].append(dst)
                continue
            elif not section.startswith('address = '):
                logging.error("Unrecognized section in output file: %s",
                              section)
                sys.exit(1)
            # "address = (region, addr)"
            addrtxt = section[10:]
            address = ConcretePtrValue.fromAnalyzerOutput(addrtxt)
            state = State(address)
            state.setFromAnalyzerOutput(config.items(section))
            self.stateAtEip[address] = state
            self.nodeidaddr[state.nodeid] = address

    def _intToConcretePtrValue(self, eip):
        if type(eip) is int:
            addr = ConcretePtrValue("global", eip)
        else:
            addr = eip
        return addr

    def getStateAt(self, eip):
        addr = self._intToConcretePtrValue(eip)
        return self.stateAtEip[addr]

    def listNextStates(self, eip):
        """
        Returns a list of destination States after executing instruction at eip
        """
        addr = self._intToConcretePtrValue(eip)
        curStateId = self.stateAtEip[addr].nodeid
        nextIds = self.edges[curStateId]
        nextStates = [self.stateAtEip[self.nodeidaddr[i]] for i in nextIds]
        return nextStates

    def exportToFile(self, filename, eip):
        # TODO
        pass


class State(object):
    """
    TODO separate computed state from user-set state
    """
    def __init__(self, address, prettyname=""):
        """
        :param address: ConcretePtrValue instance
        """
        self.address = address
        #: self.ptrs['reg' or 'mem'][name or ConcretePtrValue object] =
        #: ("memory region", int address)
        self.ptrs = {'mem': {}, 'reg': {}}
        #: self.tainting['reg' or 'mem'][name or ConcretePtrValue object] =
        #: taint value (object)?
        self.tainting = {'mem': {}, 'reg': {}}
        #: self.stmts = [statement of the intermediate language]
        self.stmts = ""
        self.nodeid = ""
        self.prettyname = ""

    def __repr__(self):
        res = self.prettyname
        if not res:
            res = "State at address %s" % self.address
        return res

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
                    return False
            for t in allKeys:
                if self.tainting[region][t] != other.tainting[region][t]:
                    return False
        return True

    def listModifiedKeys(self, other):
        """
        Returns a set of (region, name) for which ptrs or tainting values
        differ between self and other.
        """
        results = set()
        regions = (set(self.ptrs.keys()) |
                   set(self.tainting.keys()) |
                   set(other.ptrs.keys()) |
                   set(other.tainting.keys()))
        for region in regions:
            sPr = self.ptrs[region]
            sTr = self.tainting[region]
            oPr = other.ptrs[region]
            oTr = other.tainting[region]
            sPrK = set(sPr)
            sTrK = set(sTr)
            oPrK = set(oPr)
            oTrK = set(oTr)

            results |= set((region,p) for p in sPrK ^ oPrK)
            results |= set((region,p) for p in oPrK & sPrK if sPr[p] != oPr[p])

            results |= set((region,p) for p in sTrK ^ oTrK)
            results |= set((region,p) for p in sTrK & oTrK if sTr[p] != oTr[p])
        return results

    def getPrintableDiff(self, other):
        res = "\n--- %s\n+++ %s\n" % (self, other)
        for region, address in self.listModifiedKeys(other):
            res += "@@ %s %s @@\n" % (region, address)
            if address not in self.ptrs[region]:
                res += "+ %s\n" % other.ptrs[region][address]
            elif address not in other.ptrs[region]:
                res += "- %s\n" % self.ptrs[region][address]
            elif self.ptrs[region][address] != other.ptrs[region][address]:
                res += "- %s\n" % self.ptrs[region][address]
                res += "+ %s\n" % other.ptrs[region][address]
            if address not in self.tainting[region]:
                res += "+ %s\n" % other.tainting[region][address]
            elif address not in other.tainting[region]:
                res += "- %s\n" % self.tainting[region][address]
            elif self.tainting[region][address] != other.tainting[region][address]:
                res += "- %s\n" % self.tainting[region][address]
                res += "+ %s\n" % other.tainting[region][address]
        return res

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
            elif k == "id":
                self.nodeid = v
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

    def __eq__(self, other):
        raise NotImplementedError

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

    @property
    def value(self):
        return (self.region, self.address)

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

    def __repr__(self):
        return "AbstractPtrValue(%s)" % self.value

    def __eq__(self, other):
        return self.value == other.value

    @classmethod
    def fromAnalyzerOutput(cls, s):
        return cls(s)


class Tainting(object):
    def __init__(self, tainting):
        self.tainting = tainting

    def __repr__(self):
        return "Tainting(%s)" % self.tainting

    def __ne__(self, other):
        return not self.__eq__(other)

    def __eq__(self, other):
        return self.tainting == other.tainting

    @classmethod
    def fromAnalyzerOutput(cls, s):
        return cls(s)
