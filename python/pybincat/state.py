#!/usr/bin/env python2
"""
This file contains classes to manipulate the analyzer's state (output .ini
file) using python classes.
"""

import ConfigParser
import logging
import sys
from collections import defaultdict
import re
from  pybincat.tools import parsers

class AnalyzerState(object):
    """
    Interface to run the analyzer, and parse its output.
    TODO also generate its input.
    """
    def __init__(self):
        #: self.stateAtEip[EIP value] contains a State object
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

        :param initfile: path to the .ini file containing the initial state
        :param outputfile: path to the analyzer output file
        :param logfile: path to the analyzer log file
        """
        from pybincat import mlbincat
        mlbincat.process(initfile, outputfile, logfile)
        ac = cls()
        ac.setStatesFromAnalyzerOutput(outputfile)
        return ac

    def setBinaryFromString(self, string):
        """
        TODO not implemented yet.
        """
        pass

    re_val = re.compile("\((?P<region>[^,]+)\s*,\s*(?P<value>[x0-9a-fA-F_,=? ]+)\)")

    def setStatesFromAnalyzerOutput(self, filename):
        """
        Parses states contained in the analyzer's output file.

        :param filename: path to the analyzer output file
        """
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
            m = self.re_val.match(section[10:])
            if not m:
                raise Exception("Cannot parse section name (%r)" % section)
            address = PtrValue(m.group("region"), int(m.group("value"),0))
            state = State(address)
            state.setFromAnalyzerOutput(config.items(section))
            self.stateAtEip[address] = state
            self.nodeidaddr[state.nodeid] = address

    def _intToPtrValue(self, eip):
        if type(eip) is int:
            addr = PtrValue("global", eip)
        else:
            addr = eip
        return addr

    def getStateAt(self, eip):
        """
        Returns state at provided EIP

        :param eip: int or PtrValue
        """
        addr = self._intToPtrValue(eip)
        return self.stateAtEip[addr]

    def listNextStates(self, eip):
        """
        Returns a list of destination States after executing instruction at eip

        :param eip: int or PtrValue
        """
        addr = self._intToPtrValue(eip)
        curStateId = self.stateAtEip[addr].nodeid
        nextIds = self.edges[curStateId]
        nextStates = [self.stateAtEip[self.nodeidaddr[i]] for i in nextIds]
        return nextStates

    def exportToFile(self, filename, eip):
        """
        TODO not implemented yet.
        """
        pass


class State(object):
    """
    Stores analyzer state at a specific address.
    TODO separate computed state from user-set state
    """
    def __init__(self, address, prettyname=""):
        """
        :param address: PtrValue instance
        """
        self.address = address
        #: self.ptrs['reg' or 'mem'][name or PtrValue object] =
        #: ("memory region", int address)
        self.ptrs = {'mem': {}, 'reg': {}}
        #: self.tainting['reg' or 'mem'][name or PtrValue object] =
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
        return True

    def listModifiedKeys(self, other):
        """
        Returns a set of (region, name) for which ptrs or tainting values
        differ between self and other.
        """
        results = set()
        regions = set(self.ptrs) | set(other.ptrs)
        for region in regions:
            sPr = self.ptrs[region]
            oPr = other.ptrs[region]
            sPrK = set(sPr)
            oPrK = set(oPr)

            results |= set((region,p) for p in sPrK ^ oPrK)
            results |= set((region,p) for p in oPrK & sPrK if sPr[p] != oPr[p])

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
        return res

    re_region = re.compile("(?P<region>reg|mem)\s*\[(?P<adrs>[^]]+)\]")
    re_valtaint = re.compile("\((?P<kind>[^,]+)\s*,\s*(?P<value>[x0-9a-fA-F_,=? ]+)\s*(!\s*(?P<taint>[x0-9a-fA-F_,=? ]+))?.*\).*")
    def setFromAnalyzerOutput(self, outputkv):
        """
        :param outputkv: list of (key, value) tuples for each property set by
            the analyzer at this EIP
        """

        for i,(k,v) in enumerate(outputkv):
            if k == "id":
                self.nodeid = v
                continue
            m = self.re_region.match(k)
            if not m:
                raise Exception("Parsing error (entry %i, key=%r)" % (i,k))
            region = m.group("region")
            adrs = m.group("adrs")

            m = self.re_valtaint.match(v)
            if not m:
                raise Exception("Parsing error (entry %i: value=%r)" % (i,v))
            kind = m.group("kind")
            val = m.group("value")
            taint = m.group("taint")

            self.ptrs[region][adrs] = PtrValue.fromAnalyzerOutput(kind, val, taint)
            

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
    def __init__(self, region, value, vtop=0, vbot=0, taint=0, ttop=0, tbot=0):
        self.region = region.lower()
        self.value = value
        self.vtop = vtop
        self.vbot = vbot
        self.taint = taint
        self.ttop = ttop
        self.tbot = tbot

    def __repr__(self):
        return "PtrValue(%s, %s ! %s)" % (
            self.region,
            parsers.val2str(self.value, self.vtop, self.vbot),
            parsers.val2str(self.taint, self.ttop, self.tbot))

    def __hash__(self):
        return hash((type(self), self.region, self.value,
                     self.vtop, self.vbot, self.taint,
                     self.ttop, self.tbot))

    def __eq__(self, other):
        return (self.region == other.region 
                and self.value == other.value and self.taint == other.taint
                and self.vtop == other.vtop and self.ttop == other.ttop
                and self.vbot == other.vbot and self.tbot == other.tbot)

    def __ne__(self, other):
        return not (self == other)

    def __add__(self, other):
        other = getattr(other, "value", other)
        return self.__class__(self.region, self.value+other, 
                              self.vtop, self.vbot, self.taint,
                              self.ttop, self.tbot)
    def __sub__(self, other):
        other = getattr(other, "value", other)
        return self.__class__(self.region, self.value-other, 
                              self.vtop, self.vbot, self.taint,
                              self.ttop, self.tbot)
    def is_concrete(self):
        return self.vtop == 0 and self.vbot == 0
        

    @classmethod
    def fromAnalyzerOutput(cls, region, s, t):
        value, vtop, vbot = parsers.parse_val(s)
        taint, ttop, tbot = parsers.parse_val(t) if t is not None else (0,0,0)
        return cls(region, value, vtop, vbot, taint, ttop, tbot)


