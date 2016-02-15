#!/usr/bin/env python2
# This file describes tests for single instructions

import pytest
import ConfigParser
import logging
import sys
import collections


class AnalyzerConfig(object):
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
            if not section.startswith('address = '):
                logging.error("Unrecognized section in output file: %s",
                              section)
                sys.exit(1)
            zxidx = section.index("0x")  # [address = 0xFF..FF]
            sz = len(section) - (zxidx+1)
            address = int(section[zxidx:zxidx+sz], 16)
            state = State(address)
            state.setFromAnalyzerOutput(config.items(section))
            self.stateAtEip[address] = state

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
        #: self.ptrs[memory address or pointer name] =
        #: ("memory region", int address)
        self.ptrs = {'mem': {}, 'reg': {}}
        #: self.tainting["reg" or "mem"][name or ConcretePtrValue object] =
        #: taint value (object)?
        self.tainting = {}
        #: self.stmts = [statement of the intermediate language]
        self.stmts = ""

    def __eq__(self, other):
        if set(self.ptrs['mem'].keys()) != set(other.ptrs['mem'].keys()) or\
                set(self.ptrs['reg'].keys()) != set(other.ptrs['reg'].keys()):
            # might have to be refined
            logging.error("different set of keys between states")
            return False
        for ptrtype in 'mem', 'reg':
            for ptr in self.ptrs[ptrtype].keys():
                if (self.ptrs[ptrtype][ptr] != other.ptrs[ptrtype][ptr]):
                    return False
        if set(self.tainting.keys()) != set(other.tainting.keys()):
            # might have to be refined
            logging.error("different set of keys between states")
            return False
        for t in (set(self.tainting.keys()) | set(other.tainting.keys())):
            if self.tainting[t] != other.tainting[t]:
                return False
        return True

    def setFromAnalyzerOutput(self, outputkv):
        """
        :param outputkv: list of (key, value) tuples for each property set by
            the analyzer at this EIP
        """
        for k, v in outputkv:
            if k.startswith('tainting '):
                self.tainting[k[9:]] = Tainting.fromAnalyzerOutput(v)
            elif k.startswith('pointer '):
                ptrloc = k[8:]
                if ptrloc.startswith('mem ['):
                    ptrtype = 'mem'
                    key = ConcretePtrValue.fromAnalyzerOutput(ptrloc[6:-2])
                elif ptrloc.startswith('reg ['):
                    ptrtype = 'reg'
                    key = ptrloc[5:-1]
                else:
                    raise NotImplementedError('Unsupported ptrtype')
                self.ptrs[ptrtype][key] = PtrValue.fromAnalyzerOutput(v)
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
<<<<<<< local
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
=======
    def __init__(self, region, address, bot):
        self.region = region
>>>>>>> other
        self.address = address
        self.bot = bot

    def __repr__(self):
        return "ConcretePtrValue(%s, %d)" % (self.region, self.address)

    def __hash__(self):
        return hash((type(self), self.region, self.address))

    def __eq__(self, other):
        
        return self.bot == other.bot and self.region == other.region and self.address == other.address

    def __add__(self, other):
        if type(other) is not int:
            raise NotImplemented
        return ConcretePtrValue(self.region, self.address + other)

    def __sub__(self, other):
        return self + (-other)

    @classmethod
    def fromAnalyzerOutput(cls, s):
<<<<<<< local
        z, v = s.split(',')
        v = int(v, 16)
        return cls(z, v)

=======
        try:
            z, v = s[1:-1].split(',')
            v = int(v, 16)
            return cls(z, v, False)
        except:
            return cls(None, None, True)
>>>>>>> other

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


@pytest.fixture(scope='function', params=['template0.ini'])
def initialState(request):
    # TODO generate instead of using a fixed file, using States class
    # (not implemented yet)
    return open(request.param, 'rb').read()


@pytest.fixture(scope='function')
def analyzer(tmpdir, request):
    import mlbincat

    def run_analyzer(initialState, binarystr):
        """
        Create .ini and .bin
        Run analyzer, get resulting state.
        """
        oldpath = tmpdir.chdir()

        def resetpwd():  # test teardown; remove once init.ini is auto-generated
            oldpath.chdir()
        request.addfinalizer(resetpwd)

        initfile = str(tmpdir.join('init.ini'))
        with open(initfile, 'w+') as f:
            f.write(initialState)
        binfile = str(tmpdir.join('file.bin'))
        with open(binfile, 'w+') as f:
            f.write(binarystr)

        # TODO write to init
        outputfile = str(tmpdir.join('end.ini'))
        logfile = str(tmpdir.join('log.txt'))
        mlbincat.process(initfile, outputfile, logfile)
        ac = AnalyzerConfig()
        ac.setStatesFromAnalyzerOutput(outputfile)
        return ac
    return run_analyzer


def test_nop(analyzer, initialState):
    ac = analyzer(initialState, binarystr='\x90')
    #assert ac.stateAtEip[0x00] == ac.stateAtEip[0x1]
    # TODO add helper in AnalyzerConfig to perform a check at each eip
    for eip in ac.stateAtEip.keys():
<<<<<<< local
        assert ac.stateAtEip[eip].ptrs['reg']['esp'].region == 'stack'
=======
        assert ac.stateAtEip[eip].ptrs['reg [esp]'].region == 'Stack'
>>>>>>> other


def test_pushebp(analyzer, initialState):
    ac = analyzer(initialState, binarystr='\x55')
<<<<<<< local
    stateBefore = ac.stateAtEip[0x00]
    stateAfter = ac.stateAtEip[0x01]

    assert stateAfter.ptrs['reg']['esp'] == \
        stateBefore.ptrs['reg']['esp'] - 4

    assert stateAfter.ptrs['mem'][stateBefore.ptrs['reg']['esp']] == \
        stateBefore.ptrs['reg']['ebp']

    # TODO use edges described in .ini file
=======
    assert ac.stateAtEip[0x01].ptrs['reg [eax]'] == \
        ac.stateAtEip[0x00].ptrs['reg [eax]']
    # TODO check stack
>>>>>>> other
    # TODO check that nothing else has changed
