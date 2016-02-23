#!/usr/bin/env python2
# This file describes tests for single instructions

import pytest
import ConfigParser
import logging
import sys
import copy


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
        #: self.ptrs[memory address or pointer name] =
        #: ("memory region", int address)
        self.ptrs = {'mem': {}, 'reg': {}}
        #: self.tainting["reg" or "mem"][name or ConcretePtrValue object] =
        #: taint value (object)?
        self.tainting = {'mem': {}, 'reg': {}}
        #: self.stmts = [statement of the intermediate language]
        self.stmts = ""

    def __eq__(self, other):
        for region in 'mem', 'reg':
            if set(self.ptrs[region].keys()) != set(other.ptrs[region].keys()):
                # might have to be refined
                logging.error("different set of %s keys between states : %s vs %s", region, self.ptrs[region].keys(), other.ptrs[region].keys())
                return False
            if set(self.tainting[region].keys()) != set(other.tainting[region].keys()):
                # might have to be refined
                logging.error("different set of tainting keys between states. Unique key: %s", set(self.tainting[region].keys()).symmetric_difference(set(other.tainting[region].keys())))
                return False
            for ptr in self.ptrs[region].keys():
                if (self.ptrs[region][ptr] != other.ptrs[region][ptr]):
                    logging.error("different ptr values between states %s", region)
                    return False
            for t in (set(self.tainting[region].keys()) | set(other.tainting[region].keys())):
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


@pytest.fixture(scope='function', params=['template0.ini'])
def initialState(request):
    # TODO generate instead of using a fixed file, using States class
    # (not implemented yet)
    # TODO return object
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
    #TODO add initial concrete ptr to initialState
    ac = analyzer(initialState, binarystr='\x90')
    assert ac.getStateAt(0x00) == ac.getStateAt(0x1)
    # TODO add helper in AnalyzerConfig to perform a check at each eip
    for state in ac.stateAtEip.values():
        assert state.ptrs['reg']['esp'].region == 'stack'


# tests for opcodes 0x40-0x5F: inc, dec, push, pop
testregisters = list(enumerate(
 ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
))


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_push(analyzer, initialState, register):
    regid, regname = register
    opcode = 0x50 + regid
    ac = analyzer(initialState, binarystr=chr(opcode))
    stateBefore = ac.getStateAt(0x00)
    stateAfter = ac.getStateAt(0x01)

    # build expected state
    expectedStateAfter = copy.deepcopy(stateBefore)
    expectedStateAfter.ptrs['reg']['esp'] -= 4
    expectedStateAfter.ptrs['mem'][stateBefore.ptrs['reg']['esp']] = \
        stateBefore.ptrs['reg'][regname]
    expectedStateAfter.tainting['mem'][stateBefore.ptrs['reg']['esp']] = \
        stateBefore.tainting['reg'][regname]

    assert expectedStateAfter == stateAfter

    # TODO use edges described in .ini file, do not hardcode addresses


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_pop(analyzer, initialState, register):
    regid, regname = register
    opcode = 0x58 + regid
    ac = analyzer(initialState, binarystr=chr(opcode))
    stateBefore = ac.getStateAt(0x00)
    stateAfter = ac.getStateAt(0x01)

    # build expected state
    expectedStateAfter = copy.deepcopy(stateBefore)
    expectedStateAfter.ptrs['reg']['esp'] += 4
    expectedStateAfter.ptrs['reg'][regname] = \
        stateBefore.ptrs['mem'][stateBefore.ptrs['reg']['esp']]
    expectedStateAfter.tainting['reg'][regname] = \
        stateBefore.tainting['mem'][stateBefore.ptrs['reg']['esp']]

    assert expectedStateAfter == stateAfter

    # TODO use edges described in .ini file, do not hardcode addresses


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_inc(analyzer, initialState, register):
    regid, regname = register
    opcode = 0x40 + regid
    ac = analyzer(initialState, binarystr=chr(opcode))
    stateBefore = ac.getStateAt(0x00)
    stateAfter = ac.getStateAt(0x01)
    expectedStateAfter = copy.deepcopy(stateBefore)

    # XXX taint more bits?
    expectedStateAfter.ptrs['reg'][regname] += 1

    assert expectedStateAfter == stateAfter

    # TODO use edges described in .ini file, do not hardcode addresses


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_dec(analyzer, initialState, register):
    regid, regname = register
    opcode = 0x48 + regid
    ac = analyzer(initialState, binarystr=chr(opcode))
    stateBefore = ac.getStateAt(0x00)
    stateAfter = ac.getStateAt(0x01)
    expectedStateAfter = copy.deepcopy(stateBefore)

    # XXX taint more bits?
    expectedStateAfter.ptrs['reg'][regname] -= 1

    assert expectedStateAfter == stateAfter

    # TODO use edges described in .ini file, do not hardcode addresses
