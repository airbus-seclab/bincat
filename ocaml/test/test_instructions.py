#!/usr/bin/env python2
"""
This file describes tests for single instructions
"""

import pytest
import subprocess
import copy
import binascii
from pybincat import program


@pytest.fixture(scope='function', params=['template0.ini'])
def initialState(request):
    # TODO generate instead of using a fixed file, using States class
    # (not implemented yet)
    # TODO return object
    return open(request.param, 'rb').read()


@pytest.fixture(scope='function')
def analyzer(tmpdir, request):

    def run_analyzer(initialState, binarystr):
        """
        Create .ini and .bin
        Run analyzer, get resulting state.
        """
        oldpath = tmpdir.chdir()

        def resetpwd():
            """
            test teardown; remove once init.ini is auto-generated
            """
            oldpath.chdir()
        request.addfinalizer(resetpwd)

        initialState = initialState.format(code_length=len(binarystr))
        initfname = str(tmpdir.join('init.ini'))
        with open(initfname, 'w+') as f:
            f.write(initialState)
        binfile = str(tmpdir.join('file.bin'))
        with open(binfile, 'w+') as f:
            f.write(binarystr)

        outfname = str(tmpdir.join('end.ini'))
        logfname = str(tmpdir.join('log.txt'))
        p = program.Program.from_filenames(initfname, outfname, logfname)
        return p
    return run_analyzer


testregisters = list(enumerate(
    ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
))


def getNextState(prgm, curState):
    """
    Helper function: check that there is only one destination state, return it.
    """
    nextStates = prgm.next_states(curState.address)
    assert len(nextStates) == 1, \
        "expected exactly 1 destination state after running this instruction"
    nextState = nextStates[0]
    assert nextState is not None, \
        "Expected defined state after running this instruction"
    return nextState


def clearFlag(my_state, name):
    """
    Set flag to 0, untainted - helper for tests
    XXX for most tests, flags should inherit taint
    """
    v = program.Value('reg', name)
    my_state[v] = program.Value('global', 0x0)


def setFlag(my_state, name):
    """
    Set flag to 1, untainted - helper for tests
    XXX for most tests, flags should inherit taint
    """
    v = program.Value('reg', name)
    my_state[v] = program.Value('global', 1)

def calc_zf(my_state, val):
    zf = 1 if val == 0 else 0
    setReg(my_state, "zf", zf)

def calc_sf(my_state, val):
    sf = 1 if val & 0x80000000!= 0 else 0
    setReg(my_state, "sf", sf)

def calc_pf(my_state, val):
    par = ((val >> 1) & 0x55555555) + (val & 0x55555555)
    par = ((par >> 2) & 0x33333333) + (par & 0x33333333)
    par = ((par >> 4) & 0x0f0f0f0f) + (par & 0x0f0f0f0f)
    par = ((par >> 8) & 0x00ff00ff) + (par & 0x00ff00ff)
    par = (par >> 16) + (par & 0xffff)
    par &= 1
    pf = 0 if par else 1
    setReg(my_state, "pf", pf)

def taintFlag(my_state, name):
    """
    Taint flag - helper for tests
    XXX for most tests, flags should inherit taint
    """
    v = program.Value('reg', name)
    p = my_state[v]
    p.taint = 1
    p.ttop = p.tbot = 0


def setReg(my_state, name, val, taint=0):
    v = program.Value('reg', name)
    my_state[v] = program.Value('global', val, taint=taint)


def prepareExpectedState(state):
    return copy.deepcopy(state)


def assertEqualStates(state, expectedState, opcodes=""):
    """
    :param opcodes: str
    """
    if opcodes:
        try:
            p = subprocess.Popen(["ndisasm", "-u", "-"],
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE)
            out, err = p.communicate(str(opcodes))
            out = "\n"+out
        except OSError:
            out = ""
    else:
        out = ""
    assert type(state) is program.State
    assert type(expectedState) is program.State
    assert state == expectedState, "States should be identical\n" + out + \
        state.diff(expectedState, "Observed ", "Expected ")


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_xor_reg_self(analyzer, initialState, register):
    """
    Tests opcode 0x33 - xor self
    """
    regid, regname = register
    opcode = "\x33" + chr(0xc0 + regid + (regid << 3))
    prgm = analyzer(initialState, binarystr=opcode)
    stateBefore = prgm[0x00]
    stateAfter = getNextState(prgm, stateBefore)
    expectedStateAfter = prepareExpectedState(stateBefore)
    expectedStateAfter.address += len(opcode)  # pretty debug msg

    setReg(expectedStateAfter, regname, 0)
    clearFlag(expectedStateAfter, "sf")
    clearFlag(expectedStateAfter, "of")
    clearFlag(expectedStateAfter, "cf")
    clearFlag(expectedStateAfter, "af")
    setFlag(expectedStateAfter, "zf")
    setFlag(expectedStateAfter, "pf")
    # XXX check taint (not tainted)

    assertEqualStates(stateAfter, expectedStateAfter)


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_inc(analyzer, initialState, register):
    """
    Tests opcodes 0x40-0x47 == inc eax--edi
    """
    regid, regname = register
    opcode = chr(0x40 + regid)
    prgm = analyzer(initialState, binarystr=opcode)
    stateBefore = prgm[0x00]
    stateAfter = getNextState(prgm, stateBefore)
    expectedStateAfter = prepareExpectedState(stateBefore)
    expectedStateAfter.address += len(opcode)  # pretty debug msg
    for flag in ('of', 'sf', 'zf', 'af', 'pf'):
        clearFlag(expectedStateAfter, flag)

    # XXX check flags
    # XXX set zf properly
    # XXX taint more bits?
    expectedStateAfter[program.Value('reg', regname)] += 1
    # XXX flags should be tainted - known bug

    assertEqualStates(stateAfter, expectedStateAfter, opcode)


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_dec(analyzer, initialState, register):
    """
    Tests opcodes 0x48-0x4F
    """
    regid, regname = register
    opcode = chr(0x48 + regid)
    prgm = analyzer(initialState, binarystr=opcode)
    stateBefore = prgm[0x00]
    stateAfter = getNextState(prgm, stateBefore)
    expectedStateAfter = prepareExpectedState(stateBefore)
    expectedStateAfter.address += len(opcode)  # pretty debug msg

    expectedStateAfter[program.Value('reg', regname)] -= 1
    # flags
    for flag in ('of', 'sf', 'zf', 'af', 'pf'):
        clearFlag(expectedStateAfter, flag)
    if stateBefore[program.Value('reg', regname)].value == 1:
        expectedStateAfter[program.Value('reg', 'zf')].value = 1
    # PF - inefficient but understandable way of counting set bits
    nbBitsSet = bin(expectedStateAfter[
        program.Value('reg', regname)].value & 0xFF).count('1')
    expectedStateAfter[program.Value('reg', 'pf')].value = \
        (nbBitsSet + 1) % 2
    # XXX check flags

    # XXX taint more bits?
    assertEqualStates(stateAfter, expectedStateAfter)


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_push(analyzer, initialState, register):
    """
    Tests opcodes 0x50-0x57
    """
    regid, regname = register
    opcode = chr(0x50 + regid)
    prgm = analyzer(initialState, binarystr=opcode)
    stateBefore = prgm[0x00]
    stateAfter = getNextState(prgm, stateBefore)

    # build expected state
    expectedStateAfter = prepareExpectedState(stateBefore)
    expectedStateAfter.address += len(opcode)  # pretty debug msg
    expectedStateAfter[program.Value('reg', 'esp')] -= 4
    expectedStateAfter[program.Value(
        'stack', expectedStateAfter[program.Value('reg', 'esp')].value)] = \
        stateBefore[program.Value('reg', regname)]

    assertEqualStates(stateAfter, expectedStateAfter)


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_pop(analyzer, initialState, register):
    """
    Tests opcodes 0x58-0x5F
    """
    regid, regname = register
    opcode = chr(0x58 + regid)
    prgm = analyzer(initialState, binarystr=opcode)
    stateBefore = prgm[0x00]
    stateAfter = getNextState(prgm, stateBefore)

    # build expected state
    expectedStateAfter = prepareExpectedState(stateBefore)
    expectedStateAfter.address += len(opcode)  # pretty debug msg
    expectedStateAfter[program.Value('reg', 'esp')] += 4
    expectedStateAfter[program.Value('reg', regname)] = \
        stateBefore[program.Value(
            'stack', stateBefore[program.Value('reg', 'esp')].value)]

    assertEqualStates(stateAfter, expectedStateAfter, opcode)


def test_sub(analyzer, initialState):
    # sub esp, 0x1234
    hexstr = "81ec34120000"
    prgm = analyzer(initialState, binarystr=binascii.unhexlify(hexstr))
    stateBefore = prgm[0x00]
    stateAfter = getNextState(prgm, stateBefore)

    # build expected state
    expectedStateAfter = prepareExpectedState(stateBefore)
    expectedStateAfter.address += len(hexstr)  # pretty debug msg
    expectedStateAfter[program.Value('reg', 'esp')] = \
        stateBefore[program.Value('reg', 'esp')] - 0x1234
    # TODO check taint
    assertEqualStates(stateAfter, expectedStateAfter)


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_or_reg_ff(analyzer, initialState, register):
    """
    OR register with 0xff
    """
    # or ebx,0xffffffff
    regid, regname = register
    opcode = "\x83" + chr(0xc8 + regid) + "\xff"
    prgm = analyzer(initialState, opcode)
    stateBefore = prgm[0x00]
    stateAfter = getNextState(prgm, stateBefore)

    # build expected state
    expectedStateAfter = prepareExpectedState(stateBefore)
    expectedStateAfter.address += len(opcode)  # pretty debug msg
    setReg(expectedStateAfter, regname, 0xffffffff)
    # TODO check taint
    assertEqualStates(stateAfter, expectedStateAfter, opcode)


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_mov_reg_ebpm6(analyzer, initialState, register):
    regid, regname = register
    # mov    reg,DWORD PTR [ebp-0x6]
    opcode = "\x8b" + chr(0x45 + (regid << 3)) + "\xfa"
    prgm = analyzer(initialState, binarystr=opcode)
    stateBefore = prgm[0x00]
    stateAfter = getNextState(prgm, stateBefore)

    # build expected state
    expectedStateAfter = prepareExpectedState(stateBefore)
    expectedStateAfter.address += len(opcode)  # pretty debug msg
    expectedStateAfter[program.Value('reg', regname)] = \
        stateBefore[program.Value(
            'stack', stateBefore[program.Value('reg', 'ebp')].value - 6)]
    assertEqualStates(stateAfter, expectedStateAfter, opcode)


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_mov_ebp_reg(analyzer, initialState, register):
    regid, regname = register
    opcode = "\x8b" + chr(0x28 + regid)
    prgm = analyzer(initialState, binarystr=opcode)
    stateBefore = prgm[0x00]
    stateAfter = getNextState(prgm, stateBefore)

    # build expected state
    expectedStateAfter = prepareExpectedState(stateBefore)
    expectedStateAfter.address += len(opcode)  # pretty debug msg
    expectedStateAfter[program.Value('reg', 'ebp')] = \
        stateBefore[program.Value('reg', regname)]
    assertEqualStates(stateAfter, expectedStateAfter, opcode)


def test_nop(analyzer, initialState):
    """
    Tests opcode 0x90
    """
    # TODO add initial concrete ptr to initialState
    prgm = analyzer(initialState, binarystr='\x90')
    stateBefore = prgm[0x00]
    stateAfter = getNextState(prgm, stateBefore)
    assertEqualStates(stateBefore, stateAfter)


def test_and_esp(analyzer, initialState):
    """
    Test   and %esp,0xfffffff0
    """
    opcode = "\x83\xe4\xf0"
    prgm = analyzer(initialState, binarystr=opcode)
    stateBefore = prgm[0]
    stateAfter = getNextState(prgm, stateBefore)
    expectedStateAfter = prepareExpectedState(stateBefore)
    expectedStateAfter[program.Value("reg", "esp")] &= 0xfffffff0
    esp = expectedStateAfter[program.Value("reg", "esp")].value
    clearFlag(expectedStateAfter, "of")
    clearFlag(expectedStateAfter, "cf")
    calc_zf(expectedStateAfter, esp)
    calc_sf(expectedStateAfter, esp)
    calc_pf(expectedStateAfter, esp)

    assertEqualStates(stateAfter, expectedStateAfter, opcode)
