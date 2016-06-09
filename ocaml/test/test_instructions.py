#!/usr/bin/env python2
"""
This file describes tests for single instructions
"""

import pytest
import subprocess
import copy
import binascii
from pybincat import cfa


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
        p = cfa.CFA.from_filenames(initfname, outfname, logfname)
        return p
    return run_analyzer


testregisters = list(enumerate(
    ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
))


def assertNoNextState(prgm, curState):
    """
    Helper function: check that there is no destination state.
    """
    nextStates = prgm.next_states(curState.address)
    assert len(nextStates) == 0, \
        "This state is expected NOT to have any destination state."


def getNextState(prgm, curState):
    """
    Helper function: check that there is only one destination state, return it.
    """
    nextStates = prgm.next_states(curState.node_id)
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
    v = cfa.Value('reg', name)
    my_state[v] = cfa.Value('global', 0x0)


def setFlag(my_state, name):
    """
    Set flag to 1, untainted - helper for tests
    XXX for most tests, flags should inherit taint
    """
    v = cfa.Value('reg', name)
    my_state[v] = cfa.Value('global', 1)


def undefBitFlag(my_state, name):
    """
    Set flag to undefined.
    XXX specify register len?
    """
    v = cfa.Value('reg', name)
    my_state[v] = cfa.Value('?', 0, vtop=1)


def calc_af(my_state, op1, op2, val):
    af = ((val ^ op1 ^ op2) & 0x4) >> 3
    setReg(my_state, 'af', af)


def calc_zf(my_state, val):
    zf = 1 if val == 0 else 0
    setReg(my_state, 'zf', zf)


def calc_sf(my_state, val):
    sf = 1 if val & 0x80000000 != 0 else 0
    setReg(my_state, 'sf', sf)


def calc_pf(my_state, val):
    par = val ^ (val >> 1)
    par = par ^ (par >> 2)
    par = par ^ (par >> 4)
    par &= 1
    pf = 0 if par else 1
    setReg(my_state, 'pf', pf)


def taintFlag(my_state, name):
    """
    Taint flag - helper for tests
    XXX for most tests, flags should inherit taint
    """
    v = cfa.Value('reg', name)
    p = my_state[v]
    p.taint = 1
    p.ttop = p.tbot = 0


def setReg(my_state, name, val, taint=0):
    v = cfa.Value('reg', name)
    if name == 'esp':
        region = 'stack'
    else:
        region = 'global'
    my_state[v] = cfa.Value(region, val, taint=taint)


def dereference_data(my_state, ptr):
    # XXX use proper sizes when setting {v,t}{bot,top}
    if ptr.vbot != 0:
        # Analysis stops here, exception is returned
        return None
    elif ptr.vtop != 0:
        # XXX decide expected behaviour, add value to test this
        newptr = copy.copy(ptr)
        newptr.value = 0
        newptr.vbot = 0
        newptr.vtop = 0xffffffff
        return newptr
    else:  # concrete value
        # XXX decode offset value from LDT, GDT, ds
        newptr = copy.copy(ptr)
        newptr.tbot = 0
        newptr.ttop = 0
        newptr.taint = 0
        res = my_state[newptr + 0xfff300]
        if ptr.ttop != 0 or ptr.taint != 0:
            res.ttop = 0xffffffff
        return res


def prepareExpectedState(state):
    return copy.deepcopy(state)


def assertEqualStates(state, expectedState, opcodes="", prgm=None):
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
    assert type(state) is cfa.State
    assert type(expectedState) is cfa.State
    if prgm:
        parent = prgm['0']
    else:
        parent = None
    assert state == expectedState, "States should be identical\n" + out + \
        state.diff(expectedState, "Observed ", "Expected ", parent)


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_xor_reg_self(analyzer, initialState, register):
    """
    Tests opcode 0x33 - xor self
    """
    regid, regname = register
    opcode = "\x33" + chr(0xc0 + regid + (regid << 3))
    prgm = analyzer(initialState, binarystr=opcode)
    stateBefore = prgm['0']
    stateAfter = getNextState(prgm, stateBefore)
    expectedStateAfter = prepareExpectedState(stateBefore)
    expectedStateAfter.address += len(opcode)  # pretty debug msg

    setReg(expectedStateAfter, regname, 0)
    clearFlag(expectedStateAfter, "sf")
    clearFlag(expectedStateAfter, "of")
    clearFlag(expectedStateAfter, "cf")
    undefBitFlag(expectedStateAfter, "af")
    setFlag(expectedStateAfter, "zf")
    setFlag(expectedStateAfter, "pf")
    # XXX check taint (not tainted)

    assertEqualStates(stateAfter, expectedStateAfter, prgm=prgm)


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_inc(analyzer, initialState, register):
    """
    Tests opcodes 0x40-0x47 == inc eax--edi
    """
    regid, regname = register
    opcode = chr(0x40 + regid)
    prgm = analyzer(initialState, binarystr=opcode)
    stateBefore = prgm['0']
    stateAfter = getNextState(prgm, stateBefore)
    expectedStateAfter = prepareExpectedState(stateBefore)
    expectedStateAfter.address += len(opcode)  # pretty debug msg

    expectedStateAfter[cfa.Value('reg', regname)] += 1
    regvalue = stateBefore[cfa.Value('reg', regname)].value
    newregvalue = expectedStateAfter[cfa.Value('reg', regname)].value
    calc_af(expectedStateAfter, regvalue, newregvalue, 1)
    calc_pf(expectedStateAfter, newregvalue)
    calc_sf(expectedStateAfter, newregvalue)
    calc_zf(expectedStateAfter, newregvalue)
    clearFlag(expectedStateAfter, 'of')  # XXX compute properly

    # XXX taint more bits?
    # XXX flags should be tainted - known bug

    assertEqualStates(stateAfter, expectedStateAfter, opcode, prgm=prgm)


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_dec(analyzer, initialState, register):
    """
    Tests opcodes 0x48-0x4F
    """
    regid, regname = register
    opcode = chr(0x48 + regid)
    prgm = analyzer(initialState, binarystr=opcode)
    stateBefore = prgm['0']
    stateAfter = getNextState(prgm, stateBefore)
    expectedStateAfter = prepareExpectedState(stateBefore)
    expectedStateAfter.address += len(opcode)  # pretty debug msg

    expectedStateAfter[cfa.Value('reg', regname)] -= 1
    regvalue = stateBefore[cfa.Value('reg', regname)].value
    newregvalue = expectedStateAfter[cfa.Value('reg', regname)].value

    # flags
    calc_af(expectedStateAfter, regvalue, newregvalue, -1)
    calc_pf(expectedStateAfter, newregvalue)
    calc_sf(expectedStateAfter, newregvalue)
    calc_zf(expectedStateAfter, newregvalue)
    clearFlag(expectedStateAfter, 'of')  # XXX compute properly

    # XXX taint more bits?
    assertEqualStates(stateAfter, expectedStateAfter, prgm=prgm)


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_push(analyzer, initialState, register):
    """
    Tests opcodes 0x50-0x57
    """
    regid, regname = register
    opcode = chr(0x50 + regid)
    prgm = analyzer(initialState, binarystr=opcode)
    stateBefore = prgm['0']
    stateAfter = getNextState(prgm, stateBefore)

    # build expected state
    expectedStateAfter = prepareExpectedState(stateBefore)
    expectedStateAfter.address += len(opcode)  # pretty debug msg
    expectedStateAfter[cfa.Value('reg', 'esp')] -= 4
    expectedStateAfter[cfa.Value(
        'stack', expectedStateAfter[cfa.Value('reg', 'esp')].value)] = \
        stateBefore[cfa.Value('reg', regname)]

    assertEqualStates(stateAfter, expectedStateAfter, prgm=prgm)


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_pop(analyzer, initialState, register):
    """
    Tests opcodes 0x58-0x5F
    """
    regid, regname = register
    opcode = chr(0x58 + regid)
    prgm = analyzer(initialState, binarystr=opcode)
    stateBefore = prgm['0']
    stateAfter = getNextState(prgm, stateBefore)

    # build expected state
    expectedStateAfter = prepareExpectedState(stateBefore)
    expectedStateAfter.address += len(opcode)  # pretty debug msg
    expectedStateAfter[cfa.Value('reg', 'esp')] += 4
    expectedStateAfter[cfa.Value('reg', regname)] = \
        stateBefore[cfa.Value(
            'stack', stateBefore[cfa.Value('reg', 'esp')].value)]

    assertEqualStates(stateAfter, expectedStateAfter, opcode, prgm=prgm)


def test_sub(analyzer, initialState):
    # sub esp, 0x1234
    opcode = binascii.unhexlify("81ec34120000")
    prgm = analyzer(initialState, binarystr=opcode)
    stateBefore = prgm['0']
    stateAfter = getNextState(prgm, stateBefore)

    # build expected state
    expectedStateAfter = prepareExpectedState(stateBefore)
    expectedStateAfter.address += len(opcode)  # pretty debug msg

    reg = cfa.Value('reg', 'esp')
    regvalue = stateBefore[reg].value
    newregvalue = stateBefore[reg].value - 0x1234
    calc_af(expectedStateAfter, regvalue, newregvalue, 0x1234)
    calc_pf(expectedStateAfter, newregvalue)
    calc_sf(expectedStateAfter, newregvalue)
    calc_zf(expectedStateAfter, newregvalue)
    clearFlag(expectedStateAfter, 'of')  # XXX compute properly
    clearFlag(expectedStateAfter, "cf")  # XXX compute properly
    expectedStateAfter[cfa.Value('reg', 'esp')] -= 0x1234
    # TODO check taint
    assertEqualStates(stateAfter, expectedStateAfter, prgm=prgm)


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_or_reg_ff(analyzer, initialState, register):
    """
    OR register with 0xff
    """
    # or reg,0xffffffff
    regid, regname = register
    opcode = "\x83" + chr(0xc8 + regid) + "\xff"
    prgm = analyzer(initialState, opcode)
    stateBefore = prgm['0']
    stateAfter = getNextState(prgm, stateBefore)

    # build expected state
    expectedStateAfter = prepareExpectedState(stateBefore)
    expectedStateAfter.address += len(opcode)  # pretty debug msg
    setReg(expectedStateAfter, regname, 0xffffffff)
    undefBitFlag(expectedStateAfter, "af")
    calc_pf(expectedStateAfter, 0xffffffff)
    calc_sf(expectedStateAfter, 0xffffffff)
    calc_zf(expectedStateAfter, 0xffffffff)
    clearFlag(expectedStateAfter, "of")
    clearFlag(expectedStateAfter, "cf")
    # TODO check taint
    assertEqualStates(stateAfter, expectedStateAfter, opcode, prgm=prgm)


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_mov_reg_ebpm6(analyzer, initialState, register):
    """
    mov reg,[ebp-0x6]
    """
    regid, regname = register
    opcode = "\x8b" + chr(0x45 + (regid << 3)) + "\xfa"
    prgm = analyzer(initialState, binarystr=opcode)
    stateBefore = prgm['0']
    stateAfter = getNextState(prgm, stateBefore)

    # build expected state
    expectedStateAfter = prepareExpectedState(stateBefore)
    expectedStateAfter.address += len(opcode)  # pretty debug msg
    expectedStateAfter[cfa.Value('reg', regname)] = \
        dereference_data(stateBefore,
                         stateBefore[cfa.Value('reg', 'ebp')] - 6)
    assertEqualStates(stateAfter, expectedStateAfter, opcode, prgm=prgm)


# "ebp" and "esp" have no sense for this instruction (sib, disp32 instead)
@pytest.mark.parametrize('register',
                         testregisters[:4] + testregisters[6:],
                         ids=lambda x: x[1])
def test_mov_ebp_reg(analyzer, initialState, register):
    """
    mov ebp,[reg]
    """
    regid, regname = register
    opcode = "\x8b" + chr(0x28 + regid)

    prgm = analyzer(initialState, binarystr=opcode)
    stateBefore = prgm['0']

    # build expected state
    expectedStateAfter = prepareExpectedState(stateBefore)
    expectedStateAfter.address += len(opcode)  # pretty debug msg
    newvalue = dereference_data(stateBefore,
                                stateBefore[cfa.Value('reg', regname)])
    if newvalue is None:
        # dereferenced pointer contains BOTTOM
        assertNoNextState(prgm, stateBefore)
        return

    expectedStateAfter[cfa.Value('reg', 'ebp')] = newvalue
    # stateBefore[stateBefore[cfa.Value('reg', regname)] + 0xfff300]
    stateAfter = getNextState(prgm, stateBefore)
    assertEqualStates(stateAfter, expectedStateAfter, opcode, prgm=prgm)


def test_nop(analyzer, initialState):
    """
    Tests opcode 0x90
    """
    # TODO add initial concrete ptr to initialState
    prgm = analyzer(initialState, binarystr='\x90')
    stateBefore = prgm['0']
    stateAfter = getNextState(prgm, stateBefore)
    assertEqualStates(stateBefore, stateAfter, prgm=prgm)


def test_and_esp(analyzer, initialState):
    """
    Test   and %esp,0xfffffff0
    """
    opcode = "\x83\xe4\xf0"
    prgm = analyzer(initialState, binarystr=opcode)
    stateBefore = prgm['0']
    stateAfter = getNextState(prgm, stateBefore)
    expectedStateAfter = prepareExpectedState(stateBefore)
    expectedStateAfter[cfa.Value("reg", "esp")] &= 0xfffffff0
    esp = expectedStateAfter[cfa.Value("reg", "esp")].value
    undefBitFlag(expectedStateAfter, "af")
    clearFlag(expectedStateAfter, "of")
    clearFlag(expectedStateAfter, "cf")
    calc_zf(expectedStateAfter, esp)
    calc_sf(expectedStateAfter, esp)
    calc_pf(expectedStateAfter, esp)

    assertEqualStates(stateAfter, expectedStateAfter, opcode, prgm=prgm)
