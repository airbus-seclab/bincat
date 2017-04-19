#!/usr/bin/env python2
"""
This file describes tests for single instructions
"""

import pytest
import subprocess
import copy
import binascii
import os.path
from pybincat import cfa


@pytest.fixture(scope='function', params=['template0.ini'])
def initialState(request):
    # TODO generate instead of using a fixed file, using States class
    # (not implemented yet)
    # TODO return object
    filepath = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                            request.param)
    return open(filepath, 'rb').read()


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

def getLastState(prgm, curState):
    """
    Helper function: check that there is only one last state, return it.
    """
    while True:
        nextStates = prgm.next_states(curState.node_id)
        if len(nextStates) == 0:
            return curState
        assert len(nextStates) == 1, \
            "expected exactly 1 destination state after running this instruction"
        curState = nextStates[0]

def clearFlag(my_state, name):
    """
    Set flag to 0, untainted - helper for tests
    XXX for most tests, flags should inherit taint
    """
    v = cfa.Value('reg', name, cfa.reg_len(name))
    my_state[v] = [cfa.Value('g', 0x0, cfa.reg_len(name))]


def setFlag(my_state, name):
    """
    Set flag to 1, untainted - helper for tests
    XXX for most tests, flags should inherit taint
    """
    v = cfa.Value('reg', name, cfa.reg_len(name))
    my_state[v] = [cfa.Value('g', 1, cfa.reg_len(name))]


def undefBitFlag(my_state, name):
    """
    Set flag to undefined.
    XXX specify register len?
    """
    v = cfa.Value('reg', name, cfa.reg_len(name))
    my_state[v] = [cfa.Value('t', 0, cfa.reg_len(name), vtop=1)]


def calc_af(my_state, orig_state, regname, operation):
    "operation = 1 for add/inc/etc., -1 for sub/dec/etc."
    rb = getReg(orig_state, regname)
    ra = getReg(my_state, regname)
    
    afval = ((operation ^ ra.value ^ rb.value) & 0x4) >> 3
    afvtop = 1 if ra.vtop & 0x4 != 0 else 0
    aftaint = 1 if ra.taint & 0x4 != 0 else 0
    afttop = 1 if ra.taint & 0x4 != 0 else 0
    
    setRegVal(my_state, 'af', afval, afvtop, aftaint, afttop)


def calc_zf(my_state, regname):
    reg = getReg(my_state, regname)
    zfval = 1 if reg.value == 0 else 0
    zftop = 1 if reg.vtop != 0 and ((reg.value & (~reg.vtop)) == 0) else 0
    zftaint = 1 if reg.taint != 0 else 0
    zfttop = 1 if reg.ttop != 0 and ((reg.taint & (~reg.ttop)) == 0) else 0
    setRegVal(my_state, 'zf', value=zfval, vtop=zftop, taint=zftaint, ttop=zftop)


def calc_sf(my_state, regname):
    reg = getReg(my_state, regname)
    sfval = 1 if reg.value & 0x80000000 != 0 else 0
    sftop = 1 if reg.vtop & 0x80000000 != 0 else 0
    sftaint = 1 if reg.vtop & 0x80000000 != 0 else 0
    sfttop = 1 if reg.ttop & 0x80000000 != 0 else 0
    setRegVal(my_state, 'sf', value=sfval, vtop=sftop, taint=sftaint, ttop=sfttop)


def calc_pf(my_state, regname):
    reg = getReg(my_state, regname)

    val = reg.value & 0xff
    par = val ^ (val >> 1)
    par = par ^ (par >> 2)
    par = par ^ (par >> 4)
    par &= 1
    
    pfval = 0 if par else 1
    pftop = 1 if reg.vtop & 0xff != 0 else 0
    pftaint = 1 if reg.taint & 0xff != 0 else 0
    pfttop = 1 if reg.ttop & 0xff != 0 else 0
    
    setRegVal(my_state, 'pf', value=pfval, vtop=pftop, taint=pftaint, ttop=pfttop)


def taintFlag(my_state, name):
    """
    Taint flag - helper for tests
    XXX for most tests, flags should inherit taint
    """
    v = cfa.Value('reg', name)
    p = my_state[v][0]
    p.taint = 1
    p.ttop = p.tbot = 0


def getReg(my_state, name):
    v = cfa.Value('reg', name, cfa.reg_len(name))
    return my_state[v][0]

def setReg(my_state, name, regval):
    v = cfa.Value('reg', name, cfa.reg_len(name))
    my_state[v] = [ regval ]

def setRegVal(my_state, name, value, vtop=0, taint=0, ttop=0):
    if name == 'esp':
        region = 's'
    else:
        region = 'g'
    regval = cfa.Value(region, value, cfa.reg_len(name), vtop=vtop, taint=taint, ttop=ttop)
    setReg(my_state, name, regval)


def dereference_data(my_state, ptr):
    # XXX use proper sizes when setting {v,t}{bot,top}
    if ptr.vbot != 0:
        # Analysis stops here, exception is returned
        return None
    elif ptr.vtop != 0:
        # XXX decide expected behaviour, add value to test this
        newptr = copy.deepcopy(ptr)
        newptr.value = 0
        newptr.vbot = 0
        newptr.vtop = 0xffffffff
        return newptr
    else:  # concrete value
        # XXX decode offset value from LDT, GDT, ds
        newptr = copy.deepcopy(ptr)
        newptr.tbot = 0
        newptr.ttop = 0
        newptr.taint = 0
        res = copy.deepcopy(my_state[newptr])
        if ptr.ttop != 0 or ptr.taint != 0:
            for r in res:
                r.taint = 0xff
        return res


def prepareExpectedState(state):
    newstate = copy.deepcopy(state)
    newstate.node_id = str(int(newstate.node_id)+1)
    return newstate


def go_analyze(analyzer, initialState, opcodes): 
    prgm = analyzer(initialState, binarystr=opcodes)
    stateBefore = prgm['0']
    stateAfter = getLastState(prgm, stateBefore)
    expectedStateAfter = prepareExpectedState(stateBefore)
    expectedStateAfter.address = stateAfter.address
    return prgm, stateBefore, stateAfter, expectedStateAfter


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

    prgm, before, after, expected = go_analyze(analyzer, initialState, opcode)

    setRegVal(expected, regname, 0)
    clearFlag(expected, "sf")
    clearFlag(expected, "of")
    clearFlag(expected, "cf")
    undefBitFlag(expected, "af")
    setFlag(expected, "zf")
    setFlag(expected, "pf")
    # XXX check taint (not tainted)

    assertEqualStates(after, expected, opcode, prgm=prgm)


@pytest.mark.xfail
@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_inc(analyzer, initialState, register):
    """
    Tests opcodes 0x40-0x47 == inc eax--edi
    """
    regid, reg = register
    opcode = chr(0x40 + regid)

    prgm, before, after, expected = go_analyze(analyzer, initialState, opcode)
    
    expected[cfa.Value('reg', reg)][0] += 1

    bef_value = getReg(before, reg).value
    calc_af(expected, before, reg, 1)
    calc_pf(expected, reg)
    calc_sf(expected, reg)
    calc_zf(expected, reg)
    clearFlag(expected, 'of')  # XXX compute properly

    # XXX taint more bits?
    # XXX flags should be tainted - known bug

    assertEqualStates(after, expected, opcode, prgm=prgm)


@pytest.mark.xfail
@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_dec(analyzer, initialState, register):
    """
    Tests opcodes 0x48-0x4F
    """
    regid, regname = register
    opcode = chr(0x48 + regid)

    prgm, before, after, expected = go_analyze(analyzer, initialState, opcode)

    reg = getReg(expected, regname)
    reg -= 1
    setReg(expected, regname, reg)

    # flags
    calc_af(expected, before, regname, -1)
    calc_pf(expected, regname)
    calc_sf(expected, regname)
    calc_zf(expected, regname)
    clearFlag(expected, 'of')  # XXX compute properly

    # XXX taint more bits?
    assertEqualStates(after, expected, opcode, prgm=prgm)


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_push(analyzer, initialState, register):
    """
    Tests opcodes 0x50-0x57
    """
    regid, regname = register
    opcode = chr(0x50 + regid)

    prgm, before, after, expected = go_analyze(analyzer, initialState, opcode)

    # build expected state
    expected[cfa.Value('reg', 'esp')][0] -= 4
    expected[cfa.Value(
        's', after[cfa.Value('reg', 'esp')][0].value)] = \
        before[cfa.Value('reg', regname)]

    assertEqualStates(after, expected, opcode, prgm=prgm)


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_pop(analyzer, initialState, register):
    """
    Tests opcodes 0x58-0x5F
    """
    regid, regname = register
    opcode = chr(0x58 + regid)

    prgm, before, after, expected = go_analyze(analyzer, initialState, opcode)

    # build expected state
    expected[cfa.Value('reg', 'esp')][0] += 4
    expected[cfa.Value('reg', regname)] = \
        before[cfa.Value(
            's', before[cfa.Value('reg', 'esp')][0].value)]

    assertEqualStates(after, expected, opcode, prgm=prgm)


@pytest.mark.xfail
def test_sub(analyzer, initialState):
    # sub esp, 0x1234
    opcode = binascii.unhexlify("81ec34120000")

    prgm, before, after, expected = go_analyze(analyzer, initialState, opcode)
    
    # build expected state
    regvalue = getReg(before, "esp").value
    newregvalue = regvalue - 0x1234
    expected[cfa.Value('reg', 'esp')][0].value -= 0x1234
    calc_af(expected, before, "esp", -1)
    calc_pf(expected, "esp")
    calc_sf(expected, "esp")
    calc_zf(expected, "esp")
    clearFlag(expected, 'of')  # XXX compute properly
    clearFlag(expected, 'cf')  # XXX compute properly
    # TODO check taint
    assertEqualStates(after, expected, opcode, prgm=prgm)


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_or_reg_ff(analyzer, initialState, register):
    """
    OR register with 0xff
    """
    # or reg,0xffffffff
    regid, regname = register
    opcode = "\x83" + chr(0xc8 + regid) + "\xff"

    prgm, before, after, expected = go_analyze(analyzer, initialState, opcode)

    # build expected state
    setRegVal(expected, regname, 0xffffffff)
    undefBitFlag(expected, "af")
    calc_pf(expected, regname)
    calc_sf(expected, regname)
    calc_zf(expected, regname)
    clearFlag(expected, "of")
    clearFlag(expected, "cf")
    # TODO check taint
    assertEqualStates(after, expected, opcode, prgm=prgm)


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_mov_reg_ebpm6(analyzer, initialState, register):
    """
    mov reg,[ebp-0x6]
    """
    regid, regname = register
    opcode = "\x8b" + chr(0x45 + (regid << 3)) + "\xfa"

    prgm, before, after, expected = go_analyze(analyzer, initialState, opcode)

    # build expected state
    expected[cfa.Value('reg', regname)] = \
        dereference_data(before,
                         before[cfa.Value('reg', 'ebp')][0] - 6)
    assertEqualStates(after, expected, opcode, prgm=prgm)


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

    prgm, before, after, expected = go_analyze(analyzer, initialState, opcode)

    # build expected state
    newvalue = dereference_data(before,
                                before[cfa.Value('reg', regname)][0])
    if newvalue is None:
        # dereferenced pointer contains BOTTOM
        assertNoNextState(prgm, before)
        return

    expected[cfa.Value('reg', 'ebp')] = newvalue
    expected = getNextState(prgm, before)
    assertEqualStates(after, expected, opcode, prgm=prgm)


def test_nop(analyzer, initialState):
    """
    Tests opcode 0x90
    """
    # TODO add initial concrete ptr to initialState
    opcode = '\x90'

    prgm, before, after, expected = go_analyze(analyzer, initialState, opcode)

    assertEqualStates(after, expected, opcode, prgm=prgm)


def test_and_esp(analyzer, initialState):
    """
    Test   and %esp,0xfffffff0
    """
    opcode = "\x83\xe4\xf0"

    prgm, before, after, expected = go_analyze(analyzer, initialState, opcode)

    expected[cfa.Value("reg", "esp")][0].value &= 0xfffffff0
    esp = expected[cfa.Value("reg", "esp")][0].value
    undefBitFlag(expected, "af")
    clearFlag(expected, "of")
    clearFlag(expected, "cf")
    calc_zf(expected, "esp")
    calc_sf(expected, "esp")
    calc_pf(expected, "esp")

    assertEqualStates(after, expected, opcode, prgm=prgm)

@pytest.mark.xfail
def test_movzx(analyzer, initialState):
    """
    Test   movzx edx, dl
    """
    opcode = "\x0f\xb6\xd2"

    prgm, before, after, expected = go_analyze(analyzer, initialState, opcode)

    expected[cfa.Value("reg", "edx")][0].value &= 0xff
    expected[cfa.Value("reg", "edx")][0].vtop &= 0xff
    expected[cfa.Value("reg", "edx")][0].taint &= 0xff
    expected[cfa.Value("reg", "edx")][0].ttop &= 0xff

    assertEqualStates(after, expected, opcode, prgm=prgm)


def test_movzx_byte(analyzer, initialState):
    """
    Test   mov eax, 0x100 ; movzx eax, byte ptr [eax]"
    """
    opcode = ("B800010000"+"0FB600").decode("hex")

    prgm, before, after, expected = go_analyze(analyzer, initialState, opcode)

    v = before[cfa.Value("g", 0x100)][0]
    
    expected[cfa.Value("reg", "eax")][0].value = v.value & 0xff
    expected[cfa.Value("reg", "eax")][0].vtop = v.vtop & 0xff
    expected[cfa.Value("reg", "eax")][0].taint = v.taint & 0xff
    expected[cfa.Value("reg", "eax")][0].ttop = v.ttop & 0xff

    assertEqualStates(after, expected, opcode, prgm=prgm)

@pytest.mark.xfail
def test_movzx_byte_taintptr(analyzer, initialState):
    """
    Test   movzx eax, byte ptr [eax]"
    """
    opcode = "0FB600".decode("hex")

    prgm, before, after, expected = go_analyze(analyzer, initialState, opcode)
    
    v = before[cfa.Value("g", 1)][0]
    
    expected[cfa.Value("reg", "eax")][0].value = v.value & 0xff
    expected[cfa.Value("reg", "eax")][0].vtop = v.vtop & 0xff
    expected[cfa.Value("reg", "eax")][0].taint = 0xff
    expected[cfa.Value("reg", "eax")][0].ttop = 0

    assertEqualStates(after, expected, opcode, prgm=prgm)

@pytest.mark.xfail
def test_movzx_byte_untaintptr(analyzer, initialState):
    """
    Test   movzx ebx, byte ptr [ebx]"
    """
    opcode = "0FB609".decode("hex")

    prgm, before, after, expected = go_analyze(analyzer, initialState, opcode)
    
    v = before[cfa.Value("g", getReg(before, "ecx").value)][0]
    
    expected[cfa.Value("reg", "ecx")][0].value = v.value & 0xff
    expected[cfa.Value("reg", "ecx")][0].vtop = v.vtop & 0xff
    expected[cfa.Value("reg", "ecx")][0].taint = v.taint & 0xff
    expected[cfa.Value("reg", "ecx")][0].ttop = v.ttop & 0xff

    assertEqualStates(after, expected, opcode, prgm=prgm)

def test_mov_byte_taintptr(analyzer, initialState):
    """
    Test   mov al, byte ptr [eax]"
    """
    opcode = "8A00".decode("hex")

    prgm, before, after, expected = go_analyze(analyzer, initialState, opcode)
    
    v = before[cfa.Value("g", 1)][0]

    expected[cfa.Value("reg", "eax")][0].value = v.value & 0xff
    expected[cfa.Value("reg", "eax")][0].vtop = v.vtop & 0xff
    expected[cfa.Value("reg", "eax")][0].taint = 0xff
    expected[cfa.Value("reg", "eax")][0].ttop = 0

    assertEqualStates(after, expected, opcode, prgm=prgm)

@pytest.mark.xfail
def test_imul(analyzer, initialState):
    """
    Test   imul edi, ecx"
    """
    opcode = "0FAFF9".decode("hex")

    reg = "edi"
    
    prgm, before, after, expected = go_analyze(analyzer, initialState, opcode)

    edi = getReg(before, reg)
    ecx = getReg(before, "ecx")

    setRegVal(expected, reg, edi.value*ecx.value,
              vtop = 0xffffffff if edi.vtop or ecx.vtop else 0,  # XXX should be 0xde0 ?
              taint = 0xffffffff if edi.taint or ecx.taint else 0,
              ttop = 0xffffffff if edi.ttop or ecx.ttop else 0)

    calc_af(expected, before, reg, 1)
    calc_pf(expected, reg)
    calc_sf(expected, reg)
    calc_zf(expected, reg)

    assertEqualStates(after, expected, opcode, prgm=prgm)

def test_shl(analyzer, initialState):
    """
    Test shl edx, cl
    """
    opcode = "D3E2".decode("hex")

    reg = "edx"

    prgm, before, after, expected = go_analyze(analyzer, initialState, opcode)

    regv = getReg(before, reg)
    cl = getReg(before, "ecx")
    clv = cl.value & 0xff

    setRegVal(expected, reg, (regv.value << clv) & 0xffffffff,
              vtop = (regv.vtop << clv) & 0xffffffff,
              taint = (regv.taint << clv) & 0xffffffff if not cl.taint and not cl.ttop else 0xffffffff,
              ttop = (regv.ttop << clv) & 0xffffffff if not cl.ttop else 0xffffffff)
    
    calc_zf(expected, reg)
    calc_pf(expected, reg)

    calc_af(expected, before, reg, 1)
    calc_sf(expected, reg)
    assertEqualStates(after, expected, opcode, prgm=prgm)
