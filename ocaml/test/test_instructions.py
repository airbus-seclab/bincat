#!/usr/bin/env python2
"""
This file describes tests for single instructions
"""

import pytest
import copy
import binascii
from idabincat import analyzer_state


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
        ac = analyzer_state.AnalyzerState()
        ac.setStatesFromAnalyzerOutput(outputfile)
        return ac
    return run_analyzer


testregisters = list(enumerate(
 ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
))


def getNextState(ac, curState):
    """
    Helper function: check that there is only one destination state, return it.
    """
    nextStates = ac.listNextStates(curState.address)
    assert len(nextStates) == 1, \
        "expected exactly 1 destination state after running this instruction"
    return nextStates[0]


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_inc(analyzer, initialState, register):
    """
    Tests opcodes 0x40-0x47
    """
    regid, regname = register
    opcode = 0x40 + regid
    ac = analyzer(initialState, binarystr=chr(opcode))
    stateBefore = ac.getStateAt(0x00)
    stateAfter = getNextState(ac, stateBefore)
    expectedStateAfter = copy.deepcopy(stateBefore)

    # XXX taint more bits?
    expectedStateAfter.ptrs['reg'][regname] += 1

    assert expectedStateAfter == stateAfter


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_dec(analyzer, initialState, register):
    """
    Tests opcodes 0x48-0x4F
    """
    regid, regname = register
    opcode = 0x48 + regid
    ac = analyzer(initialState, binarystr=chr(opcode))
    stateBefore = ac.getStateAt(0x00)
    stateAfter = getNextState(ac, stateBefore)
    expectedStateAfter = copy.deepcopy(stateBefore)

    # XXX taint more bits?
    expectedStateAfter.ptrs['reg'][regname] -= 1

    assert expectedStateAfter == stateAfter


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_push(analyzer, initialState, register):
    """
    Tests opcodes 0x50-0x57
    """
    regid, regname = register
    opcode = 0x50 + regid
    ac = analyzer(initialState, binarystr=chr(opcode))
    stateBefore = ac.getStateAt(0x00)
    stateAfter = getNextState(ac, stateBefore)

    # build expected state
    expectedStateAfter = copy.deepcopy(stateBefore)
    expectedStateAfter.ptrs['reg']['esp'] -= 4
    expectedStateAfter.ptrs['mem'][stateBefore.ptrs['reg']['esp']] = \
        stateBefore.ptrs['reg'][regname]
    expectedStateAfter.tainting['mem'][stateBefore.ptrs['reg']['esp']] = \
        stateBefore.tainting['reg'][regname]

    assert expectedStateAfter == stateAfter


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_pop(analyzer, initialState, register):
    """
    Tests opcodes 0x58-0x5F
    """
    regid, regname = register
    opcode = 0x58 + regid
    ac = analyzer(initialState, binarystr=chr(opcode))
    stateBefore = ac.getStateAt(0x00)
    stateAfter = getNextState(ac, stateBefore)

    # build expected state
    expectedStateAfter = copy.deepcopy(stateBefore)
    expectedStateAfter.ptrs['reg']['esp'] += 4
    expectedStateAfter.ptrs['reg'][regname] = \
        stateBefore.ptrs['mem'][stateBefore.ptrs['reg']['esp']]
    expectedStateAfter.tainting['reg'][regname] = \
        stateBefore.tainting['mem'][stateBefore.ptrs['reg']['esp']]

    assert expectedStateAfter == stateAfter


def test_sub(analyzer, initialState):
    # sub esp, 0x1234
    hexstr = "81ec34120000"
    ac = analyzer(initialState, binarystr=binascii.unhexlify(hexstr))
    stateBefore = ac.getStateAt(0x00)
    stateAfter = getNextState(ac, stateBefore)

    # build expected state
    expectedStateAfter = copy.deepcopy(stateBefore)
    expectedStateAfter.ptrs['reg']['esp'] = stateBefore.ptrs['reg']['esp'] \
        - 0x1234
    # TODO check taint
    assert expectedStateAfter == stateAfter


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_or_reg_ff(analyzer, initialState, register):
    """
    Tests opcodes 0xc8-0xcf - OR register with 0xff
    """
    # or ebx,0xffffffff
    regid, regname = register
    binstr = "\x83" + chr(0xc8 + regid) + "\xff"
    ac = analyzer(initialState, binstr)
    stateBefore = ac.getStateAt(0x00)
    stateAfter = getNextState(ac, stateBefore)

    # build expected state
    expectedStateAfter = copy.deepcopy(stateBefore)
    expectedStateAfter.ptrs['reg'][regname] = 0xffffffff
    # TODO check taint
    assert expectedStateAfter == stateAfter


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_mov_ebp_reg(analyzer, initialState, register):
    regid, regname = register
    binstr = "\x8b" + chr(0xec + regid)
    ac = analyzer(initialState, binarystr=binstr)
    stateBefore = ac.getStateAt(0x00)
    stateAfter = getNextState(ac, stateBefore)

    # build expected state
    expectedStateAfter = copy.deepcopy(stateBefore)
    expectedStateAfter.ptrs['reg']['ebp'] = stateBefore.ptrs['reg'][regname]
    expectedStateAfter.tainting['reg']['ebp'] = \
        stateBefore.tainting['reg'][regname]
    assert expectedStateAfter == stateAfter


def test_nop(analyzer, initialState):
    """
    Tests opcode 0x90
    """
    # TODO add initial concrete ptr to initialState
    ac = analyzer(initialState, binarystr='\x90')
    stateBefore = ac.getStateAt(0x00)
    stateAfter = getNextState(ac, stateBefore)
    assert stateBefore == stateAfter, "NOP should not change state"
