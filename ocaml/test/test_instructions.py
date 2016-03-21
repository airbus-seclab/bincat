#!/usr/bin/env python2
"""
This file describes tests for single instructions
"""

import pytest
import copy
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


# tests for opcodes 0x40-0x5F: inc, dec, push, pop
testregisters = list(enumerate(
 ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
))


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_inc(analyzer, initialState, register):
    """
    Tests opcodes 0x40-0x47
    """
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
    """
    Tests opcodes 0x48-0x4F
    """
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


@pytest.mark.parametrize('register', testregisters, ids=lambda x: x[1])
def test_push(analyzer, initialState, register):
    """
    Tests opcodes 0x50-0x57
    """
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
    """
    Tests opcodes 0x58-0x5F
    """
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


def test_nop(analyzer, initialState):
    """
    Tests opcode 0x90
    """
    # TODO add initial concrete ptr to initialState
    ac = analyzer(initialState, binarystr='\x90')
    assert ac.getStateAt(0x00) == ac.getStateAt(0x1)
    # TODO add helper in AnalyzerConfig to perform a check at each eip
    for state in ac.stateAtEip.values():
        assert state.ptrs['reg']['esp'].region == 'stack'
