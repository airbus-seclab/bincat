#!/usr/bin/env python2
"""
Tests targeting the loading of binary files
"""

import pytest
import copy
from pybincat import state


@pytest.fixture(scope='function', params=['init-5055-read-last-only.ini',
                                          'init-5055-read-all.ini'])
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
        ac = state.AnalyzerState.run_analyzer(initfile, outputfile,
                                                       logfile)
        return ac
    return run_analyzer


def getNextState(ac, curState):
    """
    Helper function: check that there is only one destination state, return it.
    """
    nextStates = ac.listNextStates(curState.address)
    assert len(nextStates) == 1, \
        "expected exactly 1 destination state after running this instruction"
    return nextStates[0]


def test_decode_5055_full(analyzer):
    """
    Fully analyze input file containing 0x5055
    """
    filename = 'init-5055-read-all.ini'
    initialState = open(filename, 'rb').read()
    ac = analyzer(initialState, binarystr='\x50\x55')
    stateInit = ac.getStateAt(0x00)
    #: after push eax
    state1 = getNextState(ac, stateInit)
    #: after push ebp
    state2 = getNextState(ac, state1)

    expectedState1 = copy.deepcopy(stateInit)

    expectedState1.ptrs['reg']['esp'] -= 4
    expectedState1.ptrs['mem'][stateInit.ptrs['reg']['esp']] = \
        stateInit.ptrs['reg']['eax']
    expectedState1.tainting['mem'][stateInit.ptrs['reg']['esp']] = \
        stateInit.tainting['reg']['eax']

    expectedState2 = copy.deepcopy(expectedState1)
    expectedState2.ptrs['reg']['esp'] -= 4
    expectedState2.ptrs['mem'][expectedState1.ptrs['reg']['esp']] = \
        expectedState1.ptrs['reg']['ebp']
    expectedState2.tainting['mem'][expectedState1.ptrs['reg']['esp']] = \
        expectedState1.tainting['reg']['ebp']

    assert len(ac.edges) == 2
    assert expectedState1 == state1
    assert expectedState2 == state2


def test_decode_5055_lastbyte(analyzer):
    filename = 'init-5055-read-lastbyte.ini'
    initialState = open(filename, 'rb').read()
    ac = analyzer(initialState, binarystr='\x50\x55')
    state1 = ac.getStateAt(0x1000)
    #: after push ebp
    state2 = getNextState(ac, state1)

    expectedState2 = copy.deepcopy(state1)
    expectedState2.ptrs['reg']['esp'] -= 4
    expectedState2.ptrs['mem'][state1.ptrs['reg']['esp']] = \
        state1.ptrs['reg']['ebp']
    expectedState2.tainting['mem'][state1.ptrs['reg']['esp']] = \
        state1.tainting['reg']['ebp']

    assert len(ac.edges) == 1
    assert expectedState2 == state2

# TODO test with entrypoint != rva-code
