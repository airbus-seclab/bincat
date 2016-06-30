#!/usr/bin/env python2
"""
Tests targeting the loading of binary files
"""

import pytest
import copy
import subprocess
from pybincat import cfa


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

        def resetpwd():
            """
            test teardown; remove once init.ini is auto-generated
            """
            oldpath.chdir()
        request.addfinalizer(resetpwd)

        initfname = str(tmpdir.join('init.ini'))
        with open(initfname, 'w+') as f:
            f.write(initialState)
        binfname = str(tmpdir.join('file.bin'))
        with open(binfname, 'w+') as f:
            f.write(binarystr)

        outfname = str(tmpdir.join('end.ini'))
        logfname = str(tmpdir.join('log.txt'))
        p = cfa.CFA.from_filenames(initfname, outfname, logfname)
        return p
    return run_analyzer


def getNextState(prgm, curState):
    """
    Helper function: check that there is only one destination state, return it.
    XXX factor code with other tests
    """
    nextStates = prgm.next_states(curState.node_id)
    assert len(nextStates) == 1, \
        "expected exactly 1 destination state after running this instruction"
    nextState = nextStates[0]
    assert nextState is not None, \
        "Expected defined state after running this instruction"
    return nextState


def assertEqualStates(state, expectedState, opcodes=None):
    """
    XXX factor code
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
    assert state == expectedState, "States should be identical\n" + out + \
        state.diff(expectedState, "Observed ", "Expected ")


def test_decode_5055_full(analyzer):
    """
    Fully analyze input file containing 0x5055
    """
    filename = 'init-5055-read-all.ini'
    initialState = open(filename, 'rb').read()
    binarystr = '\x50\x55'
    prgm = analyzer(initialState, binarystr=binarystr)
    stateInit = prgm['0']
    #: after push eax
    state1 = getNextState(prgm, stateInit)
    #: after push ebp
    state2 = getNextState(prgm, state1)

    expectedState1 = copy.deepcopy(stateInit)

    expectedState1[cfa.Value('reg', 'esp')] -= 4
    expectedState1[cfa.Value(
        'stack', expectedState1[cfa.Value('reg', 'esp')].value)] = \
        stateInit[cfa.Value('reg', 'eax')]

    expectedState1.address += 1  # not checked, cosmetic for debugging only

    expectedState2 = copy.deepcopy(expectedState1)
    expectedState2[cfa.Value('reg', 'esp')] -= 4
    expectedState2[cfa.Value(
        'stack', expectedState2[cfa.Value('reg', 'esp')].value)] = \
        expectedState1[cfa.Value('reg', 'ebp')]
    expectedState2.address += 1

    assert len(prgm.edges) == 2
    assertEqualStates(state1, expectedState1, binarystr[0])
    assertEqualStates(state2, expectedState2, binarystr[1])


def test_decode_5055_lastbyte(analyzer):
    filename = 'init-5055-read-lastbyte.ini'
    initialState = open(filename, 'rb').read()
    binarystr = '\x50\x55'
    prgm = analyzer(initialState, binarystr=binarystr)
    state1 = prgm['0']
    # XXX check address is 0x1000
    #: after push ebp
    state2 = getNextState(prgm, state1)

    expectedState2 = copy.deepcopy(state1)
    expectedState2[cfa.Value('reg', 'esp')] -= 4
    expectedState2[cfa.Value(
        'stack', expectedState2[cfa.Value('reg', 'esp')].value)] = \
        state1[cfa.Value('reg', 'ebp')]

    expectedState2.address += 1  # not checked, cosmetic for debugging only

    assert len(prgm.edges) == 1
    assertEqualStates(state2, expectedState2, binarystr[1])

# TODO test with entrypoint != rva-code
