#!/usr/bin/env python2
"""
Tests targeting the loading of binary files
"""

import pytest
import copy
import subprocess
import os.path
from pybincat import cfa


@pytest.fixture(scope='function', params=['init-5055-read-last-only.ini',
                                          'init-5055-read-all.ini'])
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

        initfname = str(tmpdir.join('init.ini'))
        with open(initfname, 'w+') as f:
            f.write(initialState)
        binfname = str(tmpdir.join('file.bin'))
        with open(binfname, 'w+') as f:
            f.write(binarystr)

        outfname = str(tmpdir.join('end.ini'))
        logfname = str(tmpdir.join('log.txt'))
        p = cfa.CFA.from_filenames(initfname, outfname, logfname)
        # concatenate Values: State.regaddrs's values are lists of exactly 1
        # Value
        for state in p.nodes.values():
            for regaddr, val in state.regaddrs.items():
                # integer representation
                concatv = val[-1]
                for nextv in val[-2::-1]:
                    concatv = concatv & nextv
                state.regaddrs[regaddr] = [concatv]
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


def assertEqualStates(state, expectedState, opcodes="", prgm=None):
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
    if prgm:
        parent = prgm['0']
    else:
        parent = None
    assert state == expectedState, "States should be identical\n" + out + \
        state.diff(expectedState, "Observed ", "Expected ", parent)


def prepareExpectedState(state):
    newstate = copy.deepcopy(state)
    newstate.node_id = str(int(newstate.node_id)+1)
    return newstate


def test_decode_5055_full(analyzer):
    """
    Fully analyze input file containing 0x5055
    """
    filename = 'init-5055-read-all.ini'
    filepath = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                            filename)
    initialState = open(filepath, 'rb').read()
    binarystr = '\x50\x55'
    prgm = analyzer(initialState, binarystr=binarystr)
    stateInit = prgm['0']
    #: after push eax
    state1 = getNextState(prgm, stateInit)
    #: after push ebp
    state2 = getNextState(prgm, state1)

    expectedState1 = prepareExpectedState(stateInit)

    expectedState1[cfa.Value('reg', 'esp')][0].value -= 4
    expectedState1[cfa.Value(
        's', expectedState1[cfa.Value('reg', 'esp')][0].value)] = \
        stateInit[cfa.Value('reg', 'eax')]

    expectedState1.address += 1  # not checked, cosmetic for debugging only

    expectedState2 = prepareExpectedState(stateInit)
    expectedState2[cfa.Value('reg', 'esp')][0].value -= 8
    concatv = [expectedState1[cfa.Value('reg', 'eax')][0] &
               expectedState1[cfa.Value('reg', 'ebp')][0]]
    expectedState2[cfa.Value(
        's', expectedState2[cfa.Value('reg', 'esp')][0].value)] = concatv
    expectedState2.address += 1

    assert len(prgm.edges) == 2
    assertEqualStates(state1, expectedState1, binarystr[0], prgm)
    assertEqualStates(state2, expectedState2, binarystr[1], prgm)


def test_decode_5055_lastbyte(analyzer):
    filename = 'init-5055-read-lastbyte.ini'
    filepath = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                            filename)
    initialState = open(filepath, 'rb').read()
    binarystr = '\x50\x55'
    prgm = analyzer(initialState, binarystr=binarystr)
    state1 = prgm['0']
    #: after push ebp
    state2 = getNextState(prgm, state1)

    expectedState2 = prepareExpectedState(state1)
    expectedState2[cfa.Value('reg', 'esp')][0].value -= 4
    print state1[cfa.Value('reg', 'ebp')]

    zk = cfa.Value('s', expectedState2[cfa.Value('reg', 'esp')][0].value)
    print zk
    #print zk in expectedState2[

    expectedState2[cfa.Value(
        's', expectedState2[cfa.Value('reg', 'esp')][0].value)] = \
        state1[cfa.Value('reg', 'ebp')]
    print "zk", zk
    print "e2", type(expectedState2[zk]), "e3"

    expectedState2.address += 1  # not checked, cosmetic for debugging only

    assert len(prgm.edges) == 1
    assertEqualStates(state2, expectedState2, binarystr[1], prgm=prgm)

# TODO test with entrypoint != rva-code
