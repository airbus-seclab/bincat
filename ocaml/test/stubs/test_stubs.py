#!/usr/bin/env python2
"""
This file describes tests for printf
"""

import pytest
import os
import subprocess
from pybincat import cfa


def analyze(tmpdir, initfname):

    olddir = os.getcwd()
    os.chdir(os.path.dirname(__file__))
    
    outfname = str(tmpdir.join('end.ini'))
    logfname = str(tmpdir.join('log.txt'))
    
    res = cfa.CFA.from_filenames(initfname, outfname, logfname)

    os.chdir(olddir)
    return outfname, logfname, res

def getReg(my_state, name):
    v = cfa.Value('reg', name, cfa.reg_len(name))
    return my_state[v][0]

def getMem(my_state, addr):
    v = cfa.Value('g', addr)
    return my_state[v]

def getMemAsStr(my_state, addr):
    r = getMem(my_state, addr)
    return "".join(chr(v.value) for v in r)


def getLastState(prgm):
    curState = prgm['0']
    while True:
        nextStates = prgm.next_states(curState.node_id)
        if len(nextStates) == 0:
            return curState
        assert len(nextStates) == 1, \
            "expected exactly 1 destination state after running this instruction"
        curState = nextStates[0]



def test_printf(tmpdir):
    outfname,logfname,res = analyze(tmpdir, "printf.ini")
    res = open(logfname).read()
    msg1 = "stub of printf analysed"
    msg2 = "[analysis] printf output:"
    assert msg1 in res
    assert msg2 in res
    p = res.find(msg2)+len(msg2)+1
    p2 = res.find("\n", p)
    assert res[p:p2] == "%x" % 0x12345678

    p = res.find(msg2)+len(msg2)+1
    assert "12345678" in res[p:p+50]
    
def test_printf_px(tmpdir):
    outfname,logfname,res = analyze(tmpdir, "printf2.ini")
    res = open(logfname).read()

    msg1 = "stub of printf analysed"
    msg2 = "[analysis] printf output:"
    assert msg1 in res
    assert msg2 in res

    assert "stub of printf analysed" in res
    assert "[analysis] printf output:" in res
    p = res.find(msg2)+len(msg2)+1
    p2 = res.find("\n", p)
    assert res[p:p2] == "value=%x" % 0x12345678

    p = res.find(msg2)+len(msg2)+1
    assert "value=12345678" in res[p:p+50]
    
def test_printf_ps(tmpdir):
    outfname,logfname,res = analyze(tmpdir, "printf3.ini")
    res = open(logfname).read()

    msg1 = "stub of printf analysed"
    msg2 = "[analysis] printf output:"
    assert msg1 in res
    assert msg2 in res

    assert "stub of printf analysed" in res
    assert "[analysis] printf output:" in res
    p = res.find(msg2)+len(msg2)+1
    p2 = res.find("\n", p)
    assert res[p:p2] == "abcd[%s]" % "ABC foobar"
    
def test_printf_p012x(tmpdir):
    outfname,logfname,res = analyze(tmpdir, "printf4.ini")
    res = open(logfname).read()

    msg1 = "stub of printf analysed"
    msg2 = "[analysis] printf output:"
    assert msg1 in res
    assert msg2 in res

    assert "stub of printf analysed" in res
    assert "[analysis] printf output:" in res
    p = res.find(msg2)+len(msg2)+1
    p2 = res.find("\n", p)
    assert res[p:p2] == "abcd[%012x]" % 0x12345678

def test_sprintf1(tmpdir):
    outfname,logfname,res = analyze(tmpdir, "sprintf1.ini")
    s = getLastState(res)
    eax = getReg(s, "eax")
    expected = "abcd[%012x]\n" % 0x12345678
    assert eax.value == len(expected)
    assert getMemAsStr(s, 0x400) == expected+"\x00"

def test_sprintf2(tmpdir):
    outfname,logfname,res = analyze(tmpdir, "sprintf2.ini")
    s = getLastState(res)
    eax = getReg(s, "eax")
    expected = "abcd[%s]\n" % "ABCDEF"
    assert eax.value == len(expected)
    assert getMemAsStr(s, 0x400) == expected+"\x00"

def test_sprintf_check_1(tmpdir):
    outfname,logfname,res = analyze(tmpdir, "sprintf_check1.ini")
    s = getLastState(res)
    eax = getReg(s, "eax")
    expected = "abcd[%s]\n" % "ABCDEF"
    assert eax.value == len(expected)
    assert getMemAsStr(s, 0x400) == expected+"\x00"
    
def test_memcpy(tmpdir):
    cplen = 15
    psrc = 0x200
    pdst = 0x400
    outfname,logfname,res = analyze(tmpdir, "memcpy1.ini")
    first_state = res[0]
    last_state = getLastState(res)
    src = getMemAsStr(first_state, psrc)
    dst = getMemAsStr(last_state, pdst)
    eax = getReg(last_state, "eax")
    assert eax.value == pdst
    assert dst == src
    
