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
    
    p = cfa.CFA.from_filenames(initfname, outfname, logfname)

    os.chdir(olddir)
    return outfname, logfname

def test_printf(tmpdir):
    outfname,logfname = analyze(tmpdir, "printf.ini")
    res = open(logfname).read()
    msg1 = "stub of printf analysed"
    msg2 = "[analysis] printf output:"
    assert msg1 in res
    assert msg2 in res
    p = res.find(msg2)+len(msg2)+1
    assert "12345678" in res[p:p+50]
    
def test_printf_px(tmpdir):
    outfname,logfname = analyze(tmpdir, "printf2.ini")
    res = open(logfname).read()

    msg1 = "stub of printf analysed"
    msg2 = "[analysis] printf output:"
    assert msg1 in res
    assert msg2 in res

    assert "stub of printf analysed" in res
    assert "[analysis] printf output:" in res
    p = res.find(msg2)+len(msg2)+1
    assert "value=12345678" in res[p:p+50]
    
