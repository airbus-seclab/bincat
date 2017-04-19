#!/usr/bin/env python2
"""
This file describes tests for printf
"""

import pytest
import os
import subprocess
import gzip
from pybincat import cfa


def analyze(tmpdir, initfname):

    olddir = os.getcwd()
    os.chdir(os.path.dirname(__file__))
    
    outfname = str(tmpdir.join('end.ini'))
    logfname = str(tmpdir.join('log.txt'))

    p = cfa.CFA.from_filenames(initfname, outfname, logfname)

    os.chdir(olddir)
    return outfname, logfname

def test_qemu_i386(tmpdir):
    os.system("gunzip < test-i386.raw.gz > test-i386.raw") # XXX
    outfname,logfname = analyze(tmpdir, "test-i386.ini")
    os.system("rm test-i386.raw")                          # XXX
    res = open(logfname)
    expected = gzip.open("test-i386.out.gz")
    for la in res:
        if "[analysis]" in la:
            continue
        la = la.strip()
        print repr(la)
        if not la:
            continue
        lb = expected.readline().strip()
        assert la == lb
