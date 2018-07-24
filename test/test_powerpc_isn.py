import pytest
import os
from util import PowerPC

powerpc = PowerPC(os.path.join(os.path.dirname(os.path.realpath(__file__)),'powerpc.ini.in'))
compare = powerpc.compare


def test_nop(tmpdir):
    asm = """
        nop
    """
    compare(tmpdir, asm, [])


def test_assign(tmpdir, cmpall):
    asm = """
        mov r0, #0x12
        mov r1, r0
        movs r2, r1
    """
    cmpall(tmpdir, asm, ["r0","r1", "r2", "n", "z"])
