import pytest
import os
from util import ARM

arm = ARM(
    os.path.join(os.path.dirname(os.path.realpath(__file__)),'armv7_isn.ini.in')
)
compare = arm.compare


def test_nop(tmpdir):
    asm = """
        mov r0,r0
    """
    compare(tmpdir, asm, [])


def test_assign(tmpdir):
    asm = """
        mov r0, #0x12
        mov r1, r0
        mov r2, r1
    """
    compare(tmpdir, asm, ["r0","r1", "r2"])
