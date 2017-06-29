import pytest
import os
from util import AARCH64

arm = AARCH64(
    os.path.join(os.path.dirname(os.path.realpath(__file__)),'armv8_isn.ini.in')
)
compare = arm.compare

def test_nop(tmpdir):
    asm = """
        nop
    """
    compare(tmpdir, asm, [])

def test_assign(tmpdir):
    asm = """
        mov x0, 124
        mov w1, w0
        mov w2, w1
    """
    compare(tmpdir, asm, ["r0","r1","r2"])

