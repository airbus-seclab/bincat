import pytest
import os
from util import AARCH64

arm = AARCH64(
    os.path.join(os.path.dirname(os.path.realpath(__file__)),'armv8_isn.ini.in')
)
compare = arm.compare

def test_assign(tmpdir):
    asm = """
        mov w0, 123
        mov w1, w2
    """
    a,b,c = arm.assemble(tmpdir, asm)
    assert False, "%r\n%s" %  (c,a)

