import pytest
import os
from util import ARM

arm = ARM(
    os.path.join(os.path.dirname(os.path.realpath(__file__)),'arm_isn.ini.in')
)
compare = arm.compare

def test_assign(tmpdir):
    asm = """
        ldr r0, =#1234
        mov r1, r2
    """
    a,b,c = arm.assemble(tmpdir, asm)
    assert False, "%r\n%s" %  (c,a)

