import pytest
import os
from util import AARCH64

arm = AARCH64(
    os.path.join(os.path.dirname(os.path.realpath(__file__)),'armv8_isn.ini.in')
)
compare = arm.compare

dataop_comp_logic = pytest.mark.parametrize("op", ["and", "eor", "orr", "bic"])
dataop_comp_arith = pytest.mark.parametrize("op", ["sub", "rsb", "add"])

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

@dataop_comp_logic
def test_data_proc_logic(tmpdir, op, armv7op, armv7op_):
    asm = """
            mov x0, #{armv7op}
            mov x1, #{armv7op_}
            {op} x2, x0, x1
    """.format(**locals())
    compare(tmpdir, asm, ["x0","x1", "x2", "x3", "n", "z"])

@dataop_comp_arith
def test_data_proc_arith(tmpdir, op, armv7op, armv7op_):
    asm = """
            mov x0, #{armv7op}
            mov x1, #{armv7op_}
            {op} x2, x0, x1
    """.format(**locals())
    compare(tmpdir, asm, ["x0","x1", "x2", "x3", "n", "z", "c", "v"])

