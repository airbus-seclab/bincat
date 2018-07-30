import pytest
import os
from util import AARCH64

arm = AARCH64(
    os.path.join(os.path.dirname(os.path.realpath(__file__)),'armv8.ini.in')
)
compare = arm.compare

mov_imm = pytest.mark.parametrize("op", ["movz", "movk", "movn"])
dataop_comp_logic = pytest.mark.parametrize("op", ["and", "eor", "orr", "bic"])
dataop_comp_arith = pytest.mark.parametrize("op", ["sub", "add", "adds", "subs"])

def test_adrp1(tmpdir, op32):
    asm = """
    label1:
        adrp x0, label1
        mov x0,x0
        mov x0,x0
        mov x0,x0
        mov x0,x0
        mov x0,x0
    label2:
        adrp x1, label2
        sub x3, x1, x0
    """.format(**locals())
    compare(tmpdir, asm, ["x3"])


def test_adrp2(tmpdir, op32):
    asm = """
        adrp x0, label
        mov x0,x0
        mov x0,x0
    label:
        mov x0,x0
        mov x0,x0
        mov x0,x0
        adrp x1, label
        sub x3, x1, x0
    """.format(**locals())
    compare(tmpdir, asm, ["x3"])

def test_data_xfer_offsets(tmpdir, armv8off):
    asm = """
            mov x0, #0
            mov x1, #123
            mov x2, #101
            stp x1, x2, [sp, #{armv8off}]
            ldp x3, x4, [sp, #{armv8off}]
    """.format(**locals())
    compare(tmpdir, asm, ["x0", "x1", "x2", "x3", "x4"])

@mov_imm
def test_mov(tmpdir, op, op16, armv8shift):
    asm = """
        mov x0, 0
        sub x0, x0, 1
        {op} x0, #{op16}, LSL #{armv8shift}
        mov w1, w0
        mov w2, w1
    """.format(**locals())
    compare(tmpdir, asm, ["x0","x1","x2"])

@dataop_comp_logic
def test_data_proc_logic_imm(tmpdir, op, armv7op, armv7op_, armv8bitmasks):
    asm = """
            mov x0, #{armv7op}
            mov x1, #{armv7op_}
            {op} x2, x0, #{armv8bitmasks}
    """.format(**locals())
    compare(tmpdir, asm, ["x0","x1", "x2"])

@dataop_comp_logic
def test_data_proc_logic(tmpdir, op, armv7op, armv7op_):
    asm = """
            mov x0, #{armv7op}
            mov x1, #{armv7op_}
            {op} x2, x0, x1
    """.format(**locals())
    compare(tmpdir, asm, ["x0","x1", "x2"])

@dataop_comp_arith
def test_data_proc_arith(tmpdir, op, armv7op, armv7op_):
    asm = """
            mov x0, #{armv7op}
            mov x1, #{armv7op_}
            {op} x2, x0, x1
    """.format(**locals())
    if op[-1] != 's':
        top_allowed = {"n":1, "c":1, "v":1, "z":1}
    else:
        top_allowed = {}
    compare(tmpdir, asm, ["x0","x1", "x2", "n", "c", "v", "z"], top_allowed = top_allowed)

@dataop_comp_arith
def test_data_proc_arith_imm(tmpdir, op, armv7op, op12):
    asm = """
            mov x0, #{armv7op}
            {op} x2, x0, #{op12}
    """.format(**locals())
    if op[-1] != 's':
        top_allowed = {"n":1, "c":1, "v":1, "z":1}
    else:
        top_allowed = {}
    compare(tmpdir, asm, ["x0", "x2", "n", "c", "z", "v"], top_allowed = top_allowed)

@dataop_comp_logic
def test_data_proc_logic_32(tmpdir, op, armv7op, armv7op_):
    asm = """
            mov w0, #{armv7op}
            mov w1, #{armv7op_}
            {op} w2, w0, w1
    """.format(**locals())
    compare(tmpdir, asm, ["x0","x1", "x2"])

@dataop_comp_arith
def test_data_proc_arith_32(tmpdir, op, armv7op, armv7op_):
    asm = """
            mov w0, #{armv7op}
            mov w1, #{armv7op_}
            {op} w2, w0, w1
    """.format(**locals())
    if op[-1] != 's':
        top_allowed = {"n":1, "c":1, "v":1, "z":1}
    else:
        top_allowed = {}
    compare(tmpdir, asm, ["x0","x1", "x2", "n", "c", "v", "z"], top_allowed = top_allowed)

def test_ubfm(tmpdir, op6, op6_, armv7op, armv7op_):
    asm = """
            mov x0, #{armv7op}
            mov x1, #{armv7op_}
            UBFM x2, x0, #{op6}, #{op6_}
    """.format(**locals())
    compare(tmpdir, asm, ["x0","x1", "x2"])

def test_ubfm32(tmpdir, op6_32, op6_32_, armv7op, armv7op_):
    asm = """
            mov w0, #{armv7op}
            mov w1, #{armv7op_}
            UBFM w2, w0, #{op6_32}, #{op6_32_}
    """.format(**locals())
    compare(tmpdir, asm, ["x0","x1", "x2"])

def test_madd_sub32(tmpdir, op32, op32_, op32__, op32___):
    asm = """
            mov w0, #{op32}
            mov w1, #{op32_}
            mov w2, #{op32__}
            mov w3, #{op32___}
            madd w0, w1, w2, w3
    """.format(**locals())
    compare(tmpdir, asm, ["x0","x1", "x2", "x3"])

def test_madd_sub64(tmpdir, op64, op64_, op64__, op64___):
    asm = """
            mov x0, #{op64}
            mov x1, #{op64_}
            mov x2, #{op64__}
            mov x3, #{op64___}
            madd x0, x1, x2, x3
    """.format(**locals())
    compare(tmpdir, asm, ["x0","x1", "x2", "x3"])

def test_sxtw(tmpdir, armv7op, armv7op_):
    asm = """
            mov w0, #{armv7op}
            sxtw x0, w0
    """.format(**locals())
    compare(tmpdir, asm, ["x0"])

def test_add_sxtw(tmpdir, armv7op, armv7op_):
    asm = """
            mov x0, #{armv7op}
            mov x1, #{armv7op_}
            add x2, x1, w0, sxtw
    """.format(**locals())
    compare(tmpdir, asm, ["x0", "x1", "x2"])

def test_fp_fmov(tmpdir, armv7op):
    asm = """
            mov x0, #{armv7op}
            fmov s0, w0
            fmov s10, w0
    """.format(**locals())
    compare(tmpdir, asm, ["q0", "q10"])


def test_simd_eor(tmpdir, armv7op, armv7op_):
    asm = """
            mov x0, #{armv7op}
            fmov s0, w0
            mov x1, #{armv7op_}
            fmov s1, w1
            eor v2.8b, v0.8b, v1.8b
    """.format(**locals())
    compare(tmpdir, asm, ["x0", "x1", "q0", "q1", "q2"])

def test_simd_orr(tmpdir, armv7op, armv7op_):
    asm = """
            mov x0, #{armv7op}
            fmov s0, w0
            mov x1, #{armv7op_}
            fmov s1, w1
            orr v2.8b, v0.8b, v1.8b
    """.format(**locals())
    compare(tmpdir, asm, ["x0", "x1", "q0", "q1", "q2"])

def test_simd_and(tmpdir, armv7op, armv7op_):
    asm = """
            mov x0, #{armv7op}
            fmov s0, w0
            mov x1, #{armv7op_}
            fmov s1, w1
            and v2.8b, v0.8b, v1.8b
    """.format(**locals())
    compare(tmpdir, asm, ["x0", "x1", "q0", "q1", "q2"])


# This tests does arithmetic between the stack and the global region
# x2 is S0x0, and then stored on the stack
# ldr w3, [x0] should trigger a pointer.combine between G0x0 (first line)
# and S0x0, setting x3 to bottom
def test_stack_combine(tmpdir):
    asm = """
            mov x3, 0
            mov x0, sp
            mov x1, sp
            sub x2, x0, x1
            str x2, [x0]
            ldr w3, [x0]
            add x3, x3, 0x100
    """.format(**locals())
    compare(tmpdir, asm, [ "x3"])
