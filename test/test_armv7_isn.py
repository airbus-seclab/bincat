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



##  ___   _ _____ _     ___ ___  ___   ___ 
## |   \ /_\_   _/_\   | _ \ _ \/ _ \ / __|
## | |) / _ \| |/ _ \  |  _/   / (_) | (__ 
## |___/_/ \_\_/_/ \_\ |_| |_|_\\___/ \___|
## 
## DATA PROC

dataop  = pytest.mark.parametrize("op", ["mov", "mvn"])
dataop2 = pytest.mark.parametrize("op", ["and", "eor", "sub", "rsb", "add", "orr", "bic"])


def test_mov_reg(tmpdir):
    asm = """
            mov r0, #0x12
            movs r1, r0
            mov r2, r0, lsl #7
            mov r3, r0, lsr #1
    """
    compare(tmpdir, asm, ["r0","r1", "r2", "r3", "z", "n"])

@dataop
def test_shifted_register_lsl_imm_shift(tmpdir, op, armv7op, armv7shift):
    asm = """
            mov r0, #{armv7op}
            {op}s r1, r0, lsl #{armv7shift}
    """.format(**locals())
    compare(tmpdir, asm, ["r0", "r1", "c", "n", "z"],
            top_allowed={"c": 1 if armv7shift == 0 else 0})

@dataop
def test_shifted_register_lsl_reg_shift(tmpdir, op, armv7op, armv7shift):
    asm = """
            mov r0, #{armv7op}
            mov r1, #{armv7shift}
            {op}s r2, r0, lsl r1
    """.format(**locals())
    compare(tmpdir, asm, ["r0", "r1", "r2", "c", "n", "z"],
            top_allowed={"c": 1 if armv7shift == 0 else 0})

@dataop
def test_shifted_register_lsr_imm_shift(tmpdir, op, armv7op, armv7shift):
    asm = """
            mov r0, #{armv7op}
            {op}s r1, r0, lsr #{armv7shift}
    """.format(**locals())
    compare(tmpdir, asm, ["r0", "r1", "c", "n", "z"],
            top_allowed={"c": 1 if armv7shift == 0 else 0})

@dataop
def test_shifted_register_lsr_reg_shift(tmpdir, op, armv7op, armv7shift):
    asm = """
            mov r0, #{armv7op}
            mov r1, #{armv7shift}
            {op}s r2, r0, lsr r1
    """.format(**locals())
    compare(tmpdir, asm, ["r0", "r1", "r2", "c", "n", "z"],
            top_allowed={"c": 1 if armv7shift == 0 else 0})

@dataop
def test_shifted_register_lsr_imm_32(tmpdir, op, armv7op):
    asm = """
            mov r0, #{armv7op}
            {op}s r1, r0, lsr #32
    """.format(**locals())
    compare(tmpdir, asm, ["r0", "r1", "c", "n", "z"])

@dataop
def test_shifted_register_lsr_reg_32(tmpdir, op, armv7op):
    asm = """
            mov r0, #{armv7op}
            mov r1, #32
            {op}s r2, r0, lsr r1
    """.format(**locals())
    compare(tmpdir, asm, ["r0", "r1", "r2", "c", "n", "z"])

@pytest.mark.xfail
def test_shifted_register_asr(tmpdir, armv7shift):
    asm = """
            mov r0, #0x12
            mov r1, r0, asr #{armv7shift}
    """.format(**locals())
    compare(tmpdir, asm, ["r0","r1"])

@pytest.mark.xfail
def test_shifted_register_ror(tmpdir, armv7shift):
    asm = """
            mov r0, #0x12
            mov r1, r0, ror #{armv7shift}
    """.format(**locals())
    compare(tmpdir, asm, ["r0","r1"])

def test_mov_set_zflag(tmpdir):
    asm = """
            mov r1, #0
            mov r2, #0
            mov r3, #0
            mov r4, #0
            movs r0, #0x12
            moveq r1, #1
            movne r2, #1
            movs r0, #0
            moveq r3, #1
            movne r4, #1
    """
    compare(tmpdir, asm, ["r0","r1","r2","r3", "r4", "n", "z"])

def test_mov_set_vflag(tmpdir):
    asm = """
            mov r1, #0
            mov r2, #0
            mov r3, #0
            mov r4, #0
            movs r0, #0x12
            movmi r1, #1
            movpl r2, #1
            movs r0, #0x80000000
            movmi r3, #1
            movpl r4, #1
    """
    compare(tmpdir, asm, ["r0","r1","r2","r3", "r4", "n", "z"])

def test_mvn(tmpdir):
    asm = """
            mov r1, #123
            mvn r2, r1
            mvn r3, r1, lsl #5
    """
    compare(tmpdir, asm, ["r1","r2","r3"])

@dataop2
def test_data_proc(tmpdir, op, armv7op, armv7op_):
    asm = """
            mov r0, #{armv7op}
            mov r1, #{armv7op}
            {op} r2, r0, r1
            {op}s r3, r0, r1
    """.format(**locals())
    compare(tmpdir, asm, ["r0","r1", "r2", "r3", "n", "z"])

