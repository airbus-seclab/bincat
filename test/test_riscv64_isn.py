import pytest
import os
from util import RISCV64

riscv64 = RISCV64(os.path.join(os.path.dirname(os.path.realpath(__file__)),'riscv64.ini.in'))
compare = riscv64.compare
show_cpu = riscv64.show_cpu


##  ___          _
## | _ ) __ _ __(_)__ ___
## | _ \/ _` (_-< / _(_-<
## |___/\__,_/__/_\__/__/
## Basics

def test_basics_nop(tmpdir):
    asm = """
        nop
    """
    show_cpu(tmpdir, asm, [])

def test_basics_assign_lui(tmpdir):
    asm = """
        lui x20, 0x12345
    """
    compare(tmpdir, asm, ["x20"])

def test_basics_assign_lui_sext(tmpdir):
    asm = """
        lui x20, 0x82345
    """
    compare(tmpdir, asm, ["x20"])


def test_basics_assign_li(tmpdir):
    asm = """
        li x20, 0x12345678
    """
    compare(tmpdir, asm, ["x20"])

def test_basics_assign_li_sext(tmpdir):
    asm = """
        li x20,0x82345678
    """
    compare(tmpdir, asm, ["x20"])

def test_basics_assign_auipc(tmpdir):
    asm = """
        auipc x20,0x12345
        nop
        auipc x21,0x12345
        sub x20,x21,x20
    """
    compare(tmpdir, asm, ["x20"])



def test_basics_assignx2(tmpdir):
    asm = """
        li x0,0xff001234
        li x1,0xff011234
        li x2,0xff021234
        li x3,0xff031234
        li x4,0xff041234
        li x5,0xff051234
        li x6,0xff061234
        li x7,0xff071234
        li x8,0xff081234
        li x9,0xff091234
        li x10,0xff0a1234
        li x11,0xff0b1234
        li x12,0xff0c1234
        li x13,0xff0d1234
        li x14,0xff0e1234
        li x15,0xff0f1234
        li x16,0xff101234
        li x17,0xff111234
        li x18,0xff121234
        li x19,0xff131234
        li x20,0xff141234
        li x21,0xff151234
        li x22,0xff161234
        li x23,0xff171234
        li x24,0xff181234
        li x25,0xff191234
        li x26,0xff1a1234
        li x27,0xff1b1234
        li x28,0xff1c1234
        li x29,0xff1d1234
        li x30,0xff1e1234
        li x31,0xff1f1234
    """
    show_cpu(tmpdir, asm, ["x0", "x1", "x3", "x4", "x5", "x6", "x7", "x8", # x2 will differ (stack pointer)
                          "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16",
                          "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24",
                          "x25", "x26", "x27", "x28", "x29", "x30", "x31"])



##    _       _ _   _              _   _
##   /_\  _ _(_) |_| |_  _ __  ___| |_(_)__ ___
##  / _ \| '_| |  _| ' \| '  \/ -_)  _| / _(_-<
## /_/ \_\_| |_|\__|_||_|_|_|_\___|\__|_\__/__/
## Arithmetics

#R-type arithmetic and logical instructions
# op can be: ADD, SUB, SLL, SLT, SLTU, XOR, SRL, SRA, OR, AND
op_arithmetic_logical_rtype = pytest.mark.parametrize("op", ["add", "sub", "sll", "slt", "sltu", "xor", "srl", "sra", "or", "and"])
@op_arithmetic_logical_rtype
def test_arith_log_rtype(tmpdir, op, op32, op32_):
    asm = """
    li x3, {op32}
    li x4, {op32_}
    {op} x5, x4, x3
    """.format(**locals())
    compare(tmpdir, asm, ["x3", "x4", "x5"])

#I-type arithmetic and logical instructions
#op can be: ADDI, SLTI, XORI, ORI, ANDI, SLLI, SRLI, SRAI
op_arithmetic_logical_itype = pytest.mark.parametrize("op", ["addi", "slti", "xori", "ori", "andi"])
@op_arithmetic_logical_itype
def test_arith_log_itype(tmpdir, op, op32, op12_s):
    asm = """
    li x3, {op32}
    {op} x4, x3, {op12_s}
    """.format(**locals())
    compare(tmpdir, asm, ["x3", "x4"])

#op can be: SLLI, SRLI, SRAI
op_arithmetic_logical_itype = pytest.mark.parametrize("op", ["slli", "srli", "srai"])
@op_arithmetic_logical_itype
def test_arith_log_shift_itype(tmpdir, op, op32, op5):
    asm = """
    li x3, {op32}
    {op} x4, x3, {op5}
    """.format(**locals())
    compare(tmpdir, asm, ["x3", "x4"])



##  ___                  _    _
## | _ )_ _ __ _ _ _  __| |_ (_)_ _  __ _
## | _ \ '_/ _` | ' \/ _| ' \| | ' \/ _` |
## |___/_| \__,_|_||_\__|_||_|_|_||_\__, |
##                                  |___/
## Branching


##  _                 _                 _    ___ _
## | |   ___  __ _ __| |   __ _ _ _  __| |  / __| |_ ___ _ _ ___
## | |__/ _ \/ _` / _` |  / _` | ' \/ _` |  \__ \  _/ _ \ '_/ -_)
## |____\___/\__,_\__,_|  \__,_|_||_\__,_|  |___/\__\___/_| \___|
## Load and Store


##  ___              _      _
## / __|_ __  ___ __(_)__ _| |
## \__ \ '_ \/ -_) _| / _` | |
## |___/ .__/\___\__|_\__,_|_|
##     |_|
## Special
