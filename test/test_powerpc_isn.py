import pytest
import os
from util import PowerPC

powerpc = PowerPC(os.path.join(os.path.dirname(os.path.realpath(__file__)),'powerpc.ini.in'))
compare = powerpc.compare


##  ___          _
## | _ ) __ _ __(_)__ ___
## | _ \/ _` (_-< / _(_-<
## |___/\__,_/__/_\__/__/
## Basics

def test_basics_nop(tmpdir):
    asm = """
        ori %r0,%r31,0
        nop
    """
    compare(tmpdir, asm, [])


def test_basics_assign(tmpdir):
    asm = """
        lis %r3, 0x1234
        ori %r3, %r3, 0x5678
    """
    compare(tmpdir, asm, ["r3"])

def test_basics_assign2(tmpdir):
    asm = """
        lis %r3, 0x1234
        ori %r3, %r3, 0x5678
        lis %r4, 0xffff
        ori %r4, %r4, 0xA5A5
        lis %r5, 0xA1B2
        ori %r5, %r5, 0xD4C3
    """
    compare(tmpdir, asm, ["r3", "r4", "r5"])



##    _       _ _   _              _   _
##   /_\  _ _(_) |_| |_  _ __  ___| |_(_)__ ___
##  / _ \| '_| |  _| ' \| '  \/ -_)  _| / _(_-<
## /_/ \_\_| |_|\__|_||_|_|_|_\___|\__|_\__/__/
## Arithmetics

ARITH_OPS = ["add", "sub", "addc", "subfc", "adde", "subfe"]

@pytest.mark.parametrize("op", ARITH_OPS)
def test_arith_op(tmpdir, op):
    asm = """
        lis %r3, 0x1234
        ori %r3, %r3, 0x5678
        lis %r4, 0xabcd
        ori %r4, %r4, 0xffff
        mtspr 1, %r3       # update XER
        {op} %r5, %r3, %r4
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5" ])

@pytest.mark.parametrize("op", ARITH_OPS)
def test_arith_op_dot(tmpdir, op):
    asm = """
        lis %r3, 0x1234
        ori %r3, %r3, 0x5678
        lis %r4, 0xabcd
        ori %r4, %r4, 0xffff
        mtspr 1, %r3       # update XER
        {op}. %r5, %r3, %r4
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "cr:29-31" ])

@pytest.mark.parametrize("op", ARITH_OPS)
def test_arith_op_o(tmpdir, op):
    asm = """
        lis %r3, 0x1234
        ori %r3, %r3, 0x5678
        lis %r4, 0xabcd
        ori %r4, %r4, 0xffff
        mtspr 1, %r3       # update XER
        {op}o %r5, %r3, %r4
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "ov" ])

@pytest.mark.parametrize("op", ARITH_OPS)
def test_arith_op_o_dot(tmpdir, op):
    asm = """
        lis %r3, 0x1234
        ori %r3, %r3, 0x5678
        lis %r4, 0xabcd
        ori %r4, %r4, 0xffff
        mtspr 1, %r3       # update XER
        {op}o. %r5, %r3, %r4
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "cr:29-31", "ov", "ca" ])

@pytest.mark.parametrize("op", ARITH_OPS)
@pytest.mark.parametrize("xer", [0x2000, 0x0000])
def test_arith_op_flags(tmpdir, op, xer, op32, op32_):
    asm = """
        lis %r3, {xer}
        mtspr 1, %r3       # update XER
        lis %r3, {op32}@h
        ori %r3, %r3, {op32}@l
        lis %r4, {op32_}@h
        ori %r4, %r4, {op32_}@l
        {op}o. %r5, %r3, %r4
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "cr:29-31", "ov", "ca" ])

@pytest.mark.parametrize("op", ["addi", "addis"])
def test_arith_addi(tmpdir, op, op32, op16_s):
    asm = """
        lis %r0, {op32}@h
        ori %r0, %r0, {op32}@l
        lis %r3, {op32}@h
        ori %r3, %r3, {op32}@l
        {op} %r4, %r3, {op16_s}
        {op} %r5, %r0, {op16_s}
    """.format(**locals())
    compare(tmpdir, asm, ["r0", "r3", "r4", "r5"])

def test_arith_addic(tmpdir, op32, op16_s):
    asm = """
        lis %r3, {op32}@h
        ori %r3, %r3, {op32}@l
        addic %r4, %r3, {op16_s}
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "ca"])

@pytest.mark.parametrize("op", ["addic.", "subfic"])
def test_arith_addic_doc_subfic(tmpdir, op, op32, op16_s):
    asm = """
        lis %r3, {op32}@h
        ori %r3, %r3, {op32}@l
        mtcrf 0xff, %r3
        mtspr 1, %r3       # update XER (for XER.so flag)
        {op} %r4, %r3, {op16_s}
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "ca", "cr:29-31"])

@pytest.mark.parametrize("op", ["addme", "addze", "subfme", "subfze"])
@pytest.mark.parametrize("xer", [0x0000, 0x2000])
def test_arith_addmeo_addzeo_subfmeo_subfzeo_dot(tmpdir, op, xer, op32):
    asm = """
        lis %r3, {xer}
        mtspr 1, %r3       # update XER
        lis %r3, {op32}@h
        ori %r3, %r3, {op32}@l
        {op}o. %r4, %r3
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "cr:29-31", "ov", "ca" ])


def test_arith_extsb(tmpdir, op8):
    asm = """
        li %r3, {op8}
        extsb. %r4, %r3
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "cr:29-31"])

def test_arith_extsh(tmpdir, op16_s):
    asm = """
        li %r3, {op16_s}
        extsh. %r4, %r3
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "cr:29-31"])


def test_arith_divw(tmpdir, op32, op32_):
    asm = """
        lis %r3, {op32}@h
        ori %r3, %r3, {op32}@l
        lis %r4, {op32_}@h
        ori %r4, %r4, {op32_}@l
        divwo. %r5, %r3, %r4
    """.format(**locals())
    invalid = (op32_== 0) or (op32 == 0x80000000 and op32_ == 0xffffffff)
    top = { "r5": 0xffffffff, "cr":0xe0000000 } if invalid else {}
    compare(tmpdir, asm, ["r3", "r4", "r5", "cr:29-31", "ov"],
            top_allowed = top)

def test_arith_divwu(tmpdir, op32, op32_):
    asm = """
        lis %r3, {op32}@h
        ori %r3, %r3, {op32}@l
        lis %r4, {op32_}@h
        ori %r4, %r4, {op32_}@l
        divwuo. %r5, %r3, %r4
    """.format(**locals())
    invalid = op32_== 0
    top = { "r5": 0xffffffff, "cr":0xe0000000 } if invalid else {}
    compare(tmpdir, asm, ["r3", "r4", "r5", "cr:29-31", "ov"],
            top_allowed = top)


@pytest.mark.parametrize("op", ["mulchw","mulchwu", "mulhhw", "mulhhwu",
                                "mulhw", "mulhwu", "mullhw", "mullhwu",
                                "mullwo"])
def test_arith_mul(tmpdir, op, op32, op32_):
    asm = """
        lis %r3, {op32}@h
        ori %r3, %r3, {op32}@l
        lis %r4, {op32}@h
        ori %r4, %r4, {op32}@l
        {op}. %r5, %r3, %r4
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "cr:29-31"])


def test_arith_mulli(tmpdir, op32, op16_s):
    asm = """
        lis %r3, {op32}@h
        ori %r3, %r3, {op32}@l
        mulli %r4, %r3, {op16_s}
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4"])


##  _              _
## | |   ___  __ _(_)__
## | |__/ _ \/ _` | / _|
## |____\___/\__, |_\__|
##           |___/
## Logic

@pytest.mark.parametrize("logic", ["or", "xor", "and", "andc", "orc", "eqv", "nand", "nor"])
def test_logic_with_flags(tmpdir, logic, op32, op32_):
    asm = """
        lis %r3, {op32}@h
        ori %r3, %r3, {op32}@l
        lis %r4, {op32_}@h
        ori %r4, %r4, {op32_}@l
        {logic}. %r5, %r3, %r4
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "cr:29-31" ])

@pytest.mark.parametrize("logic", ["ori", "oris", "xori", "xoris" ])
def test_logic_imm(tmpdir, logic, op32, op16):
    asm = """
        lis %r3, {op32}@h
        ori %r3, %r3, {op32}@l
        {logic} %r4, %r3, {op16}
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4"])

@pytest.mark.parametrize("logic", ["andi.", "andis." ])
def test_logic_imm_dot(tmpdir, logic, op32, op16):
    asm = """
        lis %r3, {op32}@h
        ori %r3, %r3, {op32}@l
        {logic} %r4, %r3, {op16}
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "cr:29-31"])

def test_logic_neg(tmpdir, op32):
    asm = """
        lis %r3, {op32}@h
        ori %r3, %r3, {op32}@l
        nego. %r4, %r3
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "cr:29-31", "ov" ])


@pytest.mark.parametrize("exp", list(range(33)))
def test_cntlzw(tmpdir, exp, op32):
    op32 |= 2**exp
    asm = """
        lis %r3, {op32}@h
        ori %r3, %r3, {op32}@l
        cntlzw. %r4, %r3
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "cr:29-31"])

@pytest.mark.parametrize("op", ["rlwimi", "rlwinm"])
def test_logic_rlwimi_rlwinm_dot(tmpdir, op, op32, op32_, op5, op5_, op5__):
    asm = """
        lis %r3, {op32}@h
        ori %r3, %r3, {op32}@l
        lis %r4, {op32_}@h
        ori %r4, %r4, {op32_}@l
        {op}. %r4, %r3, {op5}, {op5_}, {op5__}
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "cr:29-31"])

def test_logic_rlwnm_dot(tmpdir, op32, op32_, op5, op5_, op5__):
    asm = """
        lis %r3, {op32}@h
        ori %r3, %r3, {op32}@l
        li %r5, {op5}
        rlwnm. %r4, %r3, %r5, {op5_}, {op5__}
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "cr:29-31"])

@pytest.mark.parametrize("op", ["slw", "srw", "sraw"])
@pytest.mark.parametrize("opshift", [0, 1, 6, 30, 31, 32, 35, 63, 66, 125])
def test_logic_shift_dot(tmpdir, op, op32, opshift):
    asm = """
        lis %r3, {op32}@h
        ori %r3, %r3, {op32}@l
        mtspr 1, %r3       # set ca to a determined value
        li %r4, {opshift}
        {op}. %r5, %r3, %r4
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "cr:29-31", "ca"])

def test_logic_srawi(tmpdir, op32, op5):
    asm = """
        lis %r3, {op32}@h
        ori %r3, %r3, {op32}@l
        mtspr 1, %r3       # set ca to a determined value
        srawi. %r4, %r3, {op5}
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "cr:29-31", "ca"])


##   ___
##  / __|___ _ __  _ __  __ _ _ _ ___
## | (__/ _ \ '  \| '_ \/ _` | '_/ -_)
##  \___\___/_|_|_| .__/\__,_|_| \___|
##                |_|
## Compare

@pytest.mark.parametrize("op", ["cmp", "cmpl"])
@pytest.mark.parametrize("crfD", list(range(8)))
def test_compare_cmp_cmpl(tmpdir, op, crfD, op32h, op32h_):
    so = op32h & 0x8000
    asm = """
        lis %r3, 0
        mtcrf 0xff, %r3
        lis %r3, {so}
        mtspr 1, %r3     # so = 0 or 1
        lis %r3, {op32h}
        lis %r4, {op32h_}
        {op}  cr{crfD}, %r3, %r4
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "cr"])

@pytest.mark.parametrize("crfD", list(range(8)))
def test_compare_cmpli(tmpdir, crfD, op32h, op32h_):
    so = op32h & 0x8000
    asm = """
        lis %r3, 0
        mtcrf 0xff, %r3
        lis %r3, {so}
        mtspr 1, %r3     # so = 0 or 1
        lis %r3, {op32h}
        cmpli  cr{crfD}, %r3, {op32h_}
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "cr"])

@pytest.mark.parametrize("crfD", list(range(8)))
def test_compare_cmpi(tmpdir, crfD, op32h, op16_s):
    so = op32h & 0x8000
    asm = """
        lis %r3, 0
        mtcrf 0xff, %r3
        lis %r3, {so}
        mtspr 1, %r3     # so = 0 or 1
        lis %r3, {op32h}
        cmpi  cr{crfD}, %r3, {op16_s}
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "cr"])


##  ___                  _    _
## | _ )_ _ __ _ _ _  __| |_ (_)_ _  __ _
## | _ \ '_/ _` | ' \/ _| ' \| | ' \/ _` |
## |___/_| \__,_|_||_\__|_||_|_|_||_\__, |
##                                  |___/
## Branching

def test_branch_b(tmpdir):
    asm = """
        lis %r3, 0x1234
        lis %r4, 0x4321
        b next
        lis %r3, 0xabcd
      next:
        lis %r4, 0xdcba
    """
    compare(tmpdir, asm, ["r3", "r4"])

def test_branch_b_back(tmpdir):
    asm = """
        lis %r3, 0x1234
        lis %r4, 0x1234
        lis %r5, 0x1234
        lis %r6, 0x1234
        b j1
        lis %r3, 0xabcd
      j2:
        lis %r4, 0xabcd
        b j3
      j1:
        b j2
        lis %r5, 0xdcba
      j3:
        lis %r6, 0xdcba
    """
    compare(tmpdir, asm, ["r3", "r4"])

def test_branch_and_link(tmpdir):
    asm = """
        lis %r3, 0x1234
        lis %r4, 0x1234
        lis %r5, 0x1234
        lis %r6, 0x1234
        bl j1
        lis %r3, 0xabcd
        b j2
      j1:
        lis %r4, 0xabcd
        blr
        lis %r5, 0xdcba
      j2:
        lis %r6, 0xdcba
    """
    compare(tmpdir, asm, ["r3", "r4", "r5", "r6"])

def test_branch_and_link2(tmpdir):
    asm = """
        bl j1
        nop
        nop
      j1:
        mflr %r3
        bl j2
        nop
        nop
        nop
        nop
      j2:
        mflr %r4
        sub %r3, %r4, %r3
    """
    compare(tmpdir, asm, ["r3"])


VALID_COND_BYTES = [ 0x00,       0x02,       0x04,       0x06, 0x07,
                     0x08,       0x0a,       0x0c,       0x0e, 0x0f,
                     0x10,       0x12,       0x14,
                     0x18, 0x19, 0x1a, 0x1b,                         ]

@pytest.mark.parametrize("cr7", list(range(16)))
@pytest.mark.parametrize("bit", ["gt", "lt", "eq", "so"])
@pytest.mark.parametrize("cond", VALID_COND_BYTES)
@pytest.mark.parametrize("ctr", [0, 1])
def test_branch_bclr(tmpdir, cr7, bit, cond, ctr):
    asm = """
        li %r7, {cr7}
        mtcrf 0xff, %r7
        li %r8, {ctr}
        mtctr %r8
        lis %r3, 0x1234
        lis %r4, 0x1234
        lis %r5, 0x1234
        lis %r6, 0x1234
        bl j1
        lis %r3, 0xabcd
        b j2
      j1:
        lis %r4, 0xabcd
        bclr {cond}, 4*cr7+{bit}
        lis %r5, 0xdcba
      j2:
        lis %r6, 0xdcba
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "r6", "r7", "r8", "ctr"])

@pytest.mark.parametrize("cr7", list(range(16)))
@pytest.mark.parametrize("bit", ["gt", "lt", "eq", "so"])
@pytest.mark.parametrize("cond", [ x for x in VALID_COND_BYTES if x & 4 ])
                         # only conds that do not touch to CTR for bcctr
@pytest.mark.parametrize("ctr", [0, 1])
def test_branch_bcctr_bclr(tmpdir, cr7, bit, cond, ctr):
    asm = """
        li %r7, {cr7}
        mtcrf 0xff, %r7
        li %r8, {ctr}
        mtctr %r8
        lis %r3, 0x1234
        lis %r4, 0x1234
        lis %r5, 0x1234
        lis %r6, 0x1234
        bl j1
        lis %r3, 0xabcd
        b j2
      j1:
        lis %r4, 0xabcd
        mflr %r9
        mtctr %r9
        bcctr {cond}, 4*cr7+{bit}
        lis %r5, 0xdcba
      j2:
        lis %r6, 0xdcba
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "r6", "r7", "r8"])


@pytest.mark.parametrize("cr7", list(range(16)))
@pytest.mark.parametrize("cond", VALID_COND_BYTES)
@pytest.mark.parametrize("bit", ["gt", "lt", "eq", "so"])
def test_branch_cond(tmpdir, cr7, bit, cond):
    asm = """
        li %r3, {cr7}
        mtcrf 0xff, %r3
        lis %r3, 0x1234
        lis %r4, 0x1234
        lis %r5, 0x1234
        lis %r6, 0x1234
        lis %r7, 0x1234
        lis %r8, 0x1234
        bc {cond}, 4*cr7+{bit}, j1
        lis %r3, 0xabcd
        b j2
      j1:
        lis %r4, 0xabcd
      j2:
        lis %r5, 0xabcd
        b j3
      j4:
        lis %r6, 0xabcd
        b j5
      j3:
        bc {cond}, 4*cr7+{bit}, j4
        lis %r7,0xabcd
      j5:
        lis %r8, 0xabcd
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "r6", "r7", "r8", "cr"])


##  _                 _                 _    ___ _
## | |   ___  __ _ __| |   __ _ _ _  __| |  / __| |_ ___ _ _ ___
## | |__/ _ \/ _` / _` |  / _` | ' \/ _` |  \__ \  _/ _ \ '_/ -_)
## |____\___/\__,_\__,_|  \__,_|_||_\__,_|  |___/\__\___/_| \___|
## Load and Store


@pytest.mark.parametrize("op", ["lbz", "lbzu", "lha", "lhau",
                                "lhz", "lhzu", "lwz", "lwzu",])
@pytest.mark.parametrize("val", [0, 1, 0x7f, 0x80, 0x7fff, 0x8000, 0x7fffffff, 0x80000000, 0xffffffff])
def test_load(tmpdir, op, val):
    valh = val >> 16
    vall = val & 0xffff
    asm = """
        lis %r3, {valh}
        ori %r3, %r3, {vall}
        mr %r4, %r1
        mr %r6, %r1
        stw %r3, 12(%r1)
        stw %r3, -16(%r1)
        {op} %r5, 12(%r4)
        {op} %r7, -16(%r6)
        subf %r4, %r4, %r1
        subf %r6, %r6, %r1
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "r6", "r7"])

@pytest.mark.parametrize("op", ["lbzux", "lbzx", "lhaux", "lhax", "lhbrx",
                                "lhzux", "lhzx", "lwbrx", "lwzux", "lwzx"])
@pytest.mark.parametrize("val", [0, 1, 0x7f, 0x80, 0x7fff, 0x8000, 0x7fffffff, 0x80000000, 0xffffffff])
def test_load_indexed(tmpdir, op, val):
    valh = val >> 16
    vall = val & 0xffff
    asm = """
        lis %r3, {valh}
        ori %r3, %r3, {vall}
        li %r8, 12
        li %r9, -16
        mr %r4, %r1
        mr %r6, %r1
        stw %r3, 12(%r1)
        stw %r3, -16(%r1)
        {op} %r5, %r4, %r8
        {op} %r7, %r6, %r9
        subf %r4, %r4, %r1
        subf %r6, %r6, %r1
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "r6", "r7"])

@pytest.mark.parametrize("op", ["lbz", "lbzu", "lha", "lhau",
                                "lhz", "lhzu", "lwz", "lwzu",])
@pytest.mark.parametrize("ofs", [0,1,2,3,4,5,10])
def test_load_from_mapping(tmpdir, op, ofs):
    asm = """
        b j2
    j1:
        mflr %r3
        {op} %r4, {ofs}(%r3)
        b end
    j2:
        bl j1
        .string "the quick brown fox jumps over the lazy dog"
        .align 4
     end:
        nop

    """.format(**locals())
    compare(tmpdir, asm, ["r4"])

@pytest.mark.parametrize("op", ["stb", "stbu", "sth", "sthu", "stw", "stwu" ])
@pytest.mark.parametrize("val", [0, 1, 0x7f, 0x80, 0x7fff, 0x8000, 0x7fffffff, 0x80000000, 0xffffffff])
def test_store(tmpdir, op, val):
    valh = val >> 16
    vall = val & 0xffff
    asm = """
        lis %r3, 0x5555
        ori %r3, %r3, 0x5555
        stw %r3, 12(%r1)
        stw %r3, -16(%r1)
        lis %r3, {valh}
        ori %r3, %r3, {vall}
        mr %r4, %r1
        mr %r6, %r1
        {op} %r3, 12(%r4)
        {op} %r3, -16(%r6)
        subf %r4, %r4, %r1
        subf %r6, %r6, %r1
        lwz %r5, 12(%r1)
        lwz %r7, -16(%r1)
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "r6", "r7"])

@pytest.mark.parametrize("op", ["stbux", "stbx", "sthbrx", "sthux",
                                "sthx", "stwbrx", "stwux", "stwx"])
@pytest.mark.parametrize("val", [0, 1, 0x7f, 0x80, 0x7fff, 0x8000, 0x7fffffff, 0x80000000, 0xffffffff])
def test_store_indexed(tmpdir, op, val):
    valh = val >> 16
    vall = val & 0xffff
    asm = """
        lis %r3, 0x5555
        ori %r3, %r3, 0x5555
        stw %r3, 12(%r1)
        stw %r3, -16(%r1)
        lis %r3, {valh}
        ori %r3, %r3, {vall}
        li %r8, 12
        li %r9, -16
        mr %r4, %r1
        mr %r6, %r1
        {op} %r3, %r4, %r8
        {op} %r3, %r6, %r9
        subf %r4, %r4, %r1
        subf %r6, %r6, %r1
        lwz %r5, 12(%r1)
        lwz %r7, -16(%r1)
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "r6", "r7"])

def test_load_lmw(tmpdir):
    asm = """
        lis %r3, 0xdead
        stwu %r3, 4(%r1)
        ori %r3, %r3, 0xbeef
        stwu %r3, 4(%r1)
        stw %r3, 4(%r1)
        stw %r3, 8(%r1)
        stw %r3, 12(%r1)
        lmw %r27, -4(%r1)
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r27", "r28", "r29", "r30", "r31"])

def test_load_stmw(tmpdir):
    asm = """
        lis %r31, 0x3131
        lis %r30, 0x3030
        lis %r29, 0x2929
        lis %r28, 0x2828
        stmw %r28, -4(%r1)
        lwz %r3, -4(%r1)
        lwz %r4, 0(%r1)
        lwz %r5, 4(%r1)
        lwz %r6, 8(%r1)
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "r6", "r28", "r29", "r30", "r31"])

@pytest.mark.parametrize("op", list(range(1, 33)))
def test_load_lswi(tmpdir, op):
    asm = """
        xor %r0, %r0, %r0
        mr %r1, %r0
        mr %r2, %r0
        mr %r3, %r0
        mr %r4, %r0
        mr %r28, %r0
        mr %r29, %r0
        mr %r30, %r0
        mr %r31, %r0
        b j2
    j1:
        mflr %r10
        lswi %r28,%r10,{op}
        b end
    j2:
        bl j1
        .string "the quick brown fox jumps over the lazy dog"
        .align 4
     end:
        nop
    """.format(**locals())
    compare(tmpdir, asm, ["r0", "r1", "r2", "r3", "r4", "r28", "r29", "r30", "r31"])

@pytest.mark.parametrize("op", list(range(1, 33)))
def test_store_stswi(tmpdir, op):
    initreg = ["    lis %r{num}, 0xaa{num:02d}\n    ori %r{num}, %r{num}, 0x55{num:02d}".format(num=i)
               for i in [28, 29, 30, 31, 0, 1, 2, 3, 4]]
    asm = "\n".join(initreg)+"""
        b j2
    j1:
        mflr %r10
        stswi %r28,%r10,{op}
        b end
    j2:
        bl j1
        .string "the quick brown fox jumps over the lazy dog"
        .align 4
     end:
        lmw %r24, 0(%r10)
    """.format(**locals())
    compare(tmpdir, asm, ["r0", "r1", "r2", "r3", "r4", "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31"])


##   ___                          ___ ___
##  / _ \ _ __ ___   ___ _ _     / __| _ \
## | (_) | '_ (_-<  / _ \ ' \   | (__|   /
##  \___/| .__/__/  \___/_||_|   \___|_|_\
##       |_|
## Ops on CR


CR_OPS = ["crand", "crandc", "creqv", "crnand",
          "crnor", "cror", "crorc", "crxor"]

@pytest.mark.parametrize("op", CR_OPS)
def test_cr_ops(tmpdir, op, op32, op5, op5_, op5__):
    asm = """
        lis %r3, {op32}@h
        ori %r3, %r3, {op32}@l
        mtcrf 0xff, %r3
        {op} {op5}, {op5_}, {op5__}
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "cr"])


def test_cr_mcrf(tmpdir, op3, op3_, op32):
    asm = """
        lis %r3, {op32}@h
        ori %r3, %r3, {op32}@l
        mtcrf 0xff, %r3
        mcrf {op3}, {op3_}
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "cr"])

@pytest.mark.parametrize("crval", [x<<12 for x in range(16)])
def test_cr_mtcrf(tmpdir, crval):
    asm = """
        lis %r3, {crval}
        mtcrf 0xff, %r3
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "cr" ])

def test_cr_mtcrf2(tmpdir, op8, op32):
    asm = """
        lis %r3, 0
        mtcrf 0xff, %r3
        lis %r3, {op32}@h
        ori %r3, %r3, {op32}@l
        mtcrf {op8:#x}, %r3
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "cr" ])

def test_cr_mfcr(tmpdir, op32):
    asm = """
        lis %r3, {op32}@h
        ori %r3, %r3, {op32}@l
        mtcrf 0xff, %r3
        mfcr %r4
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "cr"])


##  ___              _      _
## / __|_ __  ___ __(_)__ _| |
## \__ \ '_ \/ -_) _| / _` | |
## |___/ .__/\___\__|_\__,_|_|
##     |_|
## Special

@pytest.mark.parametrize("xerval", [x<<13 for x in range(8)])
def test_special_mtspr_xer(tmpdir, xerval, op8):
    asm = """
        lis %r3, {xerval}
        ori %r3, %r3, {op8}
        mtspr 1, %r3
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "so", "ov", "ca", "tbc"])

def test_special_XERso_to_CRso(tmpdir):
    asm = """
        lis %r3, 0x8000
        mtspr 1, %r3     # so = 1
        lis %r4, 0
        mtcrf 0xff,%r4
        lis %r5, 0
        add. %r6, %r5, %r3
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "r6", "cr:28-31", "so", "ov", "ca" ])

def test_special_mfspr_processor_version(tmpdir):
    ## PV value comes from powerpc.ini
    asm = """
        lis %r3, 0x1234
        ori %r3,%r3,0x5678
        mfspr %r3, 287
    """
    compare(tmpdir, asm, ["r3"])
