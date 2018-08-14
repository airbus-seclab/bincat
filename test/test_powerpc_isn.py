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

ARITH_OPS = ["add", "sub", "addc"]

@pytest.mark.parametrize("op", ARITH_OPS)
def test_arith_add(tmpdir, op):
    asm = """
        lis %r3, 0x1234
        ori %r3, %r3, 0x5678
        lis %r4, 0xabcd
        ori %r4, %r4, 0xffff
        {op} %r5, %r3, %r4
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5" ])

@pytest.mark.parametrize("op", ARITH_OPS)
def test_arith_add_dot(tmpdir, op):
    asm = """
        lis %r3, 0x1234
        ori %r3, %r3, 0x5678
        lis %r4, 0xabcd
        ori %r4, %r4, 0xffff
        {op}. %r5, %r3, %r4
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "cr:29-31" ])

@pytest.mark.parametrize("op", ARITH_OPS)
def test_arith_addo(tmpdir, op):
    asm = """
        lis %r3, 0x1234
        ori %r3, %r3, 0x5678
        lis %r4, 0xabcd
        ori %r4, %r4, 0xffff
        {op}o %r5, %r3, %r4
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "ov" ])

@pytest.mark.parametrize("op", ARITH_OPS)
def test_arith_addo_dot(tmpdir, op):
    asm = """
        lis %r3, 0x1234
        ori %r3, %r3, 0x5678
        lis %r4, 0xabcd
        ori %r4, %r4, 0xffff
        {op}o. %r5, %r3, %r4
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "cr:29-31", "ov" ])

@pytest.mark.parametrize("op", ARITH_OPS)
@pytest.mark.parametrize("xer", [0x2000, 0x0000])
def test_arith_add_flags(tmpdir, op, xer, op32h, op32l, op32h_, op32l_):
    asm = """
        lis %r3, {xer}
        mtspr 1, %r3       # update XER
        lis %r3, {op32h}
        ori %r3, %r3, {op32l}
        lis %r4, {op32h_}
        ori %r4, %r4, {op32l_}
        {op}o. %r5, %r3, %r4
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "cr:29-31", "ov", "ca" ])



##  _              _
## | |   ___  __ _(_)__
## | |__/ _ \/ _` | / _|
## |____\___/\__, |_\__|
##           |___/
## Logic

@pytest.mark.parametrize("logic", ["or", "xor", "and"])
def test_logic_with_flags(tmpdir, logic, op32h, op32l, op32h_, op32l_):
    asm = """
        lis %r3, {op32h}
        ori %r3, %r3, {op32l}
        lis %r4, {op32h_}
        ori %r4, %r4, {op32l_}
        {logic}. %r5, %r3, %r4
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "cr:29-31" ])

def test_logic_neg(tmpdir, op32h, op32l):
    asm = """
        lis %r3, {op32h}
        ori %r3, %r3, {op32l}
        nego. %r4, %r3
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "cr:29-31", "ov" ])


##   ___
##  / __|___ _ __  _ __  __ _ _ _ ___
## | (__/ _ \ '  \| '_ \/ _` | '_/ -_)
##  \___\___/_|_|_| .__/\__,_|_| \___|
##                |_|
## Compare

@pytest.mark.parametrize("crfD", range(8))
def test_compare_cmp(tmpdir, crfD, op32h, op32h_):
    so = op32h & 0x8000
    asm = """
        lis %r3, 0
        mtcrf 0xff, %r3
        lis %r3, {so}
        mtspr 1, %r3     ; so = 0 or 1
        lis %r3, {op32h}
        lis %r4, {op32h_}
        cmp  cr{crfD}, %r3, %r4
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "cr"])


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


##  ___              _      _
## / __|_ __  ___ __(_)__ _| |
## \__ \ '_ \/ -_) _| / _` | |
## |___/ .__/\___\__|_\__,_|_|
##     |_|
## Special

@pytest.mark.parametrize("crval", [x<<12 for x in range(16)])
def test_special_mtcrf(tmpdir, crval):
    asm = """
        lis %r3, {crval}
        mtcrf 0xff, %r3
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "cr" ])

def test_special_mtcrf2(tmpdir, op8, op32h, op32l):
    asm = """
        lis %r3, 0
        mtcrf 0xff, %r3
        lis %r3, {op32h}
        ori %r3, %r3, {op32l}
        mtcrf {op8:#x}, %r3
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "cr" ])

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
        mtspr 1, %r3     ; so = 1
        lis %r4, 0
        mtcrf 0xff,%r4
        lis %r5, 0
        add. %r6, %r5, %r3
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "r6", "cr:28-31", "so", "ov", "ca" ])
