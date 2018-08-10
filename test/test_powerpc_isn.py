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


def test_arith_add(tmpdir):
    asm = """
        lis %r3, 0x1234
        ori %r3, %r3, 0x5678
        lis %r4, 0xabcd
        ori %r4, %r4, 0xffff
        add %r5, %r3, %r4
    """
    compare(tmpdir, asm, ["r3", "r4", "r5" ])

def test_arith_add_dot(tmpdir):
    asm = """
        lis %r3, 0x1234
        ori %r3, %r3, 0x5678
        lis %r4, 0xabcd
        ori %r4, %r4, 0xffff
        add. %r5, %r3, %r4
    """
    compare(tmpdir, asm, ["r3", "r4", "r5", "gt0", "lt0", "eq0" ])

def test_arith_addo(tmpdir):
    asm = """
        lis %r3, 0x1234
        ori %r3, %r3, 0x5678
        lis %r4, 0xabcd
        ori %r4, %r4, 0xffff
        addo %r5, %r3, %r4
    """
    compare(tmpdir, asm, ["r3", "r4", "r5", "ov" ])

def test_arith_addo_dot(tmpdir):
    asm = """
        lis %r3, 0x1234
        ori %r3, %r3, 0x5678
        lis %r4, 0xabcd
        ori %r4, %r4, 0xffff
        addo. %r5, %r3, %r4
    """
    compare(tmpdir, asm, ["r3", "r4", "r5", "gt0", "lt0", "eq0", "ov" ])


def test_arith_add_flags(tmpdir, op32h, op32l, op32h_, op32l_):
    asm = """
        lis %r3, {op32h}
        ori %r3, %r3, {op32l}
        lis %r4, {op32h_}
        ori %r4, %r4, {op32l_}
        addo. %r5, %r3, %r4
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "gt0", "lt0", "eq0", "ov" ])




##  _              _
## | |   ___  __ _(_)__
## | |__/ _ \/ _` | / _|
## |____\___/\__, |_\__|
##           |___/
## Logic

def test_logic_xor_flags(tmpdir, op32h, op32l, op32h_, op32l_):
    asm = """
        lis %r3, {op32h}
        ori %r3, %r3, {op32l}
        lis %r4, {op32h_}
        ori %r4, %r4, {op32l_}
        xor. %r5, %r3, %r4
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "gt0", "lt0", "eq0" ])

def test_logic_or_flags(tmpdir, op32h, op32l, op32h_, op32l_):
    asm = """
        lis %r3, {op32h}
        ori %r3, %r3, {op32l}
        lis %r4, {op32h_}
        ori %r4, %r4, {op32l_}
        or. %r5, %r3, %r4
    """.format(**locals())
    compare(tmpdir, asm, ["r3", "r4", "r5", "gt0", "lt0", "eq0" ])


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
    compare(tmpdir, asm, ["r3", "gt0", "lt0", "eq0", "so0" ])

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
    compare(tmpdir, asm, ["r3", "r4", "r5", "r6", "gt0", "lt0", "eq0", "so0", "so", "ov", "ca" ])
