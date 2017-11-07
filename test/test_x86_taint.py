import pytest
import os
from util import X86


x86 = X86(
    os.path.join(os.path.dirname(os.path.realpath(__file__)),'x86.ini.in')
)

xfail = pytest.mark.skip

def test_flag_taint(tmpdir):
    asm = """
        test eax, eax
    """

    bc = x86.make_bc_test(tmpdir, asm)
    bc.initfile.set_reg("eax", "1!1")
    bc.run()

    assert bc.result.last_reg("eax").taint == 1
    assert bc.result.last_reg("eax").value == 1
    assert bc.result.last_reg("zf").value == 0
    assert bc.result.last_reg("zf").taint == 1

def test_cmov_taint(tmpdir):
    asm = """
        cmovz ebx, ecx
    """

    bc = x86.make_bc_test(tmpdir, asm)
    bc.initfile.set_reg("ecx", "0x12345678")
    bc.initfile.set_reg("zf", "1!1")
    bc.run()

    assert bc.result.last_reg("ebx").value == 0x12345678
    assert bc.result.last_reg("ebx").taint == 0xFFFFFFFF

