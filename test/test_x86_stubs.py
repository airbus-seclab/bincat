import pytest
from util import X86

x86 = X86("x86_stub.ini.in")

xfail = pytest.mark.xfail

@pytest.mark.parametrize("val",[0, 1, 0x1f2, 0x1fa4, 0x45f672, 0x8245fa3d, 0xffffffff])
@pytest.mark.parametrize("fmt",[xfail("i"),
                                "x",
                                xfail("d"),
                                xfail("lx")])
@pytest.mark.parametrize("mod",["",
                                xfail("+"),
                                xfail("-")])
@pytest.mark.parametrize("zeropad",["","0"])
@pytest.mark.parametrize("sz",["","1","5","8","13"])
def test_printf_num(tmpdir, val, fmt, mod, zeropad, sz):
    fmtstr = "TEST[%{mod}{zeropad}{sz}{fmt}]".format(**locals())
    asm = """
        push {val:#x} 
        push 0x200      ; {fmt!r}
        call 0x80000000
    """.format(val=val, fmt=fmtstr)

    bc = x86.make_bc_test(tmpdir, asm)
    bc.initfile.set_mem(0x200, fmtstr+"\0")
    bc.run()

    expected = fmtstr % val
    
    assert bc.get_stdout() == expected, (repr(fmtstr)+"\n"+bc.listing)
    assert bc.result.last_reg("eax").value == len(expected), (repr(fmtstr)+"\n"+bc.listing)
    
