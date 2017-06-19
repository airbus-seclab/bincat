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
    
    assert expected == bc.get_stdout(), (repr(fmtstr)+"\n"+bc.listing)
    assert len(expected) == bc.result.last_reg("eax").value, (repr(fmtstr)+"\n"+bc.listing)


@pytest.mark.parametrize("numl",["", xfail("0"), "2", "5"])
@pytest.mark.parametrize("numr",["" ,xfail(".0"), xfail(".2"), xfail(".5")])
@pytest.mark.parametrize("val",["","abc", "abcdefghi"])
def test_printf_string(tmpdir, val, numl, numr):
    fmtstr = "TEST[%{numl}{numr}s]".format(**locals())
    asm = """
        push 0x300      ; {val!r}
        push 0x200      ; {fmt!r}
        call 0x80000000
    """.format(val=val, fmt=fmtstr)

    bc = x86.make_bc_test(tmpdir, asm)
    bc.initfile.set_mem(0x200, fmtstr+"\0")
    bc.initfile.set_mem(0x300, val+"\0")
    bc.run()

    expected = fmtstr % val
    
    assert expected == bc.get_stdout(), (repr(fmtstr)+"\n"+bc.listing)
    assert len(expected) == bc.result.last_reg("eax").value, (repr(fmtstr)+"\n"+bc.listing)

