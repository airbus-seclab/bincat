import pytest
import os
from util import X86

x86 = X86(
    os.path.join(os.path.dirname(os.path.realpath(__file__)),'x86.ini.in')
)

xfail = pytest.mark.skip

def test_coverage(tmpdir):
    asm = """
        mov ebx, edi
        mov ebp, esi
        cmp edi, 0x9
        jg end
        mov edx, 0xA
        mov esi, 0x0
        end:
        mov eax, ebp
    """

    bc = x86.make_bc_test(tmpdir, asm)
    bc.initfile.set_reg("edi", "0x0?0xFFFFFFFF")
    bc.initfile.set_reg("esi", "0x0?0xFFFFFFFF")

    bc.run()
    cfa = bc.result.cfa
    assert len(cfa.edges[unicode(3)]) == 2
    assert cfa.nodes[unicode(8)].statements == u'esi <- 0x0;'

