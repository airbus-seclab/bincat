import pytest
import subprocess
import copy
import binascii
import os.path
import itertools
from collections import defaultdict
from pybincat import cfa

def counter(fmt="%i", i=0):
    while True:
        yield fmt % i
        i += 1

GCC_DIR = counter("gcc-%i")
NASM_DIR = counter("nasm-%i")

ALL_FLAGS = ["cf","pf", "af", "zf","sf","df","of"]
ALL_REGS = ["eax","ebx","ecx","edx", "esi","edi","esp", "ebp"] + ALL_FLAGS

def assemble(tmpdir, asm):
    d = tmpdir.mkdir(NASM_DIR.next())
    inf = d.join("asm.S")
    outf = d.join("opcodes")
    inf.write("BITS 32\n"+asm)
    listing = subprocess.check_output(["nasm", "-l", "/dev/stdout", "-o", str(outf), str(inf)])
    opcodes = open(str(outf)).read()
    return str(outf),listing,opcodes


C_TEMPLATE_PROLOGUE = r"""
#include <stdio.h>
void main(void)
{
        unsigned int Reax,Rebx,Recx,Redx,Resi,Redi,Resp,Rebp,Reflags;
        asm volatile(
"""

C_TEMPLATE_EPILOGUE = r""" 
        "mov %0, eax\n"
        "mov %1, esp\n"
        "mov %2, ebp\n"
        "pushf\n"
        "pop eax\n"
        : 
        "=m" (Reax),
        "=m" (Resp),
        "=m" (Rebp),
        "=a" (Reflags),
        "=b" (Rebx),
        "=c" (Recx),
        "=d" (Redx),
        "=S" (Resi),
        "=D" (Redi)
        ::);
        printf("eax=%08x\n", Reax);
        printf("ebx=%08x\n", Rebx);
        printf("ecx=%08x\n", Recx);
        printf("edx=%08x\n", Redx);
        printf("esi=%08x\n", Resi);
        printf("edi=%08x\n", Redi);
        printf("esp=%08x\n", Resp);
        printf("ebp=%08x\n", Rebp);
        printf("eflags=%08x\n", Reflags);
}
"""

def strip_asm_comments(asm):
    s = []
    for l in asm.splitlines():
        p = l.find(";")
        if  p >= 0:
            l = l[:p]
        s.append(l)
    return "\n".join(s)

def cpu_run(tmpdir, asm):
    asm = strip_asm_comments(asm)
    d = tmpdir.mkdir(GCC_DIR.next())
    inf = d.join("test.c")
    outf = d.join("test")
    inf.write(C_TEMPLATE_PROLOGUE +
              '"'+asm.replace("\n",'\\n"\n"') + '"' +
              C_TEMPLATE_EPILOGUE)
    subprocess.check_call(["gcc", "-m32", "-masm=intel", "-o", str(outf), str(inf)])
    out = subprocess.check_output([str(outf)])
    regs = { reg: int(val,16) for reg, val in
            (l.strip().split("=") for l in out.splitlines()) }
    flags = regs.pop("eflags")
    regs["cf"] = flags & 1
    regs["pf"] = (flags >> 2) & 1
    regs["af"] = (flags >> 4) & 1
    regs["zf"] = (flags >> 6) & 1
    regs["sf"] = (flags >> 7) & 1
    regs["df"] = (flags >> 10) & 1
    regs["of"] = (flags >> 11) & 1
    return regs


def getReg(my_state, name):
    v = cfa.Value('reg', name, cfa.reg_len(name))
    return my_state[v][0]
def getLastState(prgm):
    curState = prgm['0']
    while True:
        nextStates = prgm.next_states(curState.node_id)
        if len(nextStates) == 0:
            return curState
        assert len(nextStates) == 1, \
            "expected exactly 1 destination state after running this instruction"
        curState = nextStates[0]

def prettify_listing(asm):
    s = []
    for l in asm.splitlines():
        l = l.strip()
        if "BITS 32" in l or len(l.split()) <= 1:
            continue
        if l:
            s.append("\t"+l)
    return "\n".join(s)


def extract_directives_from_asm(asm):
    d = defaultdict(dict)
    for l in asm.splitlines():
        if "@override" in l:
            sl = l.split()
            addr = int(sl[1],16)
            val = sl[sl.index("@override")+1]
            d["override"][addr] = val 
    return d


def bincat_run(tmpdir, asm):
    opcodesfname,listing,opcodes = assemble(tmpdir, asm)

    directives = extract_directives_from_asm(listing)
    
    outf = tmpdir.join('end.ini')
    logf = tmpdir.join('log.txt')
    initf = tmpdir.join('init.ini')
    initf.write(
        open("test_values.ini").read().format(
            code_length = len(opcodes),
            filepath = opcodesfname,
            overrides = "\n".join("%#010x=%s" % (addr, val) for addr,val in directives["override"].iteritems())
        )
    )

    try:
        prgm = cfa.CFA.from_filenames(str(initf), str(outf), str(logf))
    except Exception,e:
        return e, listing

    last_state = getLastState(prgm)
    
    return { reg : getReg(last_state, reg) for reg in ALL_REGS}, listing


def compare(tmpdir, asm, regs=ALL_REGS, reg_taints={}):
    cpu = cpu_run(tmpdir, asm)
    bincat,listing = bincat_run(tmpdir, asm)
    assert  not isinstance(bincat, Exception), repr(bincat)+"\n"+prettify_listing(listing)+"\n=========================\n"+"\n".join("cpu : %s = %08x" % (r,cpu[r]) for r in regs)
    
    diff = []
    same = []
    for r in regs:
        vtop = bincat[r].vtop
        value = bincat[r].value
        if cpu[r] & ~vtop != value & ~vtop:
            diff.append("- cpu   :  %s = %08x" % (r, cpu[r]))
            diff.append("+ bincat:  %s = %08x  %r" % (r,value,bincat[r]))
        else:
            same.append("  both  :  %s = %08x  %r" % (r, value,bincat[r]))
    assert not diff, "\n"+prettify_listing(listing)+"\n=========================\n"+"\n".join(diff)+"\n=========================\n"+"\n".join(same)
    diff = []
    for r,t in reg_taints.iteritems():
        if bincat[r].taint != t:
            diff.append("- expected :  %s = %08x ! %08x" % (r, cpu[r], t))
            diff.append("+ bincat   :  %s = %08x ! %08x  %r" % (r, bincat[r].value, bincat[r].taint, bincat[r]))
        else:
            same.append("  both     :  %s = %08x ! %08x  %r" % (r, bincat[r].value, bincat[r].taint, bincat[r]))
    assert not diff, "\n"+prettify_listing(listing)+"\n=========================\n"+"\n".join(diff)+"\n=========================\n"+"\n".join(same)
    

def test_assign(tmpdir):
    asm = """
    	mov eax,0xaaaa55aa
	mov ebx,0xcccccc55
    """
    compare(tmpdir, asm, ["eax","ebx"])


def test_rol(tmpdir):
    for i in range(65):
        asm = """
                mov cl,%i
                mov eax,0x12b4e78f
                rol eax,cl
        """ % i
        compare(tmpdir, asm, ["eax", "cf", "of"])

def test_ror(tmpdir):
    for i in range(65):
        asm = """
                mov cl,%i
                mov eax,0x12b4e78f
                ror eax,cl
        """ % i
        compare(tmpdir, asm, ["eax", "cf", "of"])


def test_rcl(tmpdir):
    for i in range(65):
        asm = """
                mov cl,%i
                mov eax,0x12b4e78f
                rcl eax,cl
        """ % i
        compare(tmpdir, "stc\n"+asm, ["eax", "cf", "of"])
        compare(tmpdir, "clc\n"+asm, ["eax", "cf", "of"])

def test_rcr(tmpdir):
    for i in range(65):
        asm = """
                mov cl,%i
                mov eax,0x12b4e78f
                rcr eax,cl
        """ % i
        compare(tmpdir, "stc\n"+asm, ["eax", "cf", "of"])
        compare(tmpdir, "clc\n"+asm, ["eax", "cf", "of"])

def test_rol_immediate(tmpdir):
    for i in range(65):
        asm = """
                mov eax,0x12b4e78f
                rol eax,%i
        """ % i
        compare(tmpdir, asm, ["eax", "cf", "of"])

def test_ror_immediate(tmpdir):
    for i in range(65):
        asm = """
                mov eax,0x12b4e78f
                ror eax,%i
        """ % i
        compare(tmpdir, asm, ["eax", "cf", "of"])


def test_rcl_immediate(tmpdir):
    for i in range(65):
        asm = """
                mov eax,0x12b4e78f
                rcl eax,%i
        """ % i
        compare(tmpdir, "stc\n"+asm, ["eax", "cf", "of"])
        compare(tmpdir, "clc\n"+asm, ["eax", "cf", "of"])

def test_rcr_immediate(tmpdir):
    for i in range(65):
        asm = """
                mov eax,0x12b4e78f
                rcr eax,%i
        """ % i
        compare(tmpdir, "stc\n"+asm, ["eax", "cf", "of"])
        compare(tmpdir, "clc\n"+asm, ["eax", "cf", "of"])



SOME_OPERANDS = [ 0, 1, 2, 7, 8, 0xf, 0x7f, 0x80, 0xff, 0x1234, 0x7fff, 0x8000, 0xffff, 0xffffffff, 0x80000000, 0x7fffffff ]
SOME_OPERANDS_COUPLES = list(itertools.product(SOME_OPERANDS, SOME_OPERANDS))

def test_add_reg32(tmpdir):
    asm = """
            mov eax, %#x
            add eax, %#x
          """
    for vals in SOME_OPERANDS_COUPLES:
        compare(tmpdir, asm % vals, ["eax", "of", "sf", "zf", "cf", "pf", "af"])

def test_sub_reg32(tmpdir):
    asm = """
            mov eax, %#x
            sub eax, %#x
          """
    for vals in SOME_OPERANDS_COUPLES:
        compare(tmpdir, asm % vals, ["eax", "of", "sf", "zf", "cf", "pf", "af"])

def test_cmp_reg32(tmpdir):
    asm = """
            mov eax, %#x
            cmp eax, %#x
          """
    for vals in SOME_OPERANDS_COUPLES:
        compare(tmpdir, asm % vals, ["eax", "of", "sf", "zf", "cf", "pf", "af"])

def test_cmovxx_reg32(tmpdir):
    asm = """
            pushf
            pop eax
            and eax, 0xfffff72a
            or eax, %#x
            push eax
            popf
            mov edx, 0xdeadbeef
            xor ebx,ebx
            cmov%s ebx, edx
            xor ecx,ecx
            cmov%s ecx, edx
          """
    for f in range(0x40): # all flags combinations
        flags = (f&0x20<<6) | (f&0x10<<3) | (f&8<<3) | (f&4<<2) | (f&2<<1) | (f&1)
        for cond1, cond2 in [("a","be"),("ae","b"),("c","nc"), ("e", "ne"),
                             ("g","le"), ("ge","l"), ("o", "no"), ("s", "ns"),
                             ("p", "np") ]:
            compare(tmpdir, asm % (flags, cond1, cond2), ["ebx", "ecx", "edx", "of", "sf", "zf", "cf", "pf", "af"])

def test_inc_reg32(tmpdir):
    asm = """
            mov eax, %#x
            inc eax
          """
    for vals in SOME_OPERANDS:
        compare(tmpdir, asm % vals, ["eax", "of", "sf", "zf", "cf", "pf", "af"])

def test_dec_reg32(tmpdir):
    asm = """
            mov eax, %#x
            dec eax
          """
    for vals in SOME_OPERANDS:
        compare(tmpdir, asm % vals, ["eax", "of", "sf", "zf", "cf", "pf", "af"])

def test_and_reg32(tmpdir):
    asm = """
            mov eax, %#x
            and eax, %#x
          """
    for vals in SOME_OPERANDS_COUPLES:
        compare(tmpdir, asm % vals, ["eax", "of", "sf", "zf", "cf", "pf"])

def test_or_reg32(tmpdir):
    asm = """
            mov eax, %#x
            or eax, %#x
          """
    for vals in SOME_OPERANDS_COUPLES:
        compare(tmpdir, asm % vals, ["eax", "of", "sf", "zf", "cf", "pf"])

def test_xor_reg32(tmpdir):
    asm = """
            mov eax, %#x
            xor eax, %#x
          """
    for vals in SOME_OPERANDS_COUPLES:
        compare(tmpdir, asm % vals, ["eax", "of", "sf", "zf", "cf", "pf"])

def test_not_reg32(tmpdir):
    asm = """
            mov eax, %#x
            not eax
          """
    for vals in SOME_OPERANDS:
        compare(tmpdir, asm % vals, ["eax"])

def test_test_reg32(tmpdir):
    asm = """
            mov eax, %#x
            test eax, %#x
          """
    for vals in SOME_OPERANDS_COUPLES:
        compare(tmpdir, asm % vals, ["eax", "sf", "zf", "pf"])

def test_mul_reg32(tmpdir):
    asm = """
            mov eax, %#x
            mov ebx, %#x
            mul ebx
          """
    for vals in SOME_OPERANDS_COUPLES:
        compare(tmpdir, asm % vals, ["eax", "edx", "of", "cf"])

def test_mul_taint(tmpdir):
    asm = """
            mov eax, %#x  ; @override reg[eax],%#x 
            mov ebx, %#x  ; @override reg[ebx],%#x
            mul ebx
          """

    compare(tmpdir, asm % (1,0xff, 0x10001, 0),["eax", "ebx","edx"],
            reg_taints = dict(eax=0xff00ff, edx=0))
    

def test_imul_reg32(tmpdir):
    asm = """
            mov eax, %#x
            mov ebx, %#x
            imul ebx
          """
    for vals in SOME_OPERANDS_COUPLES:
        compare(tmpdir, asm % vals, ["eax", "edx", "of", "cf"])

def test_shl_reg32(tmpdir):
    asm = """
            mov cl, %i
            mov eax, 0x12b4e78f
            shl eax, cl
          """
    for i in range(65):
        compare(tmpdir, asm % i, ["eax", "of", "cf"])

def test_shr_reg32(tmpdir):
    asm = """
            mov cl, %i
            mov eax, 0x12b4e78f
            shr eax, cl
          """
    for i in range(65):
        compare(tmpdir, asm % i, ["eax", "of", "cf"])

def test_sal_reg32(tmpdir):
    asm = """
            mov cl, %i
            mov eax, 0x12b4e78f
            sal eax, cl
          """
    for i in range(65):
        compare(tmpdir, asm % i, ["eax", "of", "cf"])

def test_sar_reg32(tmpdir):
    asm = """
            mov cl, %i
            mov eax, 0x12b4e78f
            sar eax, cl
          """
    for i in range(65):
        compare(tmpdir, asm % i, ["eax", "of", "cf"])

def test_shld_reg32(tmpdir):
    asm = """
            mov eax, 0x12b4e78f
            mov ebx, 0xa5486204
            mov cl, %i
            shld eax, ebx, cl
          """
    for i in range(4,65):
        compare(tmpdir, asm % i, ["eax", "ebx", "of", "cf"])

def test_shrd_reg32(tmpdir):
    asm = """
            mov eax, 0x12b4e78f
            mov ebx, 0xa5486204
            mov cl, %i
            shrd eax, ebx, cl
          """
    for i in range(4,65):
        compare(tmpdir, asm % i, ["eax", "ebx", "of", "cf"])

def test_movzx(tmpdir):
    asm = """
            mov eax, %i
            movzx bx, al
            movzx ecx, al
            movzx edx, ax
          """
    for val in [0, 1, 2, 0x7f, 0x7f, 0x80, 0x81, 0xff, 0x100, 0x101, 0x7fff, 0x8000, 0xffff ]:
        compare(tmpdir, asm % val, ["eax", "ebx", "ecx", "edx"])

def test_movsx(tmpdir):
    asm = """
            mov eax, %i
            movsx bx, al
            movsx ecx, al
            movsx edx, ax
          """
    for val in [0, 1, 2, 0x7f, 0x7f, 0x80, 0x81, 0xff, 0x100, 0x101, 0x7fff, 0x8000, 0xffff ]:
        compare(tmpdir, asm % val, ["eax", "ebx", "ecx", "edx"])

def test_repne_scasb(tmpdir):
    asm = """
            push 0x00006A69
            push 0x68676665
            push 0x64636261
            mov edi, esp
            xor al,al
            mov ecx, 0xffffffff
            cld
            repne scasb
            pushf
            sub edi, esp
            mov edx, ecx
            not edx
            popf
         """
    compare(tmpdir, asm, ["edi", "ecx", "edx", "zf", "cf", "of", "pf", "af", "sf"])


def test_repne_scasb_unknown_memory(tmpdir):
    asm = """
            mov edi, esp
            xor al,al
            mov ecx, 0xffffffff
            cld
            repne scasb
            pushf
            sub edi, esp
            mov edx, ecx
            not edx
            popf
         """
    compare(tmpdir, asm, ["edi", "ecx", "edx", "zf", "cf", "of", "pf", "af", "sf"])


def test_loop(tmpdir):
    asm = """
            mov ecx, 0x40
            mov eax, 0
         loop:
            inc eax
            loop loop
          """
    compare(tmpdir, asm, ["eax", "ecx", "zf", "cf", "of", "pf", "af", "sf"])


def test_cond_jump_jne(tmpdir):
    asm = """
            mov ecx, %i
            mov eax, 0
         loop:
            inc eax
            dec ecx
            cmp ecx,0
            jne loop
          """
    for i in range(1, 20):
        compare(tmpdir, asm % i, ["eax", "ecx", "zf", "cf", "of", "pf", "af", "sf"])

