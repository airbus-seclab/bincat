import subprocess
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


def cpu_run(tmpdir, opcodesfname):
    out = subprocess.check_output(["./eggloader_x86",opcodesfname])
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
        open("x86_isn.ini.in").read().format(
            code_length = len(opcodes),
            filepath = opcodesfname,
            overrides = "\n".join("%#010x=%s" % (addr, val) for addr,val in directives["override"].iteritems())
        )
    )

    try:
        prgm = cfa.CFA.from_filenames(str(initf), str(outf), str(logf))
    except Exception,e:
        return e, listing, opcodesfname

    last_state = getLastState(prgm)
    
    return { reg : getReg(last_state, reg) for reg in ALL_REGS}, listing, opcodesfname


def compare(tmpdir, asm, regs=ALL_REGS, reg_taints={}, top_allowed={}):
    bincat,listing, opcodesfname = bincat_run(tmpdir, asm)
    try:
        cpu = cpu_run(tmpdir, opcodesfname)
    except subprocess.CalledProcessError,e:
        pytest.fail("%s\n%s"%(e,asm))
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
        allow_top = top_allowed.get(r,0)
        if vtop & ~allow_top:
            diff.append("+ top allowed:  %s = %08x ? %08x" % (r,cpu[r], allow_top))
            diff.append("+ bincat     :  %s = %08x ? %08x  %r" % (r,value,vtop,bincat[r]))
    assert not diff, "\n"+prettify_listing(listing)+"\n=========================\n"+"\n".join(diff)+"\n=========================\n"+"\n".join(same)
    diff = []
    for r,t in reg_taints.iteritems():
        if bincat[r].taint != t:
            diff.append("- expected :  %s = %08x ! %08x" % (r, cpu[r], t))
            diff.append("+ bincat   :  %s = %08x ! %08x  %r" % (r, bincat[r].value, bincat[r].taint, bincat[r]))
        else:
            same.append("  both     :  %s = %08x ! %08x  %r" % (r, bincat[r].value, bincat[r].taint, bincat[r]))
    assert not diff, "\n"+prettify_listing(listing)+"\n=========================\n"+"\n".join(diff)+"\n=========================\n"+"\n".join(same)

