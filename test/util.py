import subprocess
import os
import sys
import inspect
import pytest
from collections import defaultdict
from pybincat import cfa

def counter(fmt="%i", i=0):
    while True:
        yield fmt % i
        i += 1

GCC_DIR = counter("gcc-%i")


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

class Bincat:
    def __init__(self, tmpdir, initfile):
        outf = tmpdir.join('end.ini')
        logf = tmpdir.join('log.txt')
        inif = tmpdir.join('init.ini')

        inif.write(initfile)
        
        self.inif = str(inif)
        self.logf = str(logf)
        self.outf = str(outf)
        
        self.cfa = cfa.CFA.from_filenames(str(inif), str(outf), str(logf))
        self.last_state = getLastState(self.cfa)
        
    def last_reg(self, regname):
        return getReg(self.last_state, regname)

class InitFile:
    def __init__(self, fname, values={}, directives={}):
        self.template = open(fname).read()
        self.values = defaultdict(lambda : "")
        self["entrypoint"] = 0
        self.values.update(values)
        self.set_directives(directives)
        self.mem={}
        self.reg={}
    def __setitem__(self, attr, val):
        self.values[attr] = val
    def __getitem__(self, attr):
        return self.values[attr]
    def update(self, newvalues):
        self.val.update(newvalues)
    def __str__(self):
        v = self.values.copy()
        if "code_length" not in v:
            fstat = os.stat(v["filepath"])
            v["code_length"] = fstat.st_size
        v["regmem"] = ("\n".join("mem[%#x]=|%s|" % (addr, val.encode("hex"))
                                 for (addr,val) in self.mem.iteritems())
                       + "\n".join("reg[%s]=%s" % (regname, val)
                                 for (regname,val) in self.reg.iteritems())
                       )
        return self.template.format(**v)
    def set_directives(self, directives):
        overrides = directives.get("overrides",{})
        self["overrides"] = "\n".join("%#010x=%s" % (addr, val) for addr,val in overrides.iteritems())
    def set_mem(self, addr, val):
        self.mem[addr] = val
    def set_reg(self, regname, val):
        self.reg[regname] = val

class BCTest:
    def __init__(self, arch, tmpdir, asm):
        self.arch = arch
        self.tmpdir = tmpdir
        self.rawlisting, self.filename, self.opcodes = self.arch.assemble(tmpdir, asm)
        self.listing = self.arch.prettify_listing(self.rawlisting)
        directives = self.arch.extract_directives_from_asm(asm)
        self.initfile = InitFile(self.arch.ini_in_file,
                                 dict(filepath=self.filename),
                                 directives)
        self.result = None
    def run(self):
        self.result = Bincat(self.tmpdir, self.initfile)
    def get_logs(self):
        return open(self.result.logf).read()
    def get_stdout(self):
        s = []
        for l in open(self.result.logf):
            if l.startswith("[STDOUT] "):
                s.append(l[9:])
        return "".join(s)

class Arch:
    ALL_REGS = []
    def __init__(self, ini_in_file=None):
        self.ini_in_file  = ini_in_file

    def assemble(self, tmpdir, asm):
        raise NotImplemented
    def cpu_run(self, tmpdir, opcodesfname):
        raise NotImplemented
    def extract_flags(self, regs):
        pass
    def prettify_listing(self, asm):
        return asm
    def extract_directives_from_asm(self, asm):
        d = defaultdict(dict)
        for l in asm.splitlines():
            if "@override" in l:
                sl = l.split()
                addr = int(sl[1],16)
                val = sl[sl.index("@override")+1]
                d["override"][addr] = val
        return d

    def make_bc_test(self, tmpdir, asm):
        return BCTest(self, tmpdir, asm)

    def compare(self, tmpdir, asm, regs=None, reg_taints={}, top_allowed={}):
        if regs is None:
            regs = self.ALL_REGS

        bctest = self.make_bc_test(tmpdir, asm)
        testname = inspect.stack()[1][3]
        hline="\n=========================\n"
        try:
            bctest.run()
        except Exception,e:  # hack to add test name in the exception
            pytest.fail("%s: %r\n%s"%(testname,e,bctest.listing))
        bincat = { reg : getReg(bctest.result.last_state, reg) for reg in self.ALL_REGS}
        try:
            cpu = self.cpu_run(tmpdir, bctest.filename)
        except subprocess.CalledProcessError,e:
            pytest.fail("%s: %s\n%s"%(testname,e,bctest.listing))

        diff = []
        same = []
        diff_summary = []
        for r in regs:
            vtop = bincat[r].vtop
            value = bincat[r].value
            if cpu[r] & ~vtop != value & ~vtop:
                diff.append("- cpu   :  %s = %08x" % (r, cpu[r]))
                diff.append("+ bincat:  %s = %08x  %r" % (r,value,bincat[r]))
                diff_summary.append(r)
            else:
                same.append("  both  :  %s = %08x  %r" % (r, value,bincat[r]))
            allow_top = top_allowed.get(r,0)
            if vtop & ~allow_top:
                diff.append("+ top allowed:  %s = %08x ? %08x" % (r,cpu[r], allow_top))
                diff.append("+ bincat     :  %s = %08x ? %08x  %r" % (r,value,vtop,bincat[r]))
                diff_summary.append("%s(top)" % r)
        assert not diff, ("%s: (%s)" % (testname, ", ".join(diff_summary))
                          +hline
                          +bctest.listing
                          +hline
                          +"\n".join(diff)
                          +hline
                          +"\n".join(same))
        diff = []
        diff_summary = []
        for r,t in reg_taints.iteritems():
            if bincat[r].taint != t:
                diff.append("- expected :  %s = %08x ! %08x" % (r, cpu[r], t))
                diff.append("+ bincat   :  %s = %08x ! %08x  %r" % (r, bincat[r].value, bincat[r].taint, bincat[r]))
                diff_summary.append(r)
            else:
                same.append("  both     :  %s = %08x ! %08x  %r" % (r, bincat[r].value, bincat[r].taint, bincat[r]))
        assert not diff, ("%s: (%s)" % (testname, ", ".join(diff_summary))
                          +hline
                          +"\n".join(diff)+"\n=========================\n"+"\n".join(same))





##      ___   __ 
## __ _( _ ) / / 
## \ \ / _ \/ _ \
## /_\_\___/\___/
##
## X86



class X86(Arch):
    NASM_TMP_DIR = counter("nasm-%i")
    ALL_FLAGS = ["cf","pf", "af", "zf","sf","df","of"]
    ALL_REGS = ["eax","ebx","ecx","edx", "esi","edi","esp", "ebp"] + ALL_FLAGS

    def assemble(self, tmpdir, asm):
        d = tmpdir.mkdir(self.NASM_TMP_DIR.next())
        inf = d.join("asm.S")
        outf = d.join("opcodes")
        inf.write("BITS 32\n"+asm)
        listing = subprocess.check_output(["nasm", "-l", "/dev/stdout", "-o", str(outf), str(inf)])
        opcodes = open(str(outf)).read()
        return listing,str(outf),opcodes

    def extract_flags(self, regs):
        flags = regs.pop("eflags")
        regs["cf"] = flags & 1
        regs["pf"] = (flags >> 2) & 1
        regs["af"] = (flags >> 4) & 1
        regs["zf"] = (flags >> 6) & 1
        regs["sf"] = (flags >> 7) & 1
        regs["df"] = (flags >> 10) & 1
        regs["of"] = (flags >> 11) & 1

    def cpu_run(self, tmpdir, opcodesfname):
        eggloader = os.path.join(os.path.dirname(os.path.realpath(__file__)),'eggloader_x86')
        out = subprocess.check_output([eggloader, opcodesfname])
        regs = { reg: int(val,16) for reg, val in
                (l.strip().split("=") for l in out.splitlines()) }
        self.extract_flags(regs)
        return regs

    def prettify_listing(self, asm):
        s = []
        for l in asm.splitlines():
            l = l.strip()
            if "BITS 32" in l or len(l.split()) <= 1:
                continue
            if l:
                s.append("\t"+l)
        return "\n".join(s)
    

##    _   ___ __  __ 
##   /_\ | _ \  \/  |
##  / _ \|   / |\/| |
## /_/ \_\_|_\_|  |_|
##
## ARM

class ARM(Arch):
    ALL_REGS = [ "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10",
                 "r11", "r12", "sp", "lr", "pc", "n", "z", "c", "v"]
    AS_TMP_DIR = counter("arm-as-%i")
    AS = ["arm-linux-gnueabi-as"]
    OBJCOPY = ["arm-linux-gnueabi-objcopy"]
    OBJDUMP = ["arm-linux-gnueabi-objdump", "-m", "arm"]
    EGGLOADER = "eggloader_armv7"
    QEMU = "qemu-arm"
    def assemble(self, tmpdir, asm):
        d = tmpdir.mkdir(self.AS_TMP_DIR.next())
        inf = d.join("asm.S")
        obj = d.join("asm.o")
        outf = d.join("opcodes")
        inf.write(".text\n.globl _start\n_start:\n" + asm)
        subprocess.check_call(self.AS + ["-o", str(obj), str(inf)])
        subprocess.check_call(self.OBJCOPY + ["-O", "binary", str(obj), str(outf)])
        lst = subprocess.check_output(self.OBJDUMP + ["-b", "binary", "-D",  str(outf)])
        s = [l for l in lst.splitlines() if l.startswith(" ")]
        listing = "\n".join(s)
        opcodes = open(str(outf)).read()
        return listing, str(outf),opcodes

    def extract_flags(self, regs):
        cpsr = regs.pop("cpsr")
        regs["n"] = cpsr >> 31
        regs["z"] = (cpsr >> 30) & 1
        regs["c"] = (cpsr >> 29) & 1
        regs["v"] = (cpsr >> 28) & 1

    def cpu_run(self, tmpdir, opcodesfname):
        eggloader = os.path.join(os.path.dirname(os.path.realpath(__file__)), self.EGGLOADER)
        out = subprocess.check_output([self.QEMU, eggloader, opcodesfname])
        regs = { reg: int(val,16) for reg, val in
                (l.strip().split("=") for l in out.splitlines()) }
        self.extract_flags(regs)
        return regs

class Thumb(ARM):
    OBJDUMP = ["arm-linux-gnueabi-objdump", "-m", "arm", "--disassembler-options=force-thumb"]
    EGGLOADER = "eggloader_armv7thumb"
    def assemble(self, tmpdir, asm):
        asm = """
           .code 16
           .thumb_func
        """ + asm
        return ARM.assemble(self, tmpdir, asm)

class AARCH64(ARM):
    ALL_REGS = [ "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
                 "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20",
                 "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp", 
                 "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9", "q10",
                 "q11", "q12", "q13", "q14", "q15", "q16", "q17", "q18", "q19", "q20",
                 "q21", "q22", "q23", "q24", "q25", "q26", "q27", "q28", "q29", "q30", "q31", 
                 "pc", "n", "z", "c", "v"]
    AS = ["aarch64-linux-gnu-as"]
    OBJCOPY = ["aarch64-linux-gnu-objcopy"]
    OBJDUMP = ["aarch64-linux-gnu-objdump", "-m", "aarch64"]
    EGGLOADER = "eggloader_armv8"
    QEMU = "qemu-aarch64"


    def extract_flags(self, regs):
        nzcv = regs.pop("nzcv")
        regs["n"] = nzcv >> 31
        regs["z"] = (nzcv >> 30) & 1
        regs["c"] = (nzcv >> 29) & 1
        regs["v"] = (nzcv >> 28) & 1

