import subprocess
import os
import sys
import inspect
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
        
        self.prgm = cfa.CFA.from_filenames(str(inif), str(outf), str(logf))
        self.last_state = getLastState(self.prgm)
        
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
                       + "\n".join("reg[%s]=%#x" % (regname, val)
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
        rec = False
        for l in open(self.result.logf):
            if "--- end of printf" in l:
                rec = False
            if rec:
                s.append(l[:-1])
            if "printf output" in l:
                rec = True
        return "".join(s)

class Arch:
    ALL_REGS = []
    def __init__(self, ini_in_file=None):
        self.ini_in_file  = ini_in_file

    def assemble(self, tmpdir, asm):
        raise NotImplemented
    def cpu_run(self, tmpdir, opcodesfname):
        raise NotImplemented
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

    def bincat_run(self, tmpdir, filename, values={}, directives={}):
        initfile = InitFile(self.ini_in_file, values, directives)
        initfile["filepath"] = filename
        bc = Bincat(tmpdir, initfile)

    def compare(self, tmpdir, asm, regs=None, reg_taints={}, top_allowed={}):
        if regs is None:
            regs = self.ALL_REGS

        bctest = self.make_bc_test(tmpdir, asm)
        testname = inspect.stack()[1][3]
        hline="\n=========================\n"
        try:
            bctest.run()
        except Exception,e:  # hack to add test name in the exception
            raise type(e),type(e)("%s: %s" % (testname,str(e))), sys.exc_info()[2]
        bincat = { reg : getReg(bctest.result.last_state, reg) for reg in self.ALL_REGS}
        try:
            cpu = self.cpu_run(tmpdir, bctest.filename)
        except subprocess.CalledProcessError,e:
            pytest.fail("%s: %s\n%s"%(testname,e,asm))

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
    
    
    def cpu_run(self, tmpdir, opcodesfname):
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
    
    
    def prettify_listing(self, asm):
        s = []
        for l in asm.splitlines():
            l = l.strip()
            if "BITS 32" in l or len(l.split()) <= 1:
                continue
            if l:
                s.append("\t"+l)
        return "\n".join(s)
    

