import subprocess
import os
import inspect
import pytest
import conftest
from collections import defaultdict
from pybincat import cfa


def counter(fmt="%i", i=0):
    while True:
        yield fmt % i
        i += 1


GCC_DIR = counter("gcc-%i")


def getReg(my_node, name):
    v = cfa.Value('reg', name, cfa.reg_len(name))
    # hardcoded first unrel
    try:
        return my_node.unrels["0"][v][0]
    except KeyError:
        return my_node.unrels[list(my_node.unrels.keys())[0]][v][0]
        


def getLastNode(prgm, expect_tree=True):
    curNode = prgm['0']
    while True:
        nextNodes = prgm.next_nodes(curNode.node_id)
        if len(nextNodes) == 0:
            return curNode
        if not expect_tree:
            assert len(nextNodes) == 1, \
                ("expected exactly 1 destination node after running this "
                 "instruction (node: %s)" % curNode.node_id)
        curNode = nextNodes[0]


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
        self.last_node = getLastNode(self.cfa)

    def last_reg(self, regname):
        return getReg(self.last_node, regname)


class InitFile:
    def __init__(self, fname, values={}, directives={}):
        self.template = open(fname).read()
        self.values = defaultdict(lambda: "")
        self["entrypoint"] = 0
        self.values.update(values)
        self.set_directives(directives)
        self.program_entries = []
        self.analyzer_entries = []
        self.mem = {}
        self.reg = {}
        self.conf_edits = []

    def __setitem__(self, attr, val):
        self.values[attr] = val

    def __getitem__(self, attr):
        return self.values[attr]

    def __str__(self):
        v = self.values.copy()
        if "code_length" not in v:
            fstat = os.stat(v["filepath"])
            v["code_length"] = fstat.st_size
        v["regmem"] = ("\n".join("mem[%#x]=|%s|" % (addr, val.encode('utf-8').hex())
                                 for (addr, val) in self.mem.items())
                       + "\n".join("reg[%s]=%s" % (regname, val)
                                 for (regname, val) in self.reg.items())
                       )
        v["analyzer_section"] = "\n".join(self.analyzer_entries)
        v["program_section"] = "\n".join(self.program_entries)
        conf = self.template.format(**v)
        print(self.conf_edits)
        for before, after in self.conf_edits:
            conf = conf.replace(before, after)
        return conf

    def set_directives(self, directives):
        overrides = directives.get("overrides", {})
        self["overrides"] = "\n".join(
            "%#010x=%s" % (addr, val) for addr, val in overrides.items())

    def set_mem(self, addr, val: str):
        self.mem[addr] = val

    def set_reg(self, regname, val):
        self.reg[regname] = val

    def add_program_entry(self, entry):
        self.program_entries.append(entry)

    def add_analyzer_entry(self, entry):
        self.analyzer_entries.append(entry)

    def add_conf_replace(self, before, after):
        self.conf_edits.append((before, after))


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


def val2str(l, val, top=None, taint=None, ttop=None):
    print(l,val)
    fmt = "%%0%ix" % l
    s = fmt % val
    if top:
        s += (" ? "+fmt) % top
    if taint or ttop:
        s += (" ! "+fmt) % taint
        if ttop:
            s += ("? "+fmt) % ttop
    return s


class Arch:
    ALL_REGS = []
    QEMU = []

    def __init__(self, ini_in_file=None):
        self.ini_in_file = ini_in_file

    def extract_flags(self, regs):
        pass

    def prettify_listing(self, asm):
        return asm

    def extract_directives_from_asm(self, asm):
        d = defaultdict(dict)
        for l in asm.splitlines():
            if "@override" in l:
                sl = l.split()
                addr = int(sl[1], 16)
                val = sl[sl.index("@override")+1]
                d["override"][addr] = val
        return d

    def make_bc_test(self, tmpdir, asm):
        return BCTest(self, tmpdir, asm)

    def run_bc_test(self, bctest, testname):
        try:
            bctest.run()
        except Exception as e:  # hack to add test name in the exception
            pytest.fail("%s: %r\n%s" % (testname, e, bctest.listing))
        return {reg: getReg(bctest.result.last_node, reg) for reg in self.ALL_REGS}


    def check(self, tmpdir, asm, regs, bctest=None):
        testname = inspect.stack()[1][3]
        hline = "\n=========================\n"

        if bctest is None:
            bctest = self.make_bc_test(tmpdir, asm)
        bincat = self.run_bc_test(bctest, testname)

        diff = []
        same = []
        diff_summary = []
        for r, v in regs.items():
            if type(v) is tuple:
                v = list(v)
            else:
                v = [v]
            v += [0, 0, 0]
            target_value, target_vtop, target_taint, target_ttop = v[:4]
            target_str = val2str(reg_len(r), target_value, target_vtop, target_taint, target_ttop)
            value = bincat[r].value
            vtop = bincat[r].vtop
            taint = bincat[r].taint
            ttop = bincat[r].ttop
            if (value != target_value or vtop != target_vtop
                    or taint != target_taint or ttop != target_ttop):
                diff.append("- target:  %s = %s" %
                            (r, target_str))
                diff.append("+ bincat:  %s = %s  %r" %
                            (r, val2str(reg_len(r), value, vtop, taint, ttop), bincat[r]))
                diff_summary.append(r)
            else:
                same.append("  both  :  %s = %s  %r" %
                            (r, target_str, bincat[r]))
        assert not diff, ("%s: (%s)" % (testname, ", ".join(diff_summary))
                          + hline
                          + bctest.listing
                          + hline
                          + "\n".join(diff)
                          + hline
                          + "\n".join(same))

    def bf2mask(self, bitfield):
        if not bitfield:
            return -1
        mask = 0
        for s in bitfield:
            if "-" in s:
                start, stop = s.split("-")
            else:
                start = stop = s
            start = int(start)
            stop = int(stop)
            for b in range(start, stop+1):
                mask |= (1 << b)
        return mask

    def show_cpu(self, tmpdir, asm, regs=None):
        testname = inspect.stack()[1][3]
        hline = "\n=========================\n"
        if regs is None:
            regs = self.ALL_REGS
        bctest = self.make_bc_test(tmpdir, asm)
        try:
            cpu = self.cpu_run(tmpdir, bctest.filename)
        except subprocess.CalledProcessError as e:
            pytest.fail("%s: %s\n%s" % (testname, e, bctest.listing))

        print(hline)
        print(bctest.listing)
        print()
        for reg in regs:
            rl = reg_len(reg)
            regspec = reg.split(":")
            reg = regspec[0]
            bitfield = regspec[1:]
            print(f"{reg:6} = {cpu[reg]:0{rl}x}")

    def compare(self, tmpdir, asm, regs=None, reg_taints={}, top_allowed={}):
        testname = inspect.stack()[1][3]
        hline = "\n=========================\n"
        if regs is None:
            regs = self.ALL_REGS

        bctest = self.make_bc_test(tmpdir, asm)
        bincat = self.run_bc_test(bctest, testname)

        try:
            cpu = self.cpu_run(tmpdir, bctest.filename)
        except subprocess.CalledProcessError as e:
            pytest.fail("%s: %s\n%s" % (testname, e, bctest.listing))

        diff = []
        same = []
        diff_summary = []
        for r in regs:
            regspec = r.split(":")
            r = regspec[0]
            rl = (cfa.reg_len(r)+3)//4
            bitfield = regspec[1:]
            mask = self.bf2mask(bitfield)
            maskstring = "" if mask == -1 else f" (mask={mask:0{rl}x})"
            vtop = bincat[r].vtop
            value = bincat[r].value
            if cpu[r] & ~vtop & mask != value & ~vtop & mask:
                diff.append(f"- cpu   :  {r} = {cpu[r]:0{rl}x}")
                diff.append(f"+ bincat:  {r} = {value:0{rl}x}  {bincat[r]}")
                diff_summary.append(r)
            else:
                same.append(f"  both  :  {r} = {value:0{rl}x}  {bincat[r]}{maskstring}")
            allow_top = top_allowed.get(r, 0)
            if vtop & ~allow_top & mask:
                diff.append(f"+ top allowed:  {r} = {cpu[r]:0{rl}x} ? {allow_top:0{rl}x}")
                diff.append(f"+ bincat     :  {r} = {value:0{rl}x} ? {vtop:0{rl}x}  {bincat[r]}")
                diff_summary.append("%s(top)" % r)
        assert not diff, ("%s: (%s)" % (testname, ", ".join(diff_summary))
                          + hline
                          + bctest.listing
                          + hline
                          + "\n".join(diff)
                          + hline
                          + "\n".join(same))
        diff = []
        diff_summary = []
        for r, t in reg_taints.items():
            rl = (cfa.reg_len(r)+3)//4
            if bincat[r].taint != t:
                diff.append(f"- expected :  {r} = {cpu[r]:0{rl}x} ! {t:0{rl}x}")
                diff.append(f"+ bincat   :  {r} = {bincat[r].value:0{rl}x} ! {bincat[r].taint:0{rl}x}  {taint, bincat[r]}")
                diff_summary.append(r)
            else:
                same.append(f"  both     :  {r} = {bincat[r].value:0{rl}x} ! {bincat[r].taint:0{rl}x}  {taint, bincat[r]}")
        assert not diff, ("%s: (%s)" % (testname, ", ".join(diff_summary))
                          + hline
                          + "\n".join(diff)+"\n=========================\n"+"\n".join(same))

    def assemble(self, tmpdir, asm):
        d = tmpdir.mkdir(next(self.AS_TMP_DIR))
        inf = d.join("asm.S")
        obj = d.join("asm.o")
        outf = d.join("opcodes")
        inf.write(".text\n.globl _start\n_start:\n" + asm)
        subprocess.check_call(self.AS + ["-o", str(obj), str(inf)])
        subprocess.check_call(self.OBJCOPY + ["-O", "binary", str(obj), str(outf)])
        lst = subprocess.check_output(self.OBJDUMP + ["-b", "binary", "-D",  str(outf)]).decode("ascii", "replace")
        s = [l for l in lst.splitlines() if l.startswith(" ")]
        listing = "\n".join(s)
        opcodes = open(str(outf),"rb").read()
        return listing, str(outf), opcodes
    def cpu_run(self, tmpdir, opcodesfname):
        eggloader = os.path.join(os.path.dirname(os.path.realpath(__file__)), self.EGGLOADER)
        cmd = [eggloader, opcodesfname]
        if self.QEMU:
            cmd = self.QEMU + cmd
        out = subprocess.check_output(cmd)
        regs = {reg.decode("ascii"): int(val, 16) for reg, val in
                (l.strip().split(b"=") for l in out.splitlines())}
        self.extract_flags(regs)
        return regs


##      ___   __
## __ _( _ ) / /
## \ \ / _ \/ _ \
## /_\_\___/\___/
##
## X86

class X86(Arch):
    NASM_TMP_DIR = counter("nasm-%i")
    ALL_FLAGS = ["cf", "pf", "af", "zf", "sf", "df", "of"]
    ALL_REGS = ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"] + ALL_FLAGS
    EGGLOADER = 'eggloader_x86'

    def assemble(self, tmpdir, asm):
        d = tmpdir.mkdir(next(self.NASM_TMP_DIR))
        inf = d.join("asm.S")
        outf = d.join("opcodes")
        inf.write("BITS 32\n"+asm)
        listing = subprocess.check_output(["nasm", "-l", "/dev/stdout", "-o", str(outf), str(inf)]).decode("ascii", "replace")
        opcodes = open(str(outf), "rb").read()
        return listing, str(outf), opcodes

    def extract_flags(self, regs):
        flags = regs.pop("eflags")
        regs["cf"] = flags & 1
        regs["pf"] = (flags >> 2) & 1
        regs["af"] = (flags >> 4) & 1
        regs["zf"] = (flags >> 6) & 1
        regs["sf"] = (flags >> 7) & 1
        regs["df"] = (flags >> 10) & 1
        regs["of"] = (flags >> 11) & 1

    def prettify_listing(self, asm):
        s = []
        for l in asm.splitlines():
            l = l.strip()
            if "BITS 32" in l or len(l.split()) <= 1:
                continue
            if l:
                s.append("\t"+l)
        return "\n".join(s)

##       __ _ _
## __ __/ /| | |
## \ \ / _ \_  _|
## /_\_\___/ |_|
##
## X64

class X64(Arch):
    NASM_TMP_DIR = counter("nasm-%i")
    ALL_FLAGS = ["cf", "pf", "af", "zf", "sf", "df", "of"]
    ALL_REGS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp"] + [ "r%d" % i for i in range(8,16) ] + ALL_FLAGS
    EGGLOADER = 'eggloader_x64'

    def assemble(self, tmpdir, asm):
        d = tmpdir.mkdir(next(self.NASM_TMP_DIR))
        inf = d.join("asm.S")
        outf = d.join("opcodes")
        inf.write("BITS 64\n"+asm)
        listing = subprocess.check_output(["nasm", "-l", "/dev/stdout", "-o", str(outf), str(inf)]).decode("ascii", "replace")
        opcodes = open(str(outf), "rb").read()
        return listing, str(outf), opcodes

    def extract_flags(self, regs):
        flags = regs.pop("eflags")
        regs["cf"] = flags & 1
        regs["pf"] = (flags >> 2) & 1
        regs["af"] = (flags >> 4) & 1
        regs["zf"] = (flags >> 6) & 1
        regs["sf"] = (flags >> 7) & 1
        regs["df"] = (flags >> 10) & 1
        regs["of"] = (flags >> 11) & 1

    def prettify_listing(self, asm):
        s = []
        for l in asm.splitlines():
            l = l.strip()
            if "BITS 64" in l or len(l.split()) <= 1:
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
    ALL_REGS = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10",
                "r11", "r12", "sp", "lr", "pc", "n", "z", "c", "v"]
    AS_TMP_DIR = counter("arm-as-%i")
    AS = ["arm-linux-gnueabi-as"]
    OBJCOPY = ["arm-linux-gnueabi-objcopy"]
    OBJDUMP = ["arm-linux-gnueabi-objdump", "-m", "arm"]
    EGGLOADER = "eggloader_armv7"
    QEMU = ["qemu-arm"]

    def extract_flags(self, regs):
        cpsr = regs.pop("cpsr")
        regs["n"] = cpsr >> 31
        regs["z"] = (cpsr >> 30) & 1
        regs["c"] = (cpsr >> 29) & 1
        regs["v"] = (cpsr >> 28) & 1


class Thumb(ARM):
    OBJDUMP = ["arm-linux-gnueabi-objdump", "-m", "arm", "--disassembler-options=force-thumb"]
    EGGLOADER = "eggloader_armv7thumb"

    def assemble(self, tmpdir, asm):
        asm = """
           .code 16
           .thumb_func
        """ + asm
        return ARM.assemble(self, tmpdir, asm)

class ThumbU(Thumb):
    def assemble(self, tmpdir, asm):
        asm = """
           .code 16
           .syntax unified
           .thumb_func
        """ + asm
        return ARM.assemble(self, tmpdir, asm)

class AARCH64(ARM):
    ALL_REGS = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
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
    QEMU = ["qemu-aarch64"]

    def extract_flags(self, regs):
        nzcv = regs.pop("nzcv")
        regs["n"] = nzcv >> 31
        regs["z"] = (nzcv >> 30) & 1
        regs["c"] = (nzcv >> 29) & 1
        regs["v"] = (nzcv >> 28) & 1

##  ___                    ___  ___
## | _ \_____ __ _____ _ _| _ \/ __|
## |  _/ _ \ V  V / -_) '_|  _/ (__
## |_| \___/\_/\_/\___|_| |_|  \___|
##
## PowerPC

class PowerPC(Arch):
    ALL_REGS = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9",
                "r10", "r11", "r12", "r13", "r14", "r15", "r16", "r17", "r18", "r19",
                "r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27", "r28", "r29",
                "r30", "r31", "lr", "ctr", "cr", "so", "ov", "ca", "tbc"]
    AS_TMP_DIR = counter("powerpc-as-%i")
    AS = ["powerpc-linux-gnu-as", "-many", "-mpower9", "-mbig"]
    OBJCOPY = ["powerpc-linux-gnu-objcopy"]
    OBJDUMP = ["powerpc-linux-gnu-objdump", "-mpowerpc", "-EB"]
    EGGLOADER = "eggloader_powerpc"
    QEMU = ["qemu-ppc", "-cpu", "440epx"]

    def extract_flags(self, regs):
        xer = regs.pop("xer")
        regs["so"] = (xer >> 31) & 1
        regs["ov"] = (xer >> 30) & 1
        regs["ca"] = (xer >> 29) & 1
        regs["tbc"] = (xer >> 0) & 0x7f

##  ___                    ___  ___    __ _ _
## | _ \_____ __ _____ _ _| _ \/ __|  / /| | |
## |  _/ _ \ V  V / -_) '_|  _/ (__  / _ \_  _|
## |_| \___/\_/\_/\___|_| |_|  \___| \___/ |_|
## PowerPC 64

class PowerPC64(Arch):
    ALL_REGS = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9",
                "r10", "r11", "r12", "r13", "r14", "r15", "r16", "r17", "r18", "r19",
                "r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27", "r28", "r29",
                "r30", "r31", "lr", "ctr", "cr", "so", "ov", "ca", "tbc"]
    AS_TMP_DIR = counter("powerpc64-as-%i")
    AS = ["powerpc64-linux-gnu-as", "-many", "-mpower9", "-mbig"]
    OBJCOPY = ["powerpc64-linux-gnu-objcopy"]
    OBJDUMP = ["powerpc64-linux-gnu-objdump", "-mpowerpc", "-M64", "-EB"]
    EGGLOADER = "eggloader_powerpc64"
    QEMU = ["qemu-ppc64"]

    def extract_flags(self, regs):
        xer = regs.pop("xer")
        regs["so"] = (xer >> 31) & 1
        regs["ov"] = (xer >> 30) & 1
        regs["ca"] = (xer >> 29) & 1
        regs["tbc"] = (xer >> 0) & 0x7f


##  ___ ___ ___  ___  __   __   __ _ _
## | _ \_ _/ __|/ __|_\ \ / /  / /| | |
## |   /| |\__ \ (_|___\ V /  / _ \_  _|
## |_|_\___|___/\___|   \_/   \___/ |_|
##
## RISC-V 64

class RISCV64(Arch):
    ALL_REGS = [ "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
                 "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18",
                 "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
                 "x28", "x29", "x30", "x31"]
    AS_TMP_DIR = counter("riscv64-as-%i")
    AS = ["riscv64-linux-gnu-as"]
    OBJCOPY = ["riscv64-linux-gnu-objcopy"]
    OBJDUMP = ["riscv64-linux-gnu-objdump", "-mriscv:rv64", "--disassembler-options=no-aliases,numeric"]
    EGGLOADER = "eggloader_riscv64"
    QEMU = ["qemu-riscv64"]

    def extract_flags(self, regs):
        pass
