"""
    This file is part of BinCAT.
    Copyright 2014-2021 - Airbus

    BinCAT is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or (at your
    option) any later version.

    BinCAT is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with BinCAT.  If not, see <http://www.gnu.org/licenses/>.
"""

import ctypes
import collections
import functools
import glob
import os
import os.path
import sys
import re
from io import StringIO
try:
    import configparser as ConfigParser
except ImportError:
    import ConfigParser
import logging
import idaapi
import idautils
import ida_segment
import ida_kernwin
import idabincat.netnode
from builtins import bytes
from idabincat.plugin_options import PluginOptions
# Python 2/3 compat
if sys.version_info > (2, 8):
    long = int

# Logging
bc_log = logging.getLogger('bincat-cfg')
bc_log.setLevel(logging.INFO)

X64_GPR = ['rax', 'rcx', 'rdx', 'rbx', 'rbp', 'rsi', 'rdi', 'rsp']+["r%d" % d for d in range(8, 16)]
X86_GPR = ['eax', 'ecx', 'edx', 'ebx', 'ebp', 'esi', 'edi', 'esp']


# Needed because IDA doesn't store s_psize
class pesection_t(ctypes.Structure):
    _fields_ = [("s_name", ctypes.c_char * 8),
                ("s_vsize", ctypes.c_uint),
                ("s_vaddr", ctypes.c_uint),
                ("s_psize", ctypes.c_uint),
                ("s_scnptr", ctypes.c_int),
                ("s_relptr", ctypes.c_int),
                ("s_lnnoptr", ctypes.c_int),
                ("s_nreloc", ctypes.c_ushort),
                ("s_nlnno", ctypes.c_ushort),
                ("s_flags", ctypes.c_int)]

# For some reason, IDA stores the Elf64 hdr, even for 32 bits files...
class elf_ph_t(ctypes.Structure):
    _fields_ = [("p_type", ctypes.c_uint),
                ("p_flags", ctypes.c_uint),
                ("p_offset", ctypes.c_ulonglong),
                ("p_vaddr", ctypes.c_ulonglong),
                ("p_paddr", ctypes.c_ulonglong),
                ("p_filesz", ctypes.c_ulonglong),
                ("p_memsz", ctypes.c_ulonglong),
                ("p_align", ctypes.c_ulonglong)]


class ConfigHelpers(object):
    """
    Holds helpers, that transform data obtained from ida API.

    Used to generate default configuration.
    """
    ftypes = {idaapi.f_PE: "pe",
              idaapi.f_ELF: "elf",
              idaapi.f_MACHO: "macho"}

    @staticmethod
    def get_file_type():
        ida_db_info_structure = idaapi.get_inf_structure()
        f_type = ida_db_info_structure.filetype
        if f_type in ConfigHelpers.ftypes:
            return ConfigHelpers.ftypes[f_type]
        else:
            return "raw"

    # Helper function to get a filename as a Unicode string
    @staticmethod
    def string_decode(string):
        if idaapi.get_kernel_version()[0] == '7':
            # IDA 7 only has UTF-8 strings
            try:
                string_u = string.decode('UTF-8')
            except AttributeError:
                # Python 3
                string_u = string
        else:
            # IDA 6 uses the system locale
            # on Linux it's usually UTF-8 but we can't be sure
            # on Windows getfilesystemencoding returns "mbcs"
            # but it decodes cpXXXX correctly apparently
            string_u = string.decode(sys.getfilesystemencoding())
        return string_u

    @staticmethod
    def askfile(types, prompt):
        fname = ida_kernwin.ask_file(1, types, prompt)
        return ConfigHelpers.string_decode(fname)

    # Helper that returns an Unicode string with the file path
    @staticmethod
    def guess_file_path():
        input_file = idaapi.get_input_file_path()
        input_file = ConfigHelpers.string_decode(input_file)
        if not os.path.isfile(input_file):
            # get_input_file_path returns file path from IDB, which may not
            # exist locally if IDB has been moved (eg. send idb+binary to
            # another analyst)
            guessed_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
            guessed_path = guessed_path.replace('idb', 'exe')
            if os.path.isfile(guessed_path):
                return guessed_path
            guessed_path = guessed_path.replace('.exe', '')
            if os.path.isfile(guessed_path):
                return guessed_path
        return input_file

    @staticmethod
    def get_memory_model():
        ida_db_info_structure = idaapi.get_inf_structure()
        compiler_info = ida_db_info_structure.cc
        if compiler_info.cm & idaapi.C_PC_FLAT == idaapi.C_PC_FLAT:
            return "flat"
        else:
            return "segmented"

    @staticmethod
    def get_call_convention():
        ida_db_info_structure = idaapi.get_inf_structure()
        compiler_info = ida_db_info_structure.cc
        cc = {
            idaapi.CM_CC_INVALID: "invalid",
            idaapi.CM_CC_UNKNOWN: "unknown",
            idaapi.CM_CC_VOIDARG: "voidargs",
            idaapi.CM_CC_CDECL: "cdecl",
            idaapi.CM_CC_ELLIPSIS: "ellipsis",
            idaapi.CM_CC_STDCALL: "stdcall",
            idaapi.CM_CC_PASCAL: "pascal",
            idaapi.CM_CC_FASTCALL: "fastcall",
            idaapi.CM_CC_THISCALL: "thiscall",
            idaapi.CM_CC_MANUAL: "manual",
        }[compiler_info.cm & idaapi.CM_CC_MASK]
        # XXX
        if ConfigHelpers.get_arch() == "powerpc" and ida_db_info_structure.abiname == "sysv":
            return "svr"
        if ConfigHelpers.get_arch() == "x64":
            if ConfigHelpers.get_file_type() == 'elf':
                return "sysv"
            else:
                return "ms"
        if ConfigHelpers.get_arch().startswith('arm'):
            return "aapcs"
        elif cc not in ("stdcall", "cdecl", "fastcall"):
            return "stdcall"
        else:
            return cc

    @staticmethod
    def get_bitness(ea):
        seg = idaapi.getseg(ea)
        if not seg:
            seg = idaapi.getseg(next(idautils.Segments()))
        bitness = seg.bitness
        return {0: 16, 1: 32, 2: 64}[bitness]

    @staticmethod
    def get_endianness():
        ida_db_info_structure = idaapi.get_inf_structure()
        return "big" if ida_db_info_structure.is_be() else "little"


    @staticmethod
    def get_stack_width():
        ida_db_info_structure = idaapi.get_inf_structure()
        if ida_db_info_structure.is_64bit():
            return 8*8
        else:
            if ida_db_info_structure.is_32bit():
                return 4*8
            else:
                return 2*8

    @staticmethod
    def get_code_section(entrypoint):
        # in case we have more than one code section we apply the following:
        # heuristic entry point must be in the code section
        for n in range(idaapi.get_segm_qty()):
            seg = idaapi.getnseg(n)
            start_ea = seg.start_ea
            end_ea = seg.end_ea
            if seg.type == idaapi.SEG_CODE and start_ea <= entrypoint < end_ea:
                # TODO : check PE/ELF for **physical** (raw) section size
                return start_ea, end_ea
        bc_log.error("No code section has been found for entrypoint %#08X",
                     entrypoint)
        return -1, -1

    @staticmethod
    def get_segment_size(entrypoint):
        if ida_segment.getseg(entrypoint).use64():
            return 64
        else:
            return 32

    @staticmethod
    def get_sections():
        res = []
        if ConfigHelpers.get_file_type() == "pe":
            # IDA doesn't store the raw size of sections, we need to get the
            # headers...
            n = idaapi.netnode("$ PE header")
            imagebase = n.altval(idautils.peutils_t.PE_ALT_IMAGEBASE)
            i = 1
            while n.supval(i) is not None:
                raw = n.supval(i)
                sec = pesection_t.from_buffer_copy(raw)
                res.append([sec.s_name, imagebase+sec.s_vaddr, sec.s_vsize,
                            sec.s_scnptr, sec.s_psize])
                i += 1
            return res
        elif ConfigHelpers.get_file_type() == "elf":
            n = idaapi.netnode("$ elfnode")
            i = 0  # ELF PH start at 0
            while n.supval(i, 'p') is not None:
                raw = n.supval(i, 'p')  # program headers
                ph = elf_ph_t.from_buffer_copy(raw)
                if ph.p_type == 1:  # PT_LOAD
                    res.append(["ph%d" % i, ph.p_vaddr, ph.p_memsz,
                                ph.p_offset, ph.p_filesz])
                i += 1
            return res

        bc_log.warning("no Data section has been found")
        return []

    @staticmethod
    def add_imp_to_dict(imports, module, ea, name, ordinal):
        if not name:
            imports[ea] = (module, ordinal)
        else:
            # Remove @@GLIBC... suffix
            if "@@" in name:
                name = name.split('@@')[0]
            imports[ea] = (module, name)
        return True

    @staticmethod
    def get_imports():
        imports = {}
        nimps = idaapi.get_import_module_qty()
        for i in range(0, nimps):
            name = idaapi.get_import_module_name(i)
            imp_cb = functools.partial(ConfigHelpers.add_imp_to_dict,
                                       imports, name)
            idaapi.enum_import_names(i, imp_cb)
        return imports

    @staticmethod
    def register_size(arch, reg):
        if arch == 'x86':
            if reg in X86_GPR:
                return 32
            if reg in ['cf', 'pf', 'af', 'zf', 'sf', 'tf', 'if', 'of', 'nt',
                       'rf', 'vm', 'ac', 'vif', 'vip', 'id', 'df']:
                return 1
            if reg == 'iopl':
                return 3
        if arch == 'x64':
            if reg in X64_GPR:
                return 64
            if reg in ["xmm%d" % d for d in range(0, 16)]:
                return 128
            if reg in ['cf', 'pf', 'af', 'zf', 'sf', 'tf', 'if', 'of', 'nt',
                       'rf', 'vm', 'ac', 'vif', 'vip', 'id', 'df']:
                return 1
            if reg == 'iopl':
                return 3
        elif arch == 'armv7':
            if reg[0] == 'r' or reg in ['sp', 'lr', 'pc']:
                return 32
            if reg in ['n', 'z', 'c', 'v']:
                return 1
        elif arch == 'armv8':
            if reg[0] == 'x' or reg in ['xzr', 'sp']:
                return 64
            if reg[0] == 'q':
                return 128
            if reg in ['n', 'z', 'c', 'v']:
                return 1
        elif arch == 'powerpc':
            if reg in ['so', 'ov', 'ca']:
                return 1
            elif reg == 'tbc':
                return 7
            else:
                return 32
        return None

    @staticmethod
    def get_registers_with_state(arch):
        # returns an array of arrays
        # ["name", "value", "topmask", "taintmask"]
        regs = []
        if arch == "x86":
            for name in X86_GPR:
                regs.append([name, "0", "0xFFFFFFFF", ""])
            regs.append(["esp", "0xb8001000", "", ""])
            for name in ["cf", "pf", "af", "zf", "sf", "tf", "if", "of", "nt",
                         "rf", "vm", "ac", "vif", "vip", "id"]:
                regs.append([name, "0", "1", ""])
            regs.append(["df", "0", "", ""])
            regs.append(["iopl", "3", "", ""])
        if arch == "x64":
            for name in X64_GPR:
                regs.append([name, "0", "0xFFFFFFFFFFFFFFFF", ""])
            if name in ["xmm%d" % d for d in range(0, 16)]:
                regs.append([name, "0", "0x"+"F"*32, ""])
            regs.append(["rsp", "0xb8001000", "", ""])
            for name in ["cf", "pf", "af", "zf", "sf", "tf", "if", "of", "nt",
                         "rf", "vm", "ac", "vif", "vip", "id"]:
                regs.append([name, "0", "1", ""])
            regs.append(["df", "0", "", ""])
            regs.append(["iopl", "3", "", ""])
        elif arch == "armv7":
            for i in range(13):
                regs.append(["r%d" % i, "0", "0xFFFFFFFF", ""])
            regs.append(["sp", "0xb8001000", "", ""])
            regs.append(["lr", "0x0", "", ""])
            regs.append(["pc", "0x0", "", ""])
            regs.append(["n", "0", "1", ""])
            regs.append(["z", "0", "1", ""])
            regs.append(["c", "0", "1", ""])
            regs.append(["v", "0", "1", ""])
            regs.append(["t", "0", "", ""])
        elif arch == "armv8":
            for i in range(31):
                regs.append(["x%d" % i, "0", "0xFFFFFFFFFFFFFFFF", ""])
            regs.append(["sp", "0xb8001000", "", ""])
            for i in range(32):
                regs.append(
                    ["q%d" % i, "0", "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", ""])
            regs.append(["n", "0", "1", ""])
            regs.append(["z", "0", "1", ""])
            regs.append(["c", "0", "1", ""])
            regs.append(["v", "0", "1", ""])
            regs.append(["xzr", "0", "", ""])
        elif arch == "powerpc":
            for i in range(31):
                regs.append(["r%d" % i, "0", "0xFFFFFFFF", ""])
            for reg in ['lr', 'ctr', 'cr']:
                regs.append([reg, "0", "0xFFFFFFFF", ""])
            for reg in ['so', 'ov', 'ca']:
                regs.append([reg, "0", "1", ""])
            regs.append(["tbc", "0", "0x7F", ""])
        return regs

    @staticmethod
    def get_initial_mem(arch=None):
        return [["mem", "0xb8000000*8192", "|00|?0xFF"]]

    @staticmethod
    def get_arch():
        info = idaapi.get_inf_structure()
        procname = info.procName.lower()
        if procname == "metapc":
            if info.is_64bit():
                return "x64"
            else:
                return "x86"
        if procname == "ppc":
            return "powerpc"
        elif procname.startswith("arm"):
            if info.is_64bit():
                return "armv8"
            else:
                return "armv7"
        bc_log.error("Unknown architecture")
        return None


class InitialState(object):
    """
    Stores the initial state configuration:
        * registers
        * memory
    """
    def __init__(self, entrypoint=None, config=None):
        if config:
            arch = config.get('program', 'architecture')
            self.mem = []
            self.regs = []
            for k, v in config.items('state'):
                if k[0:3] == "reg":
                    self.regs.append(InitialState.reg_init_parse(k, v))
                else:
                    self.mem.append(InitialState.mem_init_parse(k, v))
        else:
            arch = ConfigHelpers.get_arch()
            self.regs = ConfigHelpers.get_registers_with_state(arch)
            self.mem = ConfigHelpers.get_initial_mem(arch)

    def set_regs(self, regs):
        self.regs = regs

    def set_mem(self, mem):
        self.mem = mem

    def add_mem(self, index, mem_entry):
        if index >= len(self.mem) or index < 0:
            self.mem.append(mem_entry)
        else:
            self.mem.insert(index, mem_entry)

    @staticmethod
    def mem_init_parse(mem_addr, mem_val):
        mem_addr_re = re.compile(r"(?P<region>[^[]+)\[(?P<address>[^\]]+)\]")
        m = mem_addr_re.match(mem_addr)
        return [m.group('region'), m.group('address'), mem_val]

    @staticmethod
    def reg_init_parse(reg_spec, reg_val):
        if reg_spec[0:3] != "reg":
            raise ValueError("Invalid reg spec, not starting with 'reg'")
        reg_re = re.compile(
            r"(?P<value>[^!?]+)?(\?(?P<top>[^!]+))?"
            "(!(?P<taint>[^#]*))?(?P<cmt>#.*)?")
        m = reg_re.match(reg_val)
        return [reg_spec[4:-1],
                m.group('value') or '',
                m.group('top') or '',
                m.group('taint') or '']

    @staticmethod
    def reg_to_strs(regspec):
        val_str = regspec[1]
        if regspec[2] != "":  # add top mask if needed
            val_str += "?"+regspec[2]
        if regspec[3] != "":  # add taint mask if needed
            val_str += "!"+regspec[3]
        return ["reg[%s]" % regspec[0], val_str]

    @staticmethod
    def mem_to_strs(memdef):
        return ["%s[%s]" % (memdef[0], memdef[1]), memdef[2]]

    def as_kv(self):
        res = []
        for regdef in self.regs:
            res.append(self.reg_to_strs(regdef))
        for memdef in self.mem:
            res.append(self.mem_to_strs(memdef))
        return res

    @staticmethod
    def get_default(entrypoint):
        state = InitialState(entrypoint)
        return state.as_kv()


class AnalyzerConfig(object):
    """
    Handles configuration files for the analyzer.
    """
    def __init__(self, config=None):
        self.version = "0.0"
        if config:
            self._config = config
            self.init_state = InitialState(config=config)
        else:
            self._config = ConfigParser.RawConfigParser()
            self.init_state = InitialState()
        self._config.optionxform = str
        # make sure all sections are created
        for section in ("analyzer", "program",
                        "sections", "state", "imports", "IDA"):
            if not self._config.has_section(section):
                self._config.add_section(section)

    def __copy__(self):
        return self.load_from_str(str(self))

    # Convenience access functions
    @property
    def analysis_ep(self):
        try:
            return self._config.get('analyzer', 'analysis_ep')
        except ConfigParser.NoOptionError:
            return ""

    @property
    def stop_address(self):
        try:
            return self._config.get('analyzer', 'cut')
        except ConfigParser.NoOptionError:
            return ""

    @property
    def analysis_method(self):
        return self._config.get('analyzer', 'analysis').lower()

    @property
    def binary_filepath(self):
        # remove quotes
        value = self._config.get('program', 'filepath')
        # Python 2/3 compat
        try:
            value = value.decode('utf-8')
        except AttributeError:
            pass
        value = value.replace('"', '')
        return value

    @property
    def in_marshalled_cfa_file(self):
        # remove quotes
        value = self._config.get('analyzer', 'in_marshalled_cfa_file')
        value = value.replace('"', '')
        return value

    @property
    def headers_files(self):
        try:
            value = self._config.get('analyzer', 'headers')
            value = value.replace('"', '')
            return value
        except ConfigParser.NoOptionError:
            return ''

    @property
    def format(self):
        return self._config.get('program', 'format').lower()

    @property
    def coredump(self):
        try:
            return self._config.get('program', 'load_elf_coredump')
        except ConfigParser.NoOptionError:
            return None

    @property
    def state(self):
        return self.init_state

    @property
    def overrides(self):
        if 'override' not in self._config.sections():
            return []
        res = []
        for ea, overrides in self._config.items('override'):
            ea = int(ea, 16)
            for override in overrides.split(';'):
                override = override.strip()
                if not override:
                    continue
                dest, val = override.split(',')
                dest = dest.strip()
                val = val.strip()
                res.append((ea, dest, val))
        return res

    @property
    def skips(self):
        if not self._config.has_option('analyzer', 'fun_skip'):
            return []
        skipstr = self._config.get('analyzer', 'fun_skip')
        idx = 0
        res = []
        err = False
        while True:
            try:
                allow_value_err = False
                val = []
                # identify @ or function name
                endidx = skipstr.index('(', idx)
                val.append(skipstr[idx:endidx].strip())
                idx = endidx + 1
                # identify arg_nb
                endidx = skipstr.index(',', idx)
                val.append(skipstr[idx:endidx].strip())
                idx = endidx + 1
                # identify ret_val
                endidx = skipstr.index(')', idx)
                val.append(skipstr[idx:endidx].strip())
                idx = endidx + 1
                res.append(tuple(val))
                allow_value_err = True
                idx = 1 + skipstr.index(',', idx)
            except ValueError:
                err = not allow_value_err
                break
            except:
                err = True
        if err:
            bc_log.error("Error while parsing fun_skip from config", exc_info=True)
            return []
        return res

    @property
    def nops(self):
        if not self._config.has_option('analyzer', 'nop'):
            return []
        return [(n,) for n in self._config.get('analyzer', 'nop').split(', ')]

    # Remap binary properties
    @property
    def remap(self):
        if not self._config.has_option('IDA', 'remap_binary'):
            return False
        return self._config.get('IDA', 'remap_binary').lower() == "true";

    @remap.setter
    def remap(self, value):
        self._config.set('IDA', 'remap_binary', value)


    # Configuration modification functions - edit currently loaded config
    @analysis_ep.setter
    def analysis_ep(self, value):
        if isinstance(value, (int, long)):
            value = "0x%X" % value
        self._config.set('analyzer', 'analysis_ep', value)

    @stop_address.setter
    def stop_address(self, value):
        if isinstance(value, (int, long)):
            value = "0x%X" % value
        if value is None or value == "":
            self._config.remove_option('analyzer', 'cut')
        else:
            self._config.set('analyzer', 'cut', value)

    @analysis_method.setter
    def analysis_method(self, value):
        self._config.set('analyzer', 'analysis', value.lower())

    @binary_filepath.setter
    def binary_filepath(self, value):
        # make sure value is surrounded by quotes
        if '"' not in value:
            value = '"%s"' % value
        self._config.set('program', 'filepath', value.encode('utf-8'))

    @in_marshalled_cfa_file.setter
    def in_marshalled_cfa_file(self, value):
        # make sure value is surrounded by quotes
        if '"' not in value:
            value = '"%s"' % value
        return self._config.set('analyzer', 'in_marshalled_cfa_file', value)

    @headers_files.setter
    def headers_files(self, value):
        if '"' not in value:
            value = ','.join(['"%s"' % f for f in value.split(',')])
        self._config.set('analyzer', 'headers', value)

    @format.setter
    def format(self, value):
        self._config.set('program', 'format', value)

    def replace_section_mappings(self, maplist):
        """
        maplist: list of ("name", vaddr: int, vlen: int, paddr: int, plen: hex)
        """
        self._config.remove_section('sections')
        self._config.add_section('sections')
        for s in maplist:
            self._config.set(
                "sections", "section[%s]" % s[0],
                "0x%x, 0x%x, 0x%x, 0x%x" % (s[1], s[2], s[3], s[4]))

    def set_cfa_options(self, store_cfa="true", in_cfa="", out_cfa=""):
        # make sure file paths are surrounded by quotes
        if '"' not in in_cfa:
            in_cfa = '"%s"' % in_cfa
        if '"' not in out_cfa:
            out_cfa = '"%s"' % out_cfa
        self._config.set('analyzer', 'store_marshalled_cfa', store_cfa)
        self._config.set('analyzer', 'out_marshalled_cfa_file', out_cfa)
        self._config.set('analyzer', 'in_marshalled_cfa_file', in_cfa)

    def update_overrides(self, overrides, nops, skips):
        # 1. Empty override section
        self._config.remove_section("override")
        self._config.add_section("override")

        if self.analysis_method == "forward_binary":
            # 2. Add sections from overrides argument
            ov_by_eip = collections.defaultdict(set)
            for (eip, register, value) in overrides:
                ov_by_eip[eip].add("%s, %s" % (register, value))

            # 3. Add to config
            for eip, ov_set in list(ov_by_eip.items()):
                hex_addr = "0x%x" % eip
                self._config.set("override", hex_addr, ';'.join(ov_set))
        else:  # backward
            # 2. Empty state section
            self._config.remove_section("state")
            self._config.add_section("state")

            # 3. Get overrides for current eip only, define that as initial
            # state
            initial_eip = int(self.analysis_ep, 16)
            for (eip, register, value) in overrides:
                if eip != initial_eip:
                    continue
                self._config.set("state", register, value)

        # 4. Also add nops & skips
        if len(nops) > 0:
            self._config.set('analyzer', 'nop', ','.join([n[0] for n in nops]))
        else:
            try:
                self._config.remove_option('analyzer', 'nop')
            except ConfigParser.NoSectionError:
                pass

        fun_skip_strs = []
        for sk in skips:
            fun_skip_strs.append("%s(%s,%s)" % (sk[0], sk[1], sk[2]))

        if len(fun_skip_strs) > 0:
            self._config.set('analyzer', 'fun_skip', ', '.join(fun_skip_strs))
        else:
            try:
                self._config.remove_option('analyzer', 'fun_skip')
            except ConfigParser.NoSectionError:
                pass

    @staticmethod
    def load_from_str(string):
        if sys.version_info < (2, 8):
            sio = StringIO(unicode(string))
        else:
            sio = StringIO(string)
        parser = ConfigParser.RawConfigParser()
        parser.optionxform = str
        parser.readfp(sio)
        return AnalyzerConfig(parser)

    def write(self, filepath):
        # OCaml can only handle "local" encodings for file name
        # So, ugly code following
        binpath = self.binary_filepath
        # TODO FIXME (python3 ...)
        # local_binpath = ('"%s"' % binpath).encode(sys.getfilesystemencoding())
        local_binpath = '"%s"' % binpath
        self._config.set('program', 'filepath', local_binpath)
        with open(filepath, 'w') as configfile:
            self._config.write(configfile)
        self.binary_filepath = binpath

    def __str__(self):
        self._config.remove_section('state')
        self._config.add_section('state')
        for key, val in self.init_state.as_kv():
            self._config.set('state', key, val)
        sio = StringIO()
        self._config.write(sio)
        sio.seek(0)
        return sio.read()

    def edit_str(self):
        """
        Return a text representation suitable for user edition.
        Before calling this, caller must call update_overrides.
        """
        return str(self)

    @staticmethod
    def get_default_config(analysis_start_va, analysis_stop_va,
                           analysis_method):
        """
        Returns a new AnalyzerConfig for the given entry point, cut and
        analysis method
        """
        # this function will use the default parameters
        config = ConfigParser.RawConfigParser()
        config.optionxform = str

        config_path = PluginOptions.config_path
        # Load default part - XXX move this logic to PluginOptions
        configfile = os.path.join(config_path, "conf", "default.ini")
        bc_log.debug("Reading config from %s", configfile)
        r = config.read(configfile)
        if len(r) != 1:
            bc_log.warning("Default config file %s could not be found",
                           configfile)

        code_start_va, _ = ConfigHelpers.get_code_section(
            analysis_start_va)

        config.set('analyzer', 'analysis_ep', "0x%0X" % analysis_start_va)
        config.set('analyzer', 'analysis', analysis_method)

        # [program] section
        config.add_section('program')
        # IDA doesn't really support real mode
        config.set('program', 'mode', 'protected')
        config.set('program', 'call_conv',
                   ConfigHelpers.get_call_convention())
        config.set('program', 'mem_sz',
                   ConfigHelpers.get_bitness(code_start_va))
        config.set('program', 'op_sz', ConfigHelpers.get_stack_width())
        config.set('program', 'stack_width', ConfigHelpers.get_stack_width())

        arch = ConfigHelpers.get_arch()
        config.set('program', 'architecture', arch)

        input_file = ConfigHelpers.guess_file_path()
        ftype = ConfigHelpers.get_file_type()
        config.set('program', 'filepath', '"%s"' % input_file.encode('utf-8'))

        # For now BinCAT engine only parses elf files
        if ftype != "elf":
            config.set('program', 'format', 'manual')
        else:
            config.set('program', 'format', ftype)

        # [sections section]
        config.add_section('sections')
        for s in ConfigHelpers.get_sections():
            config.set('sections', 'section[%s]' % s[0],
                       '0x%x, 0x%x, 0x%x, 0x%x' % (s[1], s[2], s[3], s[4]))

        config.add_section('state')
        config.add_section('override')
        if analysis_method == 'forward_binary':
            # [state section]
            config.set('state', 'mem[0xb8000000*8192]', '|00|?0xFF')
            init_state = InitialState.get_default(analysis_start_va)
            for key, val in init_state:
                config.set('state', key, val)

        imports = ConfigHelpers.get_imports()
        # [import] section
        config.add_section('imports')
        for ea, imp in imports.items():
            if imp[0]:
                name = "%s, \"%s\"" % imp
            else:
                name = "all,\"%s\"" % imp[1]
            config.set('imports', ("0x%x" % ea), name)
        # list all files in config_path/lib/*.{c,no}.
        # for each lib (same base filename) keep .no if it exists, else .c
        headers_filenames = glob.glob(os.path.join(config_path, 'lib', '*.no'))
        # Add .c if there is no associated .no
        for c in glob.glob(os.path.join(config_path, 'lib', '*.c')):
            if c[:-2] + '.no' not in headers_filenames:
                headers_filenames.append(c)
        # remove duplicates
        quoted_filenames = ['"%s"' % h for h in headers_filenames]
        config.set('analyzer', 'headers', ','.join(quoted_filenames))

        # Load default GDT/Segment registers according to file type
        # XXX move this logic to PluginOptions
        if ftype == "pe":
            os_name = "windows"
        else:  # default to Linux config if not windows
            os_name = "linux"
        os_specific = os.path.join(
            config_path, "conf", "%s-%s.ini" % (os_name, arch))
        bc_log.debug("Reading OS config from %s", os_specific)
        config.read(os_specific)

        # arch-specifig sections
        if arch == 'x86':
            try:
                config.add_section(arch)
            except ConfigParser.DuplicateSectionError:
                # already exists in (arch,OS)-specific config
                pass
            config.set('x86', 'mem_model', ConfigHelpers.get_memory_model())
            if analysis_method == 'backward':
                # remove segment registers
                for seg_reg in ('cs', 'ds', 'ss', 'es', 'fs', 'gs'):
                    config.remove_option('x86', seg_reg)
        elif arch == "powerpc":
            try:
                config.add_section(arch)
            except ConfigParser.DuplicateSectionError:
                # already exists in (arch,OS)-specific config
                pass
            config.set('powerpc', 'endianness', ConfigHelpers.get_endianness())

        # [libc section]
        # config.add_section('libc')
        # config.set('libc', 'call_conv', 'fastcall')
        # config.set('libc', '*', 'open(@, _)')
        # config.set('libc', '*', 'read<stdcall>(@, *, @)')
        ac = AnalyzerConfig(config)
        ac.analysis_ep = analysis_start_va
        ac.stop_address = analysis_stop_va
        return ac


class AnalyzerConfigurations(object):
    def __init__(self, state):
        self._state = state
        self._netnode = idabincat.netnode.Netnode()
        #: name -> serialized AnalyzerConfig
        self._configs = {}
        #: address (int) -> name
        self._prefs = {}
        #: list of functions to be called prior to updating overrides
        self.pre_callbacks = []
        #: list of functions to be called after updating overrides
        self.post_callbacks = []
        #: list of sorted names - cache used by UI
        self.names_cache = []
        #: list configs from IDB
        self._load_from_idb()

    def refresh_cache(self):
        self.names_cache = sorted(self._configs.keys())

    def register_callbacks(self, pre_cb, post_cb):
        # used for GUI configurations panel
        if pre_cb:
            self.pre_callbacks.append(pre_cb)
        if post_cb:
            self.post_callbacks.append(post_cb)

    def _callback_wrap(f):
        def wrap(self, *args, **kwargs):
            for cb in self.pre_callbacks:
                cb()
            f(self, *args, **kwargs)
            self.refresh_cache()
            for cb in self.post_callbacks:
                cb()
        return wrap

    def _load_from_idb(self):
        self._configs = self._netnode.get('analyzer_configs', dict())
        self._prefs = {}
        for k, v in list(self._netnode.get('analyzer_prefs', dict()).items()):
            self._prefs[int(k)] = v
        for k, v in list(self._prefs.items()):
            if v not in self._configs:
                del self._prefs[k]
        self.refresh_cache()

    def new_config(self, start_va, stop_va, analysis_config):
        """
        return new configuration
        """
        return AnalyzerConfig.get_default_config(start_va, stop_va,
                                                 analysis_config)

    def __getitem__(self, name_or_address):
        """
        Get named config, or preferred config if defined for this address.
        Returns an AnalyzerConfig instance, or None
        """
        if isinstance(name_or_address, (int, long)):
            # address
            name = self._prefs.get(name_or_address, None)
            if not name:
                return
            config_str = self._configs[name]
        else:
            config_str = self._configs.get(name_or_address, None)
        return AnalyzerConfig.load_from_str(config_str)

    def set_pref(self, address, name):
        self._prefs[address] = name
        self._netnode['analyzer_prefs'] = self._prefs

    def get_pref(self, address):
        return self._prefs.get(address, None)

    @_callback_wrap
    def __setitem__(self, name, config):
        self._configs[name] = str(config)
        self._netnode['analyzer_configs'] = self._configs

    @_callback_wrap
    def __delitem__(self, name):
        if name not in self._configs:
            return
        del self._configs[name]
        for k, v in list(self._prefs.items()):
            if v == name:
                del self._prefs[k]
        self._netnode['analyzer_configs'] = self._configs
        self._netnode['analyzer_prefs'] = self._prefs

    def __len__(self):
        return len(self._configs)
