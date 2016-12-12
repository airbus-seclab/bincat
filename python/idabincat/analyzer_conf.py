from __future__ import absolute_import
import ctypes
import collections
import functools
import os
import os.path
import StringIO
import ConfigParser
import idaapi
import idc
import logging
import idabincat.netnode
import idautils

# Logging
bc_log = logging.getLogger('bincat-cfg')
bc_log.setLevel(logging.DEBUG)

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
            return "binary"

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
        if cc not in ("stdcall", "cdecl", "fastcall"):
            return "stdcall"
        else:
            return cc

    @staticmethod
    def get_bitness(ea):
        bitness = idaapi.getseg(ea).bitness
        return {0: 16, 1: 32, 2: 64}[bitness]

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
            if (seg.type == idaapi.SEG_CODE and
                    seg.startEA <= entrypoint < seg.endEA):
                # TODO : check PE/ELF for **physical** (raw) section size
                return seg.startEA, seg.endEA
        bc_log.error("No code section has been found for entrypoint %#08x",
                     entrypoint)
        return -1, -1

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
    def get_registers_with_state():
        regs = {}
        for name in ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]:
            regs[name] = "0?0xFFFFFFFF"
        for name in ["cf", "pf", "af", "zf", "sf", "tf", "if", "of", "nt",
                     "rf", "vm", "ac", "vif", "vip", "id"]:
            regs[name] = "0?1"

        regs["df"] = "0"
        regs["iopl"] = "3"
        return regs


class AnalyzerConfig(object):
    """
    Handles configuration files for the analyzer.
    """
    def __init__(self, state):
        self.version = "0.0"
        self.netnode = idabincat.netnode.Netnode()
        self._config = ConfigParser.RawConfigParser()
        self._config.optionxform = str
        #: bcplugin.State instance, to fetch current configuration data
        self.state = state

    # Convenience access functions
    @property
    def analysis_ep(self):
        return self._config.get('loader', 'analysis_ep')

    @property
    def stop_address(self):
        return self._config.get('analyzer', 'cut')

    @property
    def analysis_method(self):
        return self._config.get('analyzer', 'analysis').lower()

    @property
    def binary_filepath(self):
        return self._config.get('binary', 'filepath')

    @property
    def in_marshalled_cfa_file(self):
        return self._config.get('analyzer', 'in_marshalled_cfa_file')

    # Configuration modification functions - edit currently loaded config
    @analysis_ep.setter
    def analysis_ep(self, value):
        if type(value) in (int, long):
            value = "0x%X" % value
        self._config.set('loader', 'analysis_ep', value)

    @stop_address.setter
    def stop_address(self, value):
        if type(value) in (int, long):
            value = "0x%X" % value
        if value is None:
            value = ""
        self._config.set('analyzer', 'cut', value)

    @binary_filepath.setter
    def binary_filepath(self, value):
        self._config.set('binary', 'filepath', value)

    @in_marshalled_cfa_file.setter
    def in_marshalled_cfa_file(self, value):
        return self._config.set('analyzer', 'in_marshalled_cfa_file', value)

    def set_cfa_options(self, store_cfa="true", in_cfa="", out_cfa=""):
        self._config.set('analyzer', 'store_marshalled_cfa', store_cfa)
        self._config.set('analyzer', 'out_marshalled_cfa_file', out_cfa)
        self._config.set('analyzer', 'in_marshalled_cfa_file', in_cfa)

    def update_overrides(self, overrides):
        # 1. Empty existing overrides sections
        self._config.remove_section("override")
        self._config.add_section("override")
        # 2. Add sections from overrides argument
        ov_by_eip = collections.defaultdict(set)
        for (eip, register, value) in overrides:
            ov_by_eip[eip].add("%s, %s;" % (register, value))
        # 3. Add to config
        for eip, ov_set in ov_by_eip.items():
            hex_addr = "0x%x" % eip
            self._config.set("override", hex_addr, ''.join(ov_set))

    # Input functions: load a config from default values, a string, or the IDB
    def load_from_str(self, string):
        sio = StringIO.StringIO(string)
        self._config = ConfigParser.RawConfigParser()
        self._config.optionxform = str
        self._config.readfp(sio)

    def load_for_address(self, analysis_start_va, analysis_stop_va):
        """
        Get config for analysis_start_va, from IDB if activated and present
        Return True if loaded from IDB, False if default
        """
        c_str = None
        if self.state.options.get("load_from_idb") == "True":
            if analysis_start_va in self.netnode:
                c_str = self.netnode[analysis_start_va]
        if c_str:
            bc_log.info("loaded config from IDB for address %x",
                        analysis_start_va)
            self.load_from_str(c_str)
            return True
        else:
            self._load_default_config(analysis_start_va, analysis_stop_va)
            return False

    # Output functions: save config to idb, a file, the IDB (for a given
    # address, or as default)
    def write(self, filepath):
        with open(filepath, 'w') as configfile:
            self._config.write(configfile)

    def save_for_address(self, address):
        self.netnode[address] = str(self)

    def save_as_default(self):
        self.netnode["default"] = str(self)

    def __str__(self):
        sio = StringIO.StringIO()
        self._config.write(sio)
        sio.seek(0)
        return sio.read()

    # Internal helper functions
    def _load_default_config(self, analysis_start_va, analysis_stop_va):
        """
        Sets current config to default config for the given entry point
        """
        # this function will use the default parameters
        config = ConfigParser.RawConfigParser()
        config.optionxform = str

        # Load default part - XXX move this logic to PluginOptions
        configfile = os.path.join(self.state.options.config_path, "conf",
                                  "default.ini")
        bc_log.debug("Reading config from %s", configfile)
        r = config.read(configfile)
        if len(r) != 1:
            bc_log.warning("Default config file %s could not be found",
                           configfile)

        code_start_va, code_end_va = ConfigHelpers.get_code_section(
            analysis_start_va)
        code_len = code_end_va - code_start_va

        # [settings] section
        config.add_section('settings')
        config.set('settings', 'mem_model', ConfigHelpers.get_memory_model())
        # IDA doesn't really support real mode
        config.set('settings', 'mode', 'protected')
        config.set('settings', 'call_conv', ConfigHelpers.get_call_convention())
        config.set('settings', 'mem_sz', 32)
        config.set('settings', 'op_sz',
                   ConfigHelpers.get_bitness(code_start_va))
        config.set('settings', 'stack_width', ConfigHelpers.get_stack_width())

        # [loader section]
        config.add_section('loader')
        # code section va
        config.set('loader', 'code_va', "0x%X" % code_start_va)
        # code section offset
        config.set('loader', 'code_phys',
                   hex(idaapi.get_fileregion_offset(code_start_va)))
        # code section length
        config.set('loader', 'code_length', "0x%0X" % code_len)

        config.set('loader', 'analysis_ep', "0x%0X" % analysis_start_va)

        # Load default GDT/Segment registers according to file type
        ftype = ConfigHelpers.get_file_type()
        # XXX move this logic to PluginOptions
        if ftype == "pe":
            os_specific = os.path.join(
                self.state.options.config_path, "conf", "windows.ini")
        else:  # default to Linux config if not windows
            os_specific = os.path.join(
                self.state.options.config_path, "conf", "linux.ini")
        bc_log.debug("Reading OS config from %s", os_specific)
        config.read(os_specific)

        # [binary section]
        config.add_section('binary')
        input_file = idaapi.get_input_file_path()
        if not os.path.isfile(input_file):
            # get_input_file_path returns file path from IDB, which may not
            # exist locally if IDB has been moved (eg. send idb+binary to
            # another analyst)
            guessed_path = idc.GetIdbPath().replace('idb', 'exe')
            if os.path.isfile(guessed_path):
                input_file = guessed_path

        if not os.path.isfile(input_file):
            bc_log.warning("Cannot open binary %s for reading, you should "
                           "patch your config manually", input_file)

        config.set('binary', 'filepath', input_file)
        config.set('binary', 'format', ftype)

        # [sections section]
        config.add_section("sections")
        for s in ConfigHelpers.get_sections():
            config.set("sections", "section[%s]" % s[0],
                       "0x%x, 0x%x, 0x%x, 0x%x" % (s[1], s[2], s[3], s[4]))

        # [state section]
        config.add_section("state")
        regs = ConfigHelpers.get_registers_with_state()
        for rname, val in regs.iteritems():
            if rname != "esp":
                config.set("state", ("reg[%s]" % rname), val)
        # Default stack
        config.set("state", "reg[esp]", "0x2000")
        config.set("state", "stack[0x1000*8192]", "|00|?0xFF")

        imports = ConfigHelpers.get_imports()
        # [import] section
        config.add_section('imports')
        for ea, imp in imports.iteritems():
            if imp[0]:
                name = "%s, %s" % imp
            else:
                name = "all,%s" % imp[1]
            config.set('imports', ("0x%x" % ea), name)
        # [libc section]
        # config.add_section('libc')
        # config.set('libc', 'call_conv', 'fastcall')
        # config.set('libc', '*', 'open(@, _)')
        # config.set('libc', '*', 'read<stdcall>(@, *, @)')
        self._config = config
        self.analysis_ep = analysis_start_va
        self.stop_address = analysis_stop_va
