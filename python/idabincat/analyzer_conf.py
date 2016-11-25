# Fuck Python.
from __future__ import absolute_import
import collections
import functools
import os
import StringIO
import ConfigParser
import idaapi
import logging
import idabincat.netnode

# Logging
bc_log = logging.getLogger('bincat-cfg')
bc_log.setLevel(logging.DEBUG)


class AnalyzerConfig(object):
    ftypes = {idaapi.f_PE: "pe",
              idaapi.f_ELF: "elf",
              idaapi.f_MACHO: "macho"}
    """
    Handles configuration files for the analyzer.
    """
    def __init__(self):
        self.version = "0.0"
        #: int
        self.analysis_ep = None
        #: int
        self.analysis_end = None
        self.netnode = idabincat.netnode.Netnode()
        self.config = ConfigParser.RawConfigParser()
        self.config.optionxform = str

    @property
    def code_va(self):
        va, _ = self.get_code_section(self.analysis_ep)
        return va

    @property
    def code_length(self):
        va, end = self.get_code_section(self.analysis_ep)
        return end-va

    @staticmethod
    def get_file_type():
        ida_db_info_structure = idaapi.get_inf_structure()
        f_type = ida_db_info_structure.filetype
        if f_type in AnalyzerConfig.ftypes:
            return AnalyzerConfig.ftypes[f_type]
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
        cc =  {
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
        for n in xrange(idaapi.get_segm_qty()):
            seg = idaapi.getnseg(n)
            if (seg.type == idaapi.SEG_CODE and
                    seg.startEA <= entrypoint < seg.endEA):
                # TODO : check PE/ELF for **physical** (raw) section size
                return seg.startEA, seg.endEA
        bc_log.error("No code section has been found for entrypoint %#08x",
                     entrypoint)
        return -1, -1

    # XXX check if we need to return RODATA ?
    @staticmethod
    def get_data_section():
        for n in xrange(idaapi.get_segm_qty()):
            seg = idaapi.getnseg(n)
            if seg.type == idaapi.SEG_DATA:
                return seg.startEA, seg.endEA
        bc_log.warning("no Data section has been found")
        return -1, -1

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
        for i in xrange(0, nimps):
            name = idaapi.get_import_module_name(i)
            imp_cb = functools.partial(AnalyzerConfig.add_imp_to_dict, imports, name)
            idaapi.enum_import_names(i, imp_cb)
        return imports

    @staticmethod
    def get_registers_with_state():
        regs = {}
        for regname in ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]:
            regs[regname] = "0?0xFFFFFFFF"
        for regname in ["cf", "pf", "af", "zf", "sf", "tf", "if", "of", "nt",
                        "rf", "vm", "ac", "vif", "vip", "id"]:
            regs[regname] = "0?1"

        regs["df"] = "0"
        regs["iopl"] = "3"
        return regs

    def __str__(self):
        sio = StringIO.StringIO()
        self.config.write(sio)
        sio.seek(0)
        return sio.read()

    def reset_from_str(self, string):
        sio = StringIO.StringIO(string)
        self.config = ConfigParser.RawConfigParser()
        self.config.optionxform = str
        self.config.readfp(sio)
        return self

    def set_start_stop_addr(self, start, stop):
        self.analysis_ep = start
        self.analysis_end = stop

    def get_default_config(self, state, ea_start, ea_end):
        """
        Returns a new ConfigParser instance, created for the current IDB
        """
        # this function will use the default parameters
        config = ConfigParser.RawConfigParser()
        config.optionxform = str

        # Load default part - XXX move this logic to PluginOptions
        configfile = os.path.join(state.options.config_path, "conf",
                                  "default.ini")
        bc_log.debug("Reading config from %s", configfile)
        r = config.read(configfile)
        if len(r) != 1:
            bc_log.warning("Default config file %s could not be found",
                           configfile)

        # Needed to call get_bitness and others
        if not self.analysis_ep:
            self.analysis_ep = ea_start
        if not self.analysis_end:
            self.analysis_end = ea_end

        # [settings] section
        config.add_section('settings')
        config.set('settings', 'mem_model', self.get_memory_model())
        # IDA doesn't really support real mode
        config.set('settings', 'mode', 'protected')
        config.set('settings', 'call_conv', self.get_call_convention())
        config.set('settings', 'mem_sz', 32)
        config.set('settings', 'op_sz', self.get_bitness(self.code_va))
        config.set('settings', 'stack_width', self.get_stack_width())

        # [loader section]
        config.add_section('loader')
        # code section va
        config.set(
            'loader', 'code_va', hex(self.code_va).strip('L'))
        # code section offset
        config.set(
            'loader', 'code_phys',
            hex(idaapi.get_fileregion_offset(self.code_va)))
        # code section length
        config.set('loader', 'code_length', hex(self.code_length).strip('L'))

        config.set('loader', 'analysis_ep', hex(self.analysis_ep).strip('L'))
        # Add end as cut
        try:
            cut = config.get('analyzer', 'cut')
            cut += ", "+hex(self.analysis_end).strip('L')
        except ConfigParser.NoOptionError:
            cut = hex(self.analysis_end).strip('L')
        config.set('analyzer', 'cut', cut)

        # Load default GDT/Segment registers according to file type
        ftype = AnalyzerConfig.get_file_type()
        # XXX move this logic to PluginOptions
        if ftype == "pe":
            os_specific = os.path.join(state.options.config_path, "conf", "windows.ini")
        else:  # default to Linux config if not windows
            os_specific = os.path.join(state.options.config_path, "conf", "linux.ini")
        bc_log.debug("Reading OS config from %s", os_specific)
        config.read(os_specific)

        # [binary section]
        config.add_section('binary')
        input_file = idaapi.get_input_file_path()
        try:
            open(input_file, "r").close()
        except IOError:
            bc_log.warning("Cannot open binary %s for reading, you should patch"
                           " your config manually", input_file)

        config.set('binary', 'filepath', input_file)
        config.set('binary', 'format', self.get_file_type())

        # [state section]
        config.add_section("state")
        regs = AnalyzerConfig.get_registers_with_state()
        for rname, val in regs.iteritems():
            if rname != "esp":
                config.set("state", ("reg[%s]" % rname), val)
        # Default stack
        config.set("state", "reg[esp]", "0x2000")
        config.set("state", "stack[0x1000*8192]", "|00|!0xFF")

        imports = self.get_imports()
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
        return config

    def write(self, filepath):
        with open(filepath, 'w') as configfile:
            self.config.write(configfile)

    def save_to_idb(self, address):
        self.netnode[address] = str(self)

    def load_from_idb(self, address):
        if address in self.netnode:
            return self.netnode[address]
        else:
            return None

    def save_as_default(self):
        self.netnode["default"] = str(self)

    def for_address(self, state, addr_start, addr_end):
        if state.options.get("load_from_idb") == "True":
            c = self.load_from_idb(addr_start)
        else:
            c = None
        if c:
            bc_log.info("loaded config from IDB for address %x", addr_start)
            self.reset_from_str(c)
        else:
            self.config = self.get_default_config(state, addr_start, addr_end)

    def update_overrides(self, overrides):
        # 1. Empty existing overrides sections
        self.config.remove_section("override")
        self.config.add_section("override")
        # 2. Add sections from overrides argument
        ov_by_eip = collections.defaultdict(set)
        for (eip, register, value) in overrides:
            ov_by_eip[eip].add("%s, %s;" % (register, value))
        # 3. Add to config
        for eip, ov_set in ov_by_eip.items():
            hex_addr = "0x%x" % eip
            self.config.set("override", hex_addr, ''.join(ov_set))
