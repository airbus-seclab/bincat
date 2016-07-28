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
    Generates a configuration file for the analyzer.
    """
    def __init__(self):
        self.version = "0.0"
        #: int
        self.analysis_ep = None
        #: int
        self.analysis_end = None
        self.netnode = idabincat.netnode.Netnode()
        self.config = None

    @property
    def code_va(self):
        va, _ = self.get_code_section(self.analysis_ep)
        return va

    @property
    def code_length(self):
        va, end = self.get_code_section(self.analysis_ep)
        return end-va

    def __str__(self):
        sio = StringIO.StringIO()
        self.config.write(sio)
        sio.seek(0)
        return sio.read()

    def read_string(self, string):
        sio = StringIO.StringIO(string)
        self.config.readfp(sio)
        return self

    def set_start_stop_addr(self, start, stop):
        self.analysis_ep = start
        self.analysis_end = stop

    def get_file_type(self):
        ida_db_info_structure = idaapi.get_inf_structure()
        f_type = ida_db_info_structure.filetype
        return self.ftypes[f_type]

    @staticmethod
    def get_memory_model():
        ida_db_info_structure = idaapi.get_inf_structure()
        compiler_info = ida_db_info_structure.cc
        # XXX check correctness, should be == CONSTANT ?
        if compiler_info.cm & idaapi.C_PC_TINY == 1:
            return "tiny"
        if compiler_info.cm & idaapi.C_PC_SMALL == 1:
            return "small"
        if compiler_info.cm & idaapi.C_PC_COMPACT == 1:
            return "compact"
        if compiler_info.cm & idaapi.C_PC_MEDIUM == 1:
            return "medium"
        if compiler_info.cm & idaapi.C_PC_LARGE == 1:
            return "large"
        if compiler_info.cm & idaapi.C_PC_HUGE == 1:
            return "huge"
        if compiler_info.cm & idaapi.C_PC_FLAT == 3:
            return "flat"

    @staticmethod
    def get_call_convention():
        ida_db_info_structure = idaapi.get_inf_structure()
        compiler_info = ida_db_info_structure.cc
        return {
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
                    seg.startEA <= entrypoint <= seg.endEA):
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

    def get_default_config(self, ea):
        """
        Returns a new ConfigParser instance
        """
        # this function will use the default parameters
        config = ConfigParser.RawConfigParser()
        config.optionxform = str

        self.analysis_ep = ea

        # [settings] section
        config.add_section('settings')
        config.set('settings', 'mem_model', self.get_memory_model())
        # TODO get cpu mode from idaapi ?
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
        config.set('loader', 'analysis_ep', hex(self.analysis_ep))

        config.set('loader', 'cs', '0x73')
        config.set('loader', 'ds', '0x7b')
        config.set('loader', 'ss', '0x7b')
        config.set('loader', 'es', '0x7b')
        config.set('loader', 'ds', '0x7b')
        config.set('loader', 'fs', '0x7b')
        config.set('loader', 'gs', '0x7b')

        # [binary section]
        config.add_section('binary')
        # config.set('binary', 'filename', GetInputFile())
        config.set('binary', 'filepath', idaapi.get_input_file_path())
        config.set('binary', 'format', self.get_file_type())

        # [import] section
        config.add_section('imports')
        config.set('imports', '0x04', 'libc, open')

        # [GDT] section
        config.add_section('GDT')
        config.set('GDT', 'GDT[0]', '0x0000000000000000')
        config.set('GDT', 'GDT[1]', '0x0000000000000000')
        config.set('GDT', 'GDT[2]', '0x0000000000000000')
        config.set('GDT', 'GDT[3]', '0x0000000000000000')
        config.set('GDT', 'GDT[4]', '0x0000000000000000')
        config.set('GDT', 'GDT[5]', '0x0000000000000000')
        config.set('GDT', 'GDT[6]', '0x0000000000000000')
        config.set('GDT', 'GDT[7]', '0x0000000000000000')
        config.set('GDT', 'GDT[8]', '0x0000000000000000')
        config.set('GDT', 'GDT[9]', '0x0000000000000000')
        config.set('GDT', 'GDT[10]', '0x0000000000000000')
        config.set('GDT', 'GDT[11]', '0x0000000000000000')
        config.set('GDT', 'GDT[12]', '0x0000ffff00cf9b00')
        config.set('GDT', 'GDT[13]', '0x0000ffff00cf9300')
        config.set('GDT', 'GDT[14]', '0x0000ffff00cffb00')
        config.set('GDT', 'GDT[15]', '0x0000ffff00cff300')
        config.set('GDT', 'GDT[16]', '0xfac0206bf7008bb7')
        config.set('GDT', 'GDT[17]', '0xd0000fffd4008254')
        config.set('GDT', 'GDT[18]', '0x0000ffff00409a00')
        config.set('GDT', 'GDT[19]', '0x0000ffff00009a00')
        config.set('GDT', 'GDT[20]', '0x0000ffff00009200')
        config.set('GDT', 'GDT[21]', '0x0000000000009200')
        config.set('GDT', 'GDT[22]', '0x0000000000009200')
        config.set('GDT', 'GDT[23]', '0x0000ffff00409a00')
        config.set('GDT', 'GDT[24]', '0x0000ffff00009a00')
        config.set('GDT', 'GDT[25]', '0x0000ffff00409200')
        config.set('GDT', 'GDT[26]', '0x0000ffff00cf9200')
        config.set('GDT', 'GDT[27]', '0x0000ffff368f9325')
        config.set('GDT', 'GDT[28]', '0x1c800018f74091b8')
        config.set('GDT', 'GDT[29]', '0x0000000000000000')
        config.set('GDT', 'GDT[30]', '0x0000000000000000')
        config.set('GDT', 'GDT[31]', '0x8800206bc1008980')

        # [analyzer section]
        config.add_section('analyzer')
        config.set('analyzer', 'unroll', 5)
        config.set('analyzer', 'dotfile', 'cfa.dot')
        config.set('analyzer', 'verbose', 'true')

        # [state section]
        config.add_section('state')
        config.set('state', 'reg[eax]', '0x01 ! 0xff ? 0xf0')
        config.set('state', 'reg[ebx]', '0x02')
        config.set('state', 'reg[ecx]', '0x03')
        config.set('state', 'reg[edi]', '0x04')
        config.set('state', 'reg[esi]', '0x05')
        config.set('state', 'reg[esp]', '0x06')
        config.set('state', 'reg[ebp]', '0x07')

        config.set('state', 'mem[0x01]', '0x1234567812345678 ! 0xff')

        # [libc section]
        config.add_section('libc')
        config.set('libc', 'call_conv', 'fastcall')
        config.set('libc', '*', 'open(@, _)')
        config.set('libc', '*', 'read<stdcall>(@, *, @)')
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

    def for_address(self, address):
        c = self.load_from_idb(address)
        if c:
            self.read_string(c)
        else:
            self.config = self.get_default_config(address)
