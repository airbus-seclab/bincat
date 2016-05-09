#!/usr/bin/python2


# version IDA 6.8

# Imports
import os
import sys
import traceback
import ConfigParser
import tempfile

try:
    import idaapi
    import idc
    import idautils
except ImportError:
    print("This file is an IDA Pro plugin, it should only be loaded in IDA")
    sys.exit(1)


# Loading Qt packages
try:
    from PyQt5 import QtCore, QtWidgets
except:
    idaapi.msg("[+] BinCat: failed to load Qt libs from PyQt5 \n %s\n" %
               repr(sys.exc_info()))
    sys.exit(1)

# Loading pybincat.state

try:
    from pybincat import program
except:
    idaapi.msg("[+] BinCat: failed to load pybincat.program \n %s\n" %
               repr(sys.exc_info()))
    sys.exit(1)


# ------------------------------------
# setting environnement variables
if sys.platform.startswith('linux'):
    PYTHON_BIN = 'python2'
    PYTHON_PATH = os.path.normpath('/usr/bin')


class AnalyzerConfig:
    """
    Generates a configuration file for the analyzer.
    """
    def __init__(self):
        self.version = "0.0"
        #: int
        self.code_length = None
        #: int
        self.entrypoint = None
        #: int
        self.rva_code, _ = self.getCodeSection()

    def getFirstEntryPoint(self):
        ord0 = idc.GetEntryOrdinal(0)
        return ord0

    def getFileType(self):
        self.ftypes = {idaapi.f_PE: "pe",
                       idaapi.f_ELF: "elf",
                       idaapi.f_MACHO: "macho"}
        ida_db_info_structure = idaapi.get_inf_structure()
        f_type = ida_db_info_structure.filetype
        return self.ftypes[f_type]

    def getMemoryModel(self):
        ida_db_info_structure = idaapi.get_inf_structure()
        compiler_info = ida_db_info_structure.cc
        if (compiler_info.cm & idaapi.C_PC_TINY == 1):
            return "tiny"
        if (compiler_info.cm & idaapi.C_PC_SMALL == 1):
            return "small"
        if (compiler_info.cm & idaapi.C_PC_COMPACT == 1):
            return "compact"
        if (compiler_info.cm & idaapi.C_PC_MEDIUM == 1):
            return "medium"
        if (compiler_info.cm & idaapi.C_PC_LARGE == 1):
            return "large"
        if (compiler_info.cm & idaapi.C_PC_HUGE == 1):
            return "huge"
        if (compiler_info.cm & idaapi.C_PC_FLAT == 3):
            return "flat"

    def getCallConvention(self):
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

    def getBitness(self, ea):
        bitness = idc.GetSegmentAttr(ea, idc.SEGATTR_BITNESS)
        return {0: 16, 1: 32, 2: 64}[bitness]

    def getStackWidth(self):
        ida_db_info_structure = idaapi.get_inf_structure()
        if ida_db_info_structure.is_64bit():
            return(8*8)
        else:
            if ida_db_info_structure.is_32bit():
                return(4*8)
            else:
                return(2*8)

    def getCodeSection(self):
        # in case we have more than one code section we apply the following:
        # heuristic entry point must be in the code section
        BinCATLogViewer.Log("[+] BinCAT call GetCodeSegment ",
                            idaapi.SCOLOR_LOCNAME)

        ep = self.getFirstEntryPoint()
        for seg in idautils.Segments():
            seg_attributes = idc.GetSegmentAttr(
                idc.SegStart(seg), idc.SEGATTR_TYPE)
            if (seg_attributes == idaapi.SEG_CODE and
                    (idc.SegStart(seg) <= ep <= idc.SegEnd(seg))):
                start = idc.SegStart(seg)
                end = idc.SegEnd(seg)
                break
        else:
            log = "[+] BinCAT no Code section has been found"
            BinCATLogViewer.Log(log, idaapi.SCOLOR_LOCNAME)
            return -1
        log = "[+] Code section found at %#x:%#x " % (start, end)
        BinCATLogViewer.Log(log, idaapi.SCOLOR_LOCNAME)
        return start, end

    def getDataSection(self):
        for seg in idautils.Segments():
            seg_attributes = idc.GetSegmentAttr(idc.SegStart(seg),
                                                idc.SEGATTR_TYPE)
            if seg_attributes == idaapi.SEG_DATA:
                start = idc.SegStart(seg)
                end = idc.SegEnd(seg)
                break
        else:
            log = "[+] BinCAT no Data section has been found"
            BinCATLogViewer.Log(log, idaapi.SCOLOR_LOCNAME)
            return -1
        log = "[+] Data section found at %#x:%#x " % (start, end)
        BinCATLogViewer.Log(log, idaapi.SCOLOR_LOCNAME)
        return start, end

    def getConfigParser(self):
        """
        Returns a new ConfigParser instance
        """
        # this function will use the default parameters
        config = ConfigParser.ConfigParser()
        config.optionxform = str

        # [settings] section
        config.add_section('settings')
        config.set('settings', 'mem-model', self.getMemoryModel())
        # TODO get cpu mode from idaapi ?
        config.set('settings', 'mode', 'protected')
        config.set('settings', 'call-conv', self.getCallConvention())
        config.set('settings', 'mem-sz', 32)
        config.set('settings', 'op-sz', self.getBitness(self.rva_code))
        config.set('settings', 'stack-width', self.getStackWidth())

        # [loader section]
        config.add_section('loader')
        config.set(
            'loader', 'rva-code', hex(self.rva_code).strip('L'))
        config.set(
            'loader', 'entrypoint',
            hex(idaapi.get_inf_structure().startIP).strip('L'))
        config.set(
            'loader', 'phys-code-addr',
            hex(idaapi.get_fileregion_offset(self.rva_code)))
        # By default code-length is 0
        config.set('loader', 'code-length', '0')

        config.set('loader', 'cs', '0x73')
        config.set('loader', 'ds', '0x7b')
        config.set('loader', 'ss', '0x7b')
        config.set('loader', 'es', '0x7b')
        config.set('loader', 'ds', '0x7b')
        config.set('loader', 'fs', '0x7b')
        config.set('loader', 'gs', '0x7b')
        config.set('loader', 'code-length', self.code_length)
        config.set('loader', 'entrypoint', self.entrypoint)

        # [binary section]
        config.add_section('binary')
        # config.set('binary', 'filename', GetInputFile())
        config.set('binary', 'filepath', idc.GetInputFilePath())
        config.set('binary', 'format', self.getFileType())

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
        config.set('libc', 'call-conv', 'fastcall')
        config.set('libc', '*', 'open(@, _)')
        config.set('libc', '*', 'read<stdcall>(@, *, @)')
        return config

    def write(self, filepath):
        with open(filepath, 'w') as configfile:
            self.getConfigParser().write(configfile)


class TaintLaunchForm_t(QtWidgets.QDialog):

    def rbRegistersHandler(self):
        self.cbRegisters.setEnabled(True)
        # self.ipMemory.setDisabled(True)

    def rbMemoryHandler(self):
        # self.cbRegisters.setDisabled(True)
        self.ipMemory.setEnabled(True)

    def cbRegistersHandler(self, text):
        idaapi.msg(" selected register is %s \n " % text)

    def btnLaunchAnalyzer(self):
        BinCATLogViewer.Log("[+] BinCAT: Launching the analyzer",
                            idaapi.SCOLOR_LOCNAME)
        # Test if End address is not empty
        if not self.ipEndAddr.text():
            idaapi.warning(" End address is empty")
        else:
            # load the config file  for read and update
            cf = AnalyzerConfig()

            # get the code length
            startAddr = int(self.ipStartAddr.text(), 16)
            endAddr = int(self.ipEndAddr.text(), 16)
            cl = endAddr - startAddr

            rvacode = cf.rva_code
            cf.entrypoint = startAddr

            cf.code_length = (startAddr - rvacode) + cl

            path = tempfile.mkdtemp(suffix='bincat')
            initfname = os.path.join(path, "init.ini")
            outfname = os.path.join(path, "out.ini")
            logfname = os.path.join(path, "analyzer.log")

            log = "Current analyzer path: %s \n" % path
            BinCATLogViewer.Log(log, idaapi.SCOLOR_LOCNAME)

            cf.write(initfname)

            analyzerpath = BinCATForm.iptAnalyzerPath.text()
            ibcState.analyzer = Analyzer(initfname, outfname, logfname,
                                         analyzerpath)
            ibcState.analyzer.run()

            self.close()

    def btnAnalyzerConfig(self):
        BinCATLogViewer.Log("[+] BinCAT: Loading the analyzer configuration",
                            idaapi.SCOLOR_LOCNAME)
        bAc = AnalyzerConfForm_t(self)
        bAc.exec_()

    def __init__(self, parent):
        super(TaintLaunchForm_t, self).__init__(parent)

        layout = QtWidgets.QGridLayout()
        lblCstEditor = QtWidgets.QLabel(" Start taint analysis: ")
        currentEA = idc.here()

        # Start address
        lblStartAddr = QtWidgets.QLabel(" Start address: ")
        self.ipStartAddr = QtWidgets.QLineEdit(self)
        self.ipStartAddr.setText(hex(currentEA).rstrip('L'))

        # Use current basic block address as default end address
        endAddr = ""
        for block in idaapi.FlowChart(idaapi.get_func(idc.here())):
            if block.startEA <= currentEA and block.endEA >= currentEA:
                endAddr = hex(block.endEA).rstrip('L')
        lblEndAddr = QtWidgets.QLabel(" End address: ")
        self.ipEndAddr = QtWidgets.QLineEdit(self)
        self.ipEndAddr.setText(endAddr)

        # Tainting element register or memory XXX never used
        lblTntElem = QtWidgets.QLabel(" Tainted element   : ")

        # radio button register
        rbRegisters = QtWidgets.QCheckBox("Register")
        rbRegisters.toggled.connect(self.rbRegistersHandler)
        self.cbRegisters = QtWidgets.QComboBox(self)

        for reg in registers_x86:
            self.cbRegisters.addItem(reg)

        self.cbRegisters.setDisabled(True)
        self.cbRegisters.activated[str].connect(self.cbRegistersHandler)

        # self.ipRegs = QtWidgets.QLineEdit(self)
        # self.ipRegs.setDisabled(True)

        # radio button memory
        rbMemory = QtWidgets.QCheckBox("Memory")
        rbMemory.toggled.connect(self.rbMemoryHandler)
        self.ipMemory = QtWidgets.QLineEdit(self)
        self.ipMemory.setDisabled(True)

        # Start, cancel and analyzer config buttons
        self.btnStart = QtWidgets.QPushButton('Start', self)
        self.btnStart.setToolTip('Save Constraints.')
        self.btnStart.setFixedWidth(130)
        self.btnStart.clicked.connect(self.btnLaunchAnalyzer)

        self.btnCancel = QtWidgets.QPushButton('Cancel', self)
        self.btnCancel.setToolTip('Cancel.')
        self.btnCancel.setFixedWidth(130)
        self.btnCancel.clicked.connect(self.close)

        self.btnAc = QtWidgets.QPushButton('Analyzer configuration', self)
        self.btnAc.setToolTip('Configure the analyzer.')
        self.btnAc.setFixedWidth(150)
        self.btnAc.clicked.connect(self.btnAnalyzerConfig)

        layout.addWidget(lblCstEditor, 0, 0)

        layout.addWidget(lblStartAddr, 1, 0)
        layout.addWidget(self.ipStartAddr, 1, 1)

        layout.addWidget(lblEndAddr, 2, 0)
        layout.addWidget(self.ipEndAddr, 2, 1)

        layout.addWidget(rbRegisters, 3, 0)
        layout.addWidget(self.cbRegisters, 3, 1)

        layout.addWidget(rbMemory, 4, 0)
        layout.addWidget(self.ipMemory, 4, 1)

        layout.addWidget(self.btnStart, 5, 0)
        layout.addWidget(self.btnCancel, 5, 1)
        layout.addWidget(self.btnAc, 5, 2)

        layout.setColumnStretch(3, 1)
        layout.setRowStretch(6, 1)

        self.setLayout(layout)

    def show(self):
        self.setFixedSize(460, 200)
        self.setWindowTitle(" Analysis launcher: ")
        super(TaintLaunchForm_t, self).show()


class GDTEditorForm_t(QtWidgets.QDialog):

    def btnOKHandler(self):
        self.accept()

    def btnCancelHandler(self):
        self.reject()

    def __init__(self, parent):
        super(GDTEditorForm_t, self).__init__(parent)

        # XXX write to config object
        self.currentConfig = PluginState.currentConfig.getConfigParser()

        # Main table
        self.table = QtWidgets.QTableWidget()
        # 2 columun
        self.table.setColumnCount(2)

        self.table.setRowCount(len(self.currentConfig.options('GDT')))

        self.table.setHorizontalHeaderItem(
            0, QtWidgets.QTableWidgetItem("GDT"))
        self.table.setHorizontalHeaderItem(
            1, QtWidgets.QTableWidgetItem("Value"))

        # Fill the table with GDT section
        index = 0
        for gdt in self.currentConfig.options('GDT'):
            item = QtWidgets.QTableWidgetItem(gdt)
            # setItem(row, column, item)
            self.table.setItem(index, 0, item)
            index += 1

        index = 0
        for gdt in self.currentConfig.options('GDT'):
            item = QtWidgets.QTableWidgetItem(
                self.currentConfig.get('GDT', gdt))
            # setItem(row, column, item)
            self.table.setItem(index, 1, item)
            index += 1

        self.table.setColumnWidth(0, 80)
        self.table.setColumnWidth(1, 160)

        self.table.setMaximumWidth(300)
        self.table.setMinimumWidth(300)
        self.table.setMaximumHeight(400)
        self.table.setMinimumHeight(400)

        layout = QtWidgets.QGridLayout()

        layout.addWidget(self.table, 0, 0)
        # label = QtWidgets.QLabel('Tainting:')
        # layout.addWidget(label, 0, 0)

        # OK and Cancel button
        self.btnOK = QtWidgets.QPushButton('OK', self)
        self.btnOK.setToolTip('Save GDT.')
        self.btnOK.setFixedWidth(150)
        self.btnOK.clicked.connect(self.btnOKHandler)

        self.btnCancel = QtWidgets.QPushButton('Cancel', self)
        self.btnCancel.setToolTip('Cancel.')
        self.btnCancel.setFixedWidth(150)
        self.btnCancel.clicked.connect(self.close)

        layout.addWidget(self.btnOK, 1, 0)
        layout.addWidget(self.btnCancel, 1, 1)

        layout.setColumnStretch(0, 1)
        layout.setRowStretch(2, 1)

        self.setLayout(layout)

    def show(self):
        self.setFixedSize(460, 500)
        self.setWindowTitle(" GDT Editor: ")
        super(GDTEditorForm_t, self).show()


class ConstraintEditorForm_t(QtWidgets.QDialog):

    def btnOKHandler(self):
        self.accept()

    def btnCancelHandler(self):
        self.reject()

    def __init__(self, parent):
        super(ConstraintEditorForm_t, self).__init__(parent)

        layout = QtWidgets.QGridLayout()
        lblCstEditor = QtWidgets.QLabel("Initial state:")
        layout.addWidget(lblCstEditor, 0, 0)

        self.notes = QtWidgets.QPlainTextEdit()
        self.notes.setFixedHeight(300)
        self.notes.setFixedWidth(300)
        self.notes.appendPlainText("reg[eax] = 0x00")
        self.notes.appendPlainText("mem[0x4000] = 0x00")

        # OK and cancel button
        self.btnOK = QtWidgets.QPushButton('OK', self)
        self.btnOK.setToolTip('Save Constraints.')
        self.btnOK.setFixedWidth(150)
        self.btnOK.clicked.connect(self.btnOKHandler)

        self.btnCancel = QtWidgets.QPushButton('Cancel', self)
        self.btnCancel.setToolTip('Cancel.')
        self.btnCancel.setFixedWidth(150)
        self.btnCancel.clicked.connect(self.btnCancelHandler)

        layout.addWidget(self.notes, 1, 0)
        layout.addWidget(self.btnOK, 2, 0)
        layout.addWidget(self.btnCancel, 2, 1)

        layout.setColumnStretch(2, 1)
        layout.setRowStretch(3, 1)

        self.setLayout(layout)

    def show(self):
        self.setFixedSize(400, 400)
        self.setWindowTitle("Constraints Editor")
        super(ConstraintEditorForm_t, self).show()


class AnalyzerConfForm_t(QtWidgets.QDialog):
    """
    Class AnalyzerConfForm: this forms is populated by the content of the
    nop.ini file

    This form helps the en user to configure the analyzer
    """

    def btnCstrHandler(self):
        CstEdit = ConstraintEditorForm_t(self)
        CstEdit.show()

    def btnGDTHandler(self):
        GdtEdit = GDTEditorForm_t(self)
        GdtEdit.show()

    def btnImportHandler(self):
        idaapi.msg("TODO")

    def btnSegsHandler(self):
        idaapi.msg("TODO")

    def btnCancelHandler(self):
        self.reject()

    def btnOKHandler(self):
        self.accept()

    def __init__(self, parent):
        super(AnalyzerConfForm_t, self).__init__(parent)

        # XXX write to config object
        self.currentConfig = PluginState.currentConfig.getConfigParser()

        # based on the analyzer ini file (see test/nop.ini)
        # Settings label
        lblSettings = QtWidgets.QLabel("[Settings]")
        layout = QtWidgets.QGridLayout()
        layout.addWidget(lblSettings, 0, 0)

        # mem-model
        lblmemmodel = QtWidgets.QLabel(" mem-model: ")
        layout.addWidget(lblmemmodel, 1, 0)

        self.iptmm = QtWidgets.QLineEdit(self)

        self.iptmm.setText(self.currentConfig.get('settings', 'mem-model'))
        self.iptmm.setMaxLength = 256
        self.iptmm.setFixedWidth(200)

        layout.addWidget(self.iptmm, 1, 1)

        # call-conv
        lblcallconv = QtWidgets.QLabel(" call-conv: ")
        layout.addWidget(lblcallconv, 2, 0)

        self.iptcc = QtWidgets.QLineEdit(self)

        self.iptcc.setText(self.currentConfig.get('settings', 'call-conv'))
        self.iptcc.setMaxLength = 256
        self.iptcc.setFixedWidth(200)

        layout.addWidget(self.iptcc, 2, 1)

        # mem-size
        lblmemsize = QtWidgets.QLabel(" mem-size: ")
        layout.addWidget(lblmemsize, 3, 0)

        self.iptms = QtWidgets.QLineEdit(self)

        self.iptms.setText(self.currentConfig.get('settings', 'mem-sz'))
        self.iptms.setMaxLength = 256
        self.iptms.setFixedWidth(200)

        layout.addWidget(self.iptms, 3, 1)

        # op-sz
        lblopsz = QtWidgets.QLabel(" op-sz: ")
        layout.addWidget(lblopsz, 4, 0)
        self.iptos = QtWidgets.QLineEdit(self)

        self.iptos.setText(self.currentConfig.get('settings', 'op-sz'))
        self.iptos.setMaxLength = 256
        self.iptos.setFixedWidth(200)

        layout.addWidget(self.iptos, 4, 1)

        # stack-width
        lblstackwidth = QtWidgets.QLabel(" stack-width: ")
        layout.addWidget(lblstackwidth, 5, 0)
        self.iptsw = QtWidgets.QLineEdit(self)

        self.iptsw.setText(self.currentConfig.get('settings', 'stack-width'))
        self.iptsw.setMaxLength = 256
        self.iptsw.setFixedWidth(200)

        layout.addWidget(self.iptsw, 5, 1)

        # mode
        lblmode = QtWidgets.QLabel(" mode: ")
        layout.addWidget(lblmode, 6, 0)
        self.ipmode = QtWidgets.QLineEdit(self)

        self.ipmode.setText(self.currentConfig.get('settings', 'mode'))
        self.ipmode.setMaxLength = 256
        self.ipmode.setFixedWidth(200)

        layout.addWidget(self.ipmode, 6, 1)

        # loader label
        lblLoader = QtWidgets.QLabel("[Loader]")
        layout.addWidget(lblLoader, 7, 0)

        # rva-code-start
        lblrvacs = QtWidgets.QLabel(" rva-code: ")
        layout.addWidget(lblrvacs, 10, 0)
        self.iptrvacs = QtWidgets.QLineEdit(self)

        self.iptrvacs.setText(self.currentConfig.get('loader', 'rva-code'))
        self.iptrvacs.setMaxLength = 256
        self.iptrvacs.setFixedWidth(200)

        layout.addWidget(self.iptrvacs, 10, 1)

        # rva-entrypoint
        lblrvaep = QtWidgets.QLabel(" entrypoint: ")
        layout.addWidget(lblrvaep, 12, 0)
        self.iptrvaep = QtWidgets.QLineEdit(self)

        self.iptrvaep.setText(self.currentConfig.get('loader', 'entrypoint'))
        self.iptrvaep.setMaxLength = 256
        self.iptrvaep.setFixedWidth(200)

        layout.addWidget(self.iptrvaep, 12, 1)

        # Segments
        lblSegs = QtWidgets.QLabel("[Segments]")
        layout.addWidget(lblSegs, 13, 0)

        self.btnSegsEdit = QtWidgets.QPushButton('Edit/View Segments ', self)
        self.btnSegsEdit.clicked.connect(self.btnSegsHandler)
        layout.addWidget(self.btnSegsEdit, 13, 1)

        # Binary label
        lblBinary = QtWidgets.QLabel("[Binary]")
        layout.addWidget(lblBinary, 14, 0)

        # filepath
        lblfilepath = QtWidgets.QLabel(" filepath: ")
        layout.addWidget(lblfilepath, 15, 0)
        self.iptfp = QtWidgets.QLineEdit(self)

        self.iptfp.setText(self.currentConfig.get('binary', 'filepath'))
        self.iptfp.setMaxLength = 256
        self.iptfp.setFixedWidth(200)

        layout.addWidget(self.iptfp, 15, 1)

        # format
        lblformat = QtWidgets.QLabel(" format: ")
        layout.addWidget(lblformat, 16, 0)
        self.iptfmt = QtWidgets.QLineEdit(self)

        self.iptfmt.setText(self.currentConfig.get('binary', 'format'))
        self.iptfmt.setMaxLength = 256
        self.iptfmt.setFixedWidth(200)

        layout.addWidget(self.iptfmt, 16, 1)

        # code section phys start addr
        lblpc = QtWidgets.QLabel(" phys-code-addr: ")
        layout.addWidget(lblpc, 17, 0)
        self.iptpc = QtWidgets.QLineEdit(self)

        self.iptpc.setText(self.currentConfig.get('loader', 'phys-code-addr'))
        self.iptpc.setMaxLength = 256
        self.iptpc.setFixedWidth(200)

        layout.addWidget(self.iptpc, 17, 1)

        # analyzer label
        lblBinary = QtWidgets.QLabel("[Analyzer]")
        layout.addWidget(lblBinary, 18, 0)

        # unroll
        lblur = QtWidgets.QLabel(" unroll: ")
        layout.addWidget(lblur, 19, 0)
        self.iptur = QtWidgets.QLineEdit(self)

        self.iptur.setText(self.currentConfig.get('analyzer', 'unroll'))
        self.iptur.setMaxLength = 256
        self.iptur.setFixedWidth(200)

        layout.addWidget(self.iptur, 19, 1)

        # State label
        lblstate = QtWidgets.QLabel("[State]")
        layout.addWidget(lblstate, 20, 0)

        self.btnConstraint = QtWidgets.QPushButton(
            'Define', self)
        self.btnConstraint.clicked.connect(self.btnCstrHandler)
        layout.addWidget(self.btnConstraint, 20, 1)

        # Import table
        lblimport = QtWidgets.QLabel("[Imports]")
        layout.addWidget(lblimport, 21, 0)

        self.btnImportEdit = QtWidgets.QPushButton('Edit/View imports ', self)
        self.btnImportEdit.clicked.connect(self.btnImportHandler)
        layout.addWidget(self.btnImportEdit, 21, 1)

        # GDT label
        lblgdt = QtWidgets.QLabel("[GDT]")
        layout.addWidget(lblgdt, 22, 0)

        self.btnGDTEdit = QtWidgets.QPushButton('Edit/View GDT ', self)
        self.btnGDTEdit.clicked.connect(self.btnGDTHandler)
        layout.addWidget(self.btnGDTEdit, 22, 1)

        # OK and cancel button
        self.btnOK = QtWidgets.QPushButton('OK', self)
        self.btnOK.clicked.connect(self.btnOKHandler)
        layout.addWidget(self.btnOK, 25, 0)

        self.btnCancel = QtWidgets.QPushButton('Cancel', self)
        self.btnCancel.clicked.connect(self.btnCancelHandler)
        layout.addWidget(self.btnCancel, 25, 1)

        # Setting the layout
        layout.setColumnStretch(4, 1)
        layout.setRowStretch(26, 1)
        self.setLayout(layout)

    def show(self):
        # width x height
        self.setFixedSize(350, 600)
        self.setWindowTitle("Analyzer Configuration")
        super(AnalyzerConfForm_t, self).show()


class Analyzer(QtCore.QProcess):
    """
    Class Analyzer that inherits from Qprocess

    The idea is to implement callbacks on main Qprocess signals
    """

    def __init__(self, initfname, outfname, logfname, analyzerpath):
        # XXX move analyzerpath to config class?
        QtCore.QProcess.__init__(self)
        # Qprocess signal handlers
        self.error.connect(self.procanalyzer_on_error)
        self.stateChanged.connect(self.procanalyzer_on_state_change)
        self.started.connect(self.procanalyzer_on_start)
        self.finished.connect(self.procanalyzer_on_finish)

        self.initfname = initfname
        self.outfname = outfname
        self.logfname = logfname
        self.analyzerpath = analyzerpath

    def run(self):
        cmdline = "%s %s --inifile %s --outfile %s --logfile %s" % (
            os.path.join(PYTHON_PATH, PYTHON_BIN),
            self.analyzerpath, self.initfname, self.outfname, self.logfname)
        # start the process
        try:
            idaapi.msg(
                "[+] BinCAT: Analyzer cmdline is:\n  %s \n " % cmdline)
            self.start(cmdline)
            idaapi.msg("[+] Analyzer started\n")

        except Exception as e:
            idaapi.msg("[+] BinCAT failed to launch the analyzer.py\n")
            idaapi.msg("    Exception: %s\n%s" % (str(e),
                                                  traceback.format_exc()))

    def procanalyzer_on_error(self, error):
        errors = ["Failed to start", "Crashed", "TimedOut", "Read Error",
                  "Write Error", "Unknown Error"]
        idaapi.msg("[+] Analyzer error: %s\n" % errors[error])

    def procanalyzer_on_state_change(self, new_state):
        states = ["Not running", "Starting", "Running"]
        idaapi.msg("[+] Analyzer new state: %s\n" % states[new_state])

    def procanalyzer_on_start(self):
        BinCATLogViewer.Log("[*] Analyzer:  starting process \n",
                            idaapi.SCOLOR_DNAME)

    def procanalyzer_on_finish(self):
        idaapi.msg("[+] Analyzer process terminated \n")

        BinCATLogViewer.Log("[+] BinCAT: Parsing analyzer result file\n",
                            idaapi.SCOLOR_LOCNAME)

        ibcState.program = program.Program.parse(self.outfname,
                                                 logs=self.logfname)
        # Update current RVA to start address (nodeid = 0)
        startaddr_ea = ""
        keys = ibcState.program.states.keys()
        for k in keys:
            state = ibcState.program[k.value]
            if state.node_id == "0":
                startaddr_ea = k.value
                break

        ibcState.setCurrentEA(startaddr_ea, force=True)


class BinCATLog_t(idaapi.simplecustviewer_t):
    """
    BinCAT log viewer
    """
    def Create(self, sn=None):
        # Form title
        title = "BinCAT Log viewer"
        idaapi.msg("[+] BinCAT log view created \n")
        # create the custom view
        if not idaapi.simplecustviewer_t.Create(self, title):
            return False

        return True

    def Log(self, LogLine, color):
        coloredline = idaapi.COLSTR(LogLine, color)
        self.AddLine(coloredline)
        self.Refresh()


class BinCATTaintedForm_t(idaapi.PluginForm):
    """
    BinCAT Tainted values form
    This form containes the values of tainted registers and memory
    """

    def OnCreate(self, form):
        BinCATLogViewer.Log("[+] BinCAT Creating Tainted form ",
                            idaapi.SCOLOR_LOCNAME)

        self.currentrva = 0

        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        layout = QtWidgets.QGridLayout()

        splitter = QtWidgets.QSplitter()
        layout.addWidget(splitter, 0, 0)
        # Node id label
        self.nilabel = QtWidgets.QLabel('Node Id:')
        splitter.addWidget(self.nilabel)

        # RVA address label
        self.alabel = QtWidgets.QLabel('RVA address:')
        splitter.addWidget(self.alabel)

        # Value Taint Table
        self.vttable = QtWidgets.QTableView()
        self.vttable.setSortingEnabled(True)
        self.vttable.setModel(ibcState.vtmodel)
        self.vttable.verticalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)

        self.vttable.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.Stretch)

        layout.addWidget(self.vttable, 1, 0)

        layout.setRowStretch(1, 0)

        self.parent.setLayout(layout)

    # Called when the plugin form is closed
    def OnClose(self, form):
        BinCATLogViewer.Log("[+] BinCAT Closing Tainted form ",
                            idaapi.SCOLOR_LOCNAME)

    def Show(self):
        return idaapi.PluginForm.Show(
            self, "BinCAT Tainting",
            options=(idaapi.PluginForm.FORM_PERSIST |
                     idaapi.PluginForm.FORM_TAB))

    def updateCurrentEA(self, ea):
        self.alabel.setText('RVA: 0x%08x' % ea)
        state = ibcState.currentState
        if state:
            self.nilabel.setText('Node Id: %s' % state.node_id)
        else:
            self.nilabel.setText('No data')


class ValueTaintModel(QtCore.QAbstractTableModel):
    """
    Used as model in BinCATTaintedForm TableView widgets.

    Contains tainting and values for either registers or memory addresses
    """
    def __init__(self, *args, **kwargs):
        self.headers = ["Address", "Region", "Value", "Taint"]
        self.colswidths = [50, 50, 90, 90]
        #: list of (region, addr)
        self.rows = []
        super(ValueTaintModel, self).__init__(*args, **kwargs)

    def endResetModel(self):
        """
        Rebuild a list of rows
        """
        state = ibcState.currentState
        self.rows = []
        if state:
            for region in state.regions:
                for addrs in state.regions[region]:
                    self.rows.append((region, addrs))
            self.rows.sort()

        super(ValueTaintModel, self).endResetModel()

    def headerData(self, section, orientation, role):
        if orientation != QtCore.Qt.Horizontal:
            return
        if role == QtCore.Qt.DisplayRole:
            return self.headers[section]
        elif role == QtCore.Qt.SizeHintRole:
            return QtCore.QSize(self.colswidths[section], 20)

    def data(self, index, role):
        if role != QtCore.Qt.DisplayRole:
            return
        col = index.column()
        if role == QtCore.Qt.SizeHintRole:
            return QtCore.QSize(self.colswidths[col], 20)
        region, addr = self.rows[index.row()]
        if col == 0:  # addr
            return str(addr)
        elif col == 1:  # region
            return region
        else:
            v = ibcState.currentState[region][addr]
            if not v:
                return ""
        if col == 2:  # value
            return v.__valuerepr__()
        elif col == 3:  # taint
            return v.__taintrepr__()

    def rowCount(self, parent):
        return len(self.rows)

    def columnCount(self, parent):
        return len(self.headers)


class BinCATForm_t(idaapi.PluginForm):
    """
    BinCAT main IDA PluginForm
    """

    # handler for btnNewAnalyzer
    def handler_btnNewAnalyzer(self):
        options = QtWidgets.QFileDialog.Options()
        fname = QtWidgets.QFileDialog.getOpenFileName(
            self.parent, 'Open file', idc.GetIdaDirectory(),
            "Python files (*.py)", options=options)
        if fname:
            self.iptAnalyzerPath.setText(fname[0])

    def handler_btnAnalyzerConfig(self):
        # Call AnalyzerConfForm_t
        bAc = AnalyzerConfForm_t(self.parent)
        bAc.show()
        idaapi.msg("handler_btnAnalyzerConfig()\n")

    def handler_restartAnalyzer(self):
        # check if the field is not empty
        if not self.iptAnalyzerPath.text():
            BinCATLogViewer.Log(
                "[+] BinCAT new analyzer path is empty.",
                idaapi.SCOLOR_LOCNAME)
            idaapi.warning(
                "BinCAT: The analyer could not be started: new path is empty.")
        else:
            try:
                with open(self.iptAnalyzerPath.text()) as f:
                    # TODO check if the analyer.py is the correct stub
                    BinCATLogViewer.Log("[+] BinCAT: restarting analyzer.",
                                        idaapi.SCOLOR_LOCNAME)
                    self.init_Analyzer()

            except:
                BinCATLogViewer.Log(
                    "[+] BinCAT new analyzer file could not be opened.",
                    idaapi.SCOLOR_LOCNAME)
                idaapi.warning(
                    "BinCAT: The analyer could not be started: "
                    "file not found.")

        idaapi.msg("[+] BinCAT: new analyzer path %s.\n " %
                   self.iptAnalyzerPath.text())

    # Called when the plugin form is created
    def OnCreate(self, form):
        idaapi.msg("[+] BinCAT form created\n")
        BinCATLogViewer.Log("[+] BinCAT form created", idaapi.SCOLOR_LOCNAME)

        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)

        # create a label
        label = QtWidgets.QLabel('IDB file:')

        # create an input box
        self.input = QtWidgets.QLineEdit(self.parent)
        self.input.setText(idc.GetIdbPath())
        self.input.setMaxLength = 256
        self.input.setFixedWidth(300)

        # create label: analyzer path
        lblAnalyzerPath = QtWidgets.QLabel('Analyzer path:')

        # create input: analyzer path
        self.iptAnalyzerPath = QtWidgets.QLineEdit(self.parent)

        defaultAnalyzerFile = os.path.join(os.path.dirname(__file__),
                                           'analyzer.py')
        self.iptAnalyzerPath.setText(defaultAnalyzerFile)
        self.iptAnalyzerPath.setMaxLength = 256
        self.iptAnalyzerPath.setFixedWidth(300)

        # button to choose another analyer
        self.btnNewAnalyzer = QtWidgets.QPushButton('...', self.parent)
        self.btnNewAnalyzer.setToolTip('set a new analyzer.py path')
        self.btnNewAnalyzer.clicked.connect(self.handler_btnNewAnalyzer)

        # restart button for the analyzer
        self.btnAnalyzer = QtWidgets.QPushButton('restart', self.parent)
        self.btnAnalyzer.setToolTip('restart analyzer.')
        self.btnAnalyzer.setFixedWidth(150)
        self.btnAnalyzer.clicked.connect(self.handler_restartAnalyzer)

        # create a button for analyzer configuration form
        self.btnAnalyzerConfig = QtWidgets.QPushButton(
            'Analyzer configuration', self.parent)
        self.btnAnalyzerConfig.clicked.connect(self.handler_btnAnalyzerConfig)

        # create a Layout
        layout = QtWidgets.QGridLayout()
        layout.addWidget(label, 0, 0)
        layout.addWidget(self.input, 0, 1)
        layout.addWidget(lblAnalyzerPath, 1, 0)
        layout.addWidget(self.iptAnalyzerPath, 1, 1)
        layout.addWidget(self.btnAnalyzer, 1, 3)
        layout.addWidget(self.btnNewAnalyzer, 1, 2)
        layout.addWidget(self.btnAnalyzerConfig, 2, 0)

        layout.setColumnStretch(4, 1)
        layout.setRowStretch(3, 1)

        self.parent.setLayout(layout)

    # Called when the plugin form is closed
    def OnClose(self, form):
        idaapi.msg("[+] BinCAT form closed\n")
        BinCATLogViewer.Log("[+] BinCAT form closed", idaapi.SCOLOR_LOCNAME)

        global BinCATForm
        del BinCATForm

        # f = idaapi.find_tform("BinCAT Log viewer")
        # if f:
        # idaapi.close_tform(f, 0)

    def Show(self):
        return idaapi.PluginForm.Show(
            self, "BinCAT Configuration",
            options=(idaapi.PluginForm.FORM_PERSIST |
                     idaapi.PluginForm.FORM_TAB))


class HtooltipT(idaapi.action_handler_t):
    """
    Action handler for BinCAT/ Taint current basic bloc
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        # idaapi.msg(" activating HtooltipT ")
        # idaapi.warning(" BinCAT: Tainting current Basic Bloc")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class HtooltipF(idaapi.action_handler_t):
    """
    Action handler for BinCAT/ Taint current function
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        # idaapi.msg(" activating HtooltipF ")
        # idaapi.warning(" BinCAT: Tainting current Function")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class HtooltipH(idaapi.action_handler_t):
    """
    Action handler for BinCAT/ Taint from here
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        idaapi.msg(" activating HtooltipH ")
        # idaapi.warning(" BinCAT: Tainting from current position: %08x " %
        # here())
        # idaview =
        # idaapi.PluginForm.FormToPyQtWidget(get_tform_idaview(ctx.form))
        f = idaapi.find_tform("IDA View-Tainting View")
        idaview = idaapi.PluginForm.FormToPyQtWidget(f)
        AnalyzerLauncher = TaintLaunchForm_t(idaview)
        AnalyzerLauncher.exec_()

        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class Hooks(idaapi.UI_Hooks):
    """
    Class Hooks for BinCAT menu
    """

    def updating_actions(self, ctx):
        if ctx.form_type == idaapi.BWN_DISASM:
            idaview = idaapi.get_tform_idaview(ctx.form)
            place, x, y = idaapi.get_custom_viewer_place(idaview, False)
            # line =  get_custom_viewer_curline(idaview, False)
            if ctx.form_title == "IDA View-Tainting View":
                if idaapi.isCode(idaapi.getFlags(place.toea())):
                    # SetColor(place.toea(), CIC_ITEM, 0x0CE505)
                    # idaapi.set_item_color(place.toea(), 0x23ffff)

                    idaapi.msg("%s at EA: 0x%08x \n" %
                               (ctx.form_title, place.toea()))
                    ibcState.setCurrentEA(place.toea())
                    idaapi.msg("EA: 0x%08x \n" % (place.toea()))

    def populating_tform_popup(self, form, popup):
        # idaapi.attach_action_to_popup(form, popup, "my:tooltip0",
        #                               "BinCAT/Tainting/", idaapi.SETMENU_APP)
        # idaapi.attach_action_to_popup(form, popup, "my:tooltip1",
        #                               "BinCAT/Tainting/", idaapi.SETMENU_APP)
        idaapi.attach_action_to_popup(form, popup, "my:tooltip2",
                                      "BinCAT/", idaapi.SETMENU_APP)


class PluginState():
    """
    Container for plugin state related data & methods.
    """
    def __init__(self):
        self.vtmodel = ValueTaintModel()
        self.currentEA = None
        self.program = None
        self.currentState = None
        self.currentConfig = AnalyzerConfig()
        # Analyzer instance
        self.analyzer = None

    def setCurrentEA(self, ea, force=False):
        idaapi.msg("setCurrent %s" % ea)
        if not (force or ea != self.currentEA):
            return
        self.vtmodel.beginResetModel()
        self.currentEA = ea
        if self.program:
            self.currentState = self.program[ea]
        BinCATTaintedForm.updateCurrentEA(ea)
        self.vtmodel.endResetModel()


def main():
    idaapi.msg("[+] BinCAT plugin loaded\n")
    if not idaapi.get_root_filename():
        idaapi.msg("[BinCAT] please load a file/idb before \n")
        return
    # TODO remove unnecessary globals
    global registers_x86
    global BinCATForm
    global BinCATLogViewer
    global hooks
    global BinCATTaintedForm

    BinCATLogViewer = BinCATLog_t()

    BinCATForm = BinCATForm_t()
    BinCATTaintedForm = BinCATTaintedForm_t()

    #: IDA BinCAT plugin state.
    global ibcState
    ibcState = PluginState()

    idaapi.msg("[+] BinCAT Starting main form\n")
    if BinCATLogViewer.Create(1):
        BinCATLogViewer.Show()
        idaapi.set_dock_pos("BinCAT Log viewer", "Output window",
                            idaapi.DP_LEFT)
        BinCATLogViewer.Log("[+] BinCAT Starting main form",
                            idaapi.SCOLOR_LOCNAME)

    BinCATForm.Show()
    BinCATTaintedForm.Show()
    # TODO: get the list of registers from IDA depending on the current cpu
    # arch
    registers_x86 = ['EAX', 'EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'ESP', 'EBP']

    idaapi.set_dock_pos("BinCAT", "IDA View-A", idaapi.DP_TAB)

    # We create a disassembly view dedicated to BinCAT
    idaapi.open_disasm_window("Tainting View")
    idaapi.set_dock_pos("IDA View-Tainting View", "IDA View-A", idaapi.DP_TAB)
    idaapi.set_dock_pos("BinCAT Tainting", "Functions window", idaapi.DP_TAB)

    # set the focus to BinCAT view
    ida_bincat_view = idaapi.find_tform("BinCAT")
    idaapi.switchto_tform(ida_bincat_view, 1)

    # creating BinCAT menu
    BinCATLogViewer.Log("[+] BinCAT Creating Menus ", idaapi.SCOLOR_LOCNAME)
    # tooltip_act0 = idaapi.action_desc_t(
    #     'my:tooltip0', 'BinCAT: Taint this basic bloc', HtooltipT(), '',
    #     'BinCAT action', -1)
    # tooltip_act1 = idaapi.action_desc_t(
    #     'my:tooltip1', 'BinCAT: Taint this function', HtooltipF(), '',
    #     'BinCAT action', -1)
    tooltip_act2 = idaapi.action_desc_t(
        'my:tooltip2', 'Analyze from here', HtooltipH(), '',
        'BinCAT action', -1)

    # Registering BinCAT actions
    # idaapi.register_action(tooltip_act0)
    # idaapi.register_action(tooltip_act1)
    idaapi.register_action(tooltip_act2)

    idaapi.attach_action_to_menu("View/", "my:tooltip0", idaapi.SETMENU_APP)

    BinCATLogViewer.Log("[+] BinCAT Setting Menu Hooks ",
                        idaapi.SCOLOR_LOCNAME)

    try:
        hooks.unhook()
        hooks = None
        idaapi.msg("unhooked")

    except:
        hooks = Hooks()
        hooks.hook()

# ----------------------------------------------------------------------------------------------

if __name__ == "__main__":
    main()
