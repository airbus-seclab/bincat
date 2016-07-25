# version IDA 6.9
# runs the "bincat" command from ida

import os
import sys
import traceback
import ConfigParser
import tempfile
import StringIO

import idaapi
import idc
import idautils

try:
    from PyQt5 import QtCore, QtWidgets, QtGui
except:
    idaapi.warning(
        "[BinCAT] Failed to load Qt libs from PyQt5 \n%s\n" %
        repr(sys.exc_info()))


class bincat_plugin(idaapi.plugin_t):
    # variables required by IDA
    flags = 0  # normal plugin
    wanted_name = "BinCAT Plugin"
    wanted_hotkey = "Ctrl-Shift-B"
    comment = "Interface to the BinCAT analyzer"
    help = ""
    initialized = False

    # IDA API methods: init, run, term
    def init(self):
        # Loading Qt packages

        try:
            from pybincat import cfa as cfa_module
            global cfa_module
        except:
            idaapi.warning(
                "[BinCAT] Failed to load 'pybincat.cfa' python module\n%s\n" %
                repr(sys.exc_info()))
            return idaapi.PLUGIN_SKIP
        return idaapi.PLUGIN_OK

    def run(self, args):
        if self.initialized:
            return
        self.initialized = True

        PluginState.log_panel = BinCATLog_t()
        if PluginState.log_panel.Create(1):
            PluginState.log_panel.Show()
            idaapi.set_dock_pos("BinCAT Log viewer", "Output window",
                                idaapi.DP_LEFT)

        PluginState.BinCATTaintedForm = BinCATTaintedForm_t()
        PluginState.BinCATTaintedForm.Show()

        PluginState.BinCATStatementsForm = BinCATStatementsForm_t()
        PluginState.BinCATStatementsForm.Show()

        idaapi.set_dock_pos("BinCAT", "IDA View-A", idaapi.DP_TAB)

        # TODO : change to menu item ?
        tooltip_act2 = idaapi.action_desc_t(
            'my:tooltip2', 'Analyze from here', handle_analyze_here(), 'Ctrl-Shift-A',
            'BinCAT action', -1)
        idaapi.register_action(tooltip_act2)

        idaapi.attach_action_to_menu("View/", "my:tooltip0",
                                     idaapi.SETMENU_APP)
        PluginState.hooks = Hooks()
        PluginState.hooks.hook()

        info("IDABinCAT ready.")

    def term(self):
        if PluginState.hooks:
            PluginState.hooks.unhook()
            PluginState.hooks = None


# Logging methods
def info(msg):
    PluginState.log_panel.Log(msg, idaapi.SCOLOR_DEFAULT)


def important_info(msg):
    idaapi.msg("[BinCAT] %s" % msg)
    PluginState.log_panel.Log(msg, idaapi.SCOLOR_LOCNAME)


def warning(msg):
    idaapi.msg("[BinCAT] WARNING: %s" % msg)
    PluginState.log_panel.Log(msg, idaapi.SCOLOR_ERROR)


def error(msg):
    idaapi.msg("[BinCAT] ERROR: %s" % msg)
    PluginState.log_panel.Log(msg, idaapi.SCOLOR_ERROR)


class AnalyzerConfig(object):
    """
    Generates a configuration file for the analyzer.
    """
    def __init__(self):
        self.version = "0.0"
        #: int
        self.code_length = None
        #: int
        self.entrypoint = None

    @property
    def rva_code(self):
        rva, _ = self.getCodeSection(self.entrypoint)
        return rva

    def __str__(self):
        sio = StringIO.StringIO()
        self.getConfigParser().write(sio)
        sio.seek(0)
        return sio.read()

    def setStartStopAddr(self, start, stop):
        self.entrypoint = start
        self.code_length = stop - self.rva_code

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

    def getCodeSection(self, entrypoint):
        # in case we have more than one code section we apply the following:
        # heuristic entry point must be in the code section

        for seg in idautils.Segments():
            seg_attributes = idc.GetSegmentAttr(idc.SegStart(seg),
                                                idc.SEGATTR_TYPE)
            start = idc.SegStart(seg)
            end = idc.SegEnd(seg)
            if (seg_attributes == idaapi.SEG_CODE and
                    start <= entrypoint <= end):
                break
        else:
            error(
                "BinCAT no code section has been found for entrypoint %#08x\n"
                % entrypoint)
            return -1, -1
        info("Code section found at %#x:%#x\n" % (start, end))
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
            warning("no Data section has been found")
            return -1, -1
        info("Data section found at %#x:%#x " % (start, end))
        return start, end

    def getConfigParser(self):
        """
        Returns a new ConfigParser instance
        """
        # this function will use the default parameters
        config = ConfigParser.RawConfigParser()
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
        config.set('loader', 'entrypoint', hex(self.entrypoint))

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
        config.set('libc', 'call-conv', 'fastcall')
        config.set('libc', '*', 'open(@, _)')
        config.set('libc', '*', 'read<stdcall>(@, *, @)')
        return config

    def write(self, filepath):
        with open(filepath, 'w') as configfile:
            self.getConfigParser().write(configfile)


class EditConfigurationFileForm_t(QtWidgets.QDialog):
    def __init__(self, parent):
        super(EditConfigurationFileForm_t, self).__init__(parent)
        layout = QtWidgets.QGridLayout()

        self.configtxt = QtWidgets.QPlainTextEdit()
        self.configtxt.setSizePolicy(QtWidgets.QSizePolicy.Expanding,
                                     QtWidgets.QSizePolicy.Expanding)

        self.btnStart = QtWidgets.QPushButton('&Start', self)
#        self.btnStart.setFixedWidth(130)
        self.btnStart.clicked.connect(self.btnLaunchAnalyzer)

        self.btnCancel = QtWidgets.QPushButton('Cancel', self)
#        self.btnCancel.setFixedWidth(130)
        self.btnCancel.clicked.connect(self.close)

        layout.addWidget(self.configtxt, 1, 0, 1, 0)
        layout.addWidget(self.btnStart, 2, 0)
        layout.addWidget(self.btnCancel, 2, 1)
        self.setLayout(layout)

    def set_addresses(self, startAddr, stopAddr):
        startAddr = int(self.parent().ipStartAddr.text(), 16)
        stopAddr = int(self.parent().ipStopAddr.text(), 16)
        PluginState.currentConfig.setStartStopAddr(startAddr, stopAddr)
        self.configtxt.appendPlainText(str(PluginState.currentConfig))

    def set_config(self, config_txt):
        self.configtxt.appendPlainText(config_txt)

    def btnLaunchAnalyzer(self):
        PluginState.startAnalysis(self.configtxt.toPlainText())
        self.close()

    def show(self):
        self.setFixedSize(1000, 400)
        self.setWindowTitle("Edit configuration")
        super(TaintLaunchForm_t, self).show()


class TaintLaunchForm_t(QtWidgets.QDialog):

    def rbRegistersHandler(self):
        self.cbRegisters.setEnabled(True)

    def rbMemoryHandler(self):
        self.ipMemory.setEnabled(True)

    def cbRegistersHandler(self, text):
        info("selected register is %s \n " % text)

    def launch_analysis(self):
        important_info("Launching the analyzer\n")
        # Test if stop address is not empty
        if not self.ipStopAddr.text():
            idaapi.warning(" Stop address is empty")
            return
        startAddr = int(self.ipStartAddr.text(), 16)
        stopAddr = int(self.ipStopAddr.text(), 16)
        PluginState.currentConfig.setStartStopAddr(startAddr, stopAddr)
        PluginState.startAnalysis()

        self.close()

    def edit_config(self):
        # display edit form
        startAddr = int(self.ipStartAddr.text(), 16)
        stopAddr = int(self.ipStopAddr.text(), 16)
        editdlg = EditConfigurationFileForm_t(self)
        editdlg.set_addresses(startAddr, stopAddr)
        editdlg.exec_()

    def choose_file(self):
        options = QtWidgets.QFileDialog.Options()
        default_filename = os.path.join(os.path.dirname(__file__),
                                        'init.ini')
        filename, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Choose configuration file", default_filename,
            "Configuration files (*.ini)", options=options)
        if not filename or not os.path.exists(filename):
            return
        editdlg = EditConfigurationFileForm_t(self)
        editdlg.set_config(open(filename, 'r').read())
        editdlg.exec_()
        self.close()

    def __init__(self, parent):
        super(TaintLaunchForm_t, self).__init__(parent)

        layout = QtWidgets.QGridLayout()
        lblCstEditor = QtWidgets.QLabel("BinCAT analysis parameters")
        PluginState.currentEA = idc.here()

        # Start address
        lblStartAddr = QtWidgets.QLabel(" Start address: ")
        self.ipStartAddr = QtWidgets.QLineEdit(self)
        self.ipStartAddr.setText(hex(PluginState.currentEA).rstrip('L'))

        # Use current basic block address as default stop address
        stopAddr = ""
        for block in idaapi.FlowChart(idaapi.get_func(idc.here())):
            if block.startEA <= PluginState.currentEA <= block.endEA:
                stopAddr = hex(block.endEA).rstrip('L')
        lblStopAddr = QtWidgets.QLabel(" Stop address: ")
        self.ipStopAddr = QtWidgets.QLineEdit(self)
        self.ipStopAddr.setText(stopAddr)

        # Start, cancel and analyzer config buttons
        self.btnLoad = QtWidgets.QPushButton('&Load configuration file...',
                                             self)
        self.btnLoad.clicked.connect(self.choose_file)

        self.btnEditConf = QtWidgets.QPushButton('&Edit configuration...',
                                                 self)
        self.btnEditConf.clicked.connect(self.edit_config)

        self.btnStart = QtWidgets.QPushButton('&Start', self)
        self.btnStart.clicked.connect(self.launch_analysis)

        self.btnCancel = QtWidgets.QPushButton('Cancel', self)
        self.btnCancel.clicked.connect(self.close)

        layout.addWidget(lblCstEditor, 0, 0)

        layout.addWidget(lblStartAddr, 1, 0)
        layout.addWidget(self.ipStartAddr, 1, 1)

        layout.addWidget(lblStopAddr, 2, 0)
        layout.addWidget(self.ipStopAddr, 2, 1)

        layout.addWidget(self.btnLoad, 3, 0)
        layout.addWidget(self.btnEditConf, 3, 1)

        layout.addWidget(self.btnStart, 4, 0)
        layout.addWidget(self.btnCancel, 4, 1)

        self.setLayout(layout)

        self.btnStart.setFocus()

    def show(self):
        self.setFixedSize(460, 200)
        self.setWindowTitle(" Analysis launcher: ")
        super(TaintLaunchForm_t, self).show()


class Analyzer(QtCore.QProcess):
    """
    Class Analyzer that inherits from Qprocess

    The idea is to implement callbacks on main Qprocess signals
    """

    def __init__(self, initfname, outfname, logfname):
        QtCore.QProcess.__init__(self)
        # Qprocess signal handlers
        self.error.connect(self.procanalyzer_on_error)
        self.stateChanged.connect(self.procanalyzer_on_state_change)
        self.started.connect(self.procanalyzer_on_start)
        self.finished.connect(self.procanalyzer_on_finish)

        self.initfname = initfname
        self.outfname = outfname
        self.logfname = logfname

    def run(self):
        cmdline = "bincat %s %s %s" % (self.initfname, self.outfname,
                                       self.logfname)
        # start the process
        info("Analyzer cmdline: [%s]" % cmdline)
        try:
            self.start(cmdline)
        except Exception as e:
            error("BinCAT failed to launch the analyzer.py\n")
            info("Exception: %s\n%s" % (str(e), traceback.format_exc()))
        else:
            info("Analyzer started\n")

    def procanalyzer_on_error(self, err):
        errors = ["Failed to start", "Crashed", "TimedOut", "Read Error",
                  "Write Error", "Unknown Error"]
        try:
            errtxt = errors[err]
        except IndexError:
            errtxt = "Unspecified error %s" % err
        error("Analyzer error: %s\n" % errtxt)

    def procanalyzer_on_state_change(self, new_state):
        states = ["Not running", "Starting", "Running"]
        info("Analyzer new state: %s\n" % states[new_state])

    def procanalyzer_on_start(self):
        important_info("Analyzer: starting process\n")

    def procanalyzer_on_finish(self):
        important_info("Analyzer process terminated \n")
        exitcode = self.exitCode()
        if exitcode == 0:
            info("Parsing analyzer result file\n")

            PluginState.cfa = cfa_module.CFA.parse(self.outfname,
                                                   logs=self.logfname)
            # Update current RVA to start address (nodeid = 0)
            node0 = PluginState.cfa['0']

            startaddr_ea = node0.address.value
            PluginState.setCurrentEA(startaddr_ea, force=True)
        else:
            error("analyzer returned exit code=%i\n" % exitcode)
            important_info("---- stdout ----------------\n")
            important_info(str(self.readAllStandardOutput()))
            important_info("---- stderr ----------------\n")
            important_info(str(self.readAllStandardError()))
        info("---- logfile ---------------\n")
        if os.path.exists(self.logfname):
            info(open(self.logfname).read())
        info("----------------------------\n")


class BinCATLog_t(idaapi.simplecustviewer_t):
    """
    BinCAT log viewer
    """
    def Create(self, sn=None):
        # Form title
        title = "BinCAT Log viewer"
        # create the custom view
        if not idaapi.simplecustviewer_t.Create(self, title):
            return False

        return True

    def Log(self, LogLine, color):
        for l in LogLine.splitlines():
            coloredline = idaapi.COLSTR(l, color)
            self.AddLine(coloredline)
        self.Refresh()


class BinCATStatementsForm_t(idaapi.PluginForm):
    """
    BinCAT Statements form.
    """
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.listview = QtWidgets.QListView()
        self.listview.setModel(PluginState.stmtmodel)
        layout = QtWidgets.QGridLayout()
        layout.addWidget(self.listview, 0, 0)
        self.parent.setLayout(layout)

    def OnClose(self, form):
        pass

    def Show(self):
        return idaapi.PluginForm.Show(
            self, "BinCAT Statements",
            options=(idaapi.PluginForm.FORM_PERSIST |
                     idaapi.PluginForm.FORM_TAB))


class BinCATTaintedForm_t(idaapi.PluginForm):
    """
    BinCAT Tainted values form
    This form containes the values of tainted registers and memory
    """

    def OnCreate(self, form):
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
        self.vttable.setModel(PluginState.vtmodel)
        self.vttable.verticalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)

        self.vttable.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.Interactive)

        layout.addWidget(self.vttable, 1, 0)

        layout.setRowStretch(1, 0)

        self.parent.setLayout(layout)

    def OnClose(self, form):
        pass

    def Show(self):
        return idaapi.PluginForm.Show(
            self, "BinCAT Tainting",
            options=(idaapi.PluginForm.FORM_PERSIST |
                     idaapi.PluginForm.FORM_TAB))

    def updateCurrentEA(self, ea):
        """
        :param ea: int or long
        """
        self.alabel.setText('RVA: 0x%08x' % ea)
        state = PluginState.currentState
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
        self.colswidths = [90, 90, 150, 150]
        #: list of Value (addresses)
        self.rows = []
        self.changedRows = set()
        self.diffFont = QtGui.QFont()
        self.diffFont.setBold(True)
        super(ValueTaintModel, self).__init__(*args, **kwargs)

    def endResetModel(self):
        """
        Rebuild a list of rows
        """
        state = PluginState.currentState
        #: list of Values (addresses)
        self.rows = []
        self.changedRows = set()
        if state:
            self.rows = sorted(state.regaddrs)

            # find parent state
            parents = [nodeid for nodeid in PluginState.cfa.edges
                       if state.node_id in PluginState.cfa.edges[nodeid]]
            for pnode in parents:
                pstate = PluginState.cfa[pnode]
                for k in state.list_modified_keys(pstate):
                    if k in self.rows:
                        self.changedRows.add(self.rows.index(k))

        super(ValueTaintModel, self).endResetModel()

    def headerData(self, section, orientation, role):
        if orientation != QtCore.Qt.Horizontal:
            return
        if role == QtCore.Qt.DisplayRole:
            return self.headers[section]
        elif role == QtCore.Qt.SizeHintRole:
            return QtCore.QSize(self.colswidths[section], 20)

    def data(self, index, role):
        col = index.column()
        if role == QtCore.Qt.SizeHintRole:
            # XXX not obeyed. why?
            return QtCore.QSize(self.colswidths[col], 20)
        elif role == QtCore.Qt.FontRole:
            if index.row() in self.changedRows:
                return self.diffFont
            else:
                return
        elif role != QtCore.Qt.DisplayRole:
            return
        regaddr = self.rows[index.row()]
        region = regaddr.region
        addr = regaddr.value
        if col == 0:  # addr
            if region == "mem":
                return "0x%x" % addr
            else:
                return str(addr)
        elif col == 1:  # region
            return region
        else:
            v = PluginState.currentState[regaddr]
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


class handle_analyze_block(idaapi.action_handler_t):
    """
    Action handler for BinCAT/ Taint current basic block
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class handle_analyze_func(idaapi.action_handler_t):
    """
    Action handler for BinCAT/ Taint current function
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class handle_analyze_here(idaapi.action_handler_t):
    """
    Action handler for BinCAT/ Taint from here
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
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
            if idaapi.isCode(idaapi.getFlags(place.toea())):
                # SetColor(place.toea(), CIC_ITEM, 0x0CE505)
                # idaapi.set_item_color(place.toea(), 0x23ffff)

                PluginState.setCurrentEA(place.toea())

    def populating_tform_popup(self, form, popup):
        if idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(form, popup, "my:tooltip2",
                                          "BinCAT/", idaapi.SETMENU_APP)


class PluginState(object):
    """
    Container for (static) plugin state related data & methods.
    """
    log_panel = None
    vtmodel = ValueTaintModel()
    stmtmodel = QtCore.QStringListModel()
    currentEA = None
    cfa = None
    currentState = None
    currentConfig = AnalyzerConfig()
    #: Analyzer instance
    analyzer = None
    BinCATTaintedForm = None
    hooks = None

    @staticmethod
    def setCurrentEA(ea, force=False):
        """
        :param ea: int or long
        """
        if not (force or ea != PluginState.currentEA):
            return
        PluginState.vtmodel.beginResetModel()
        PluginState.currentEA = ea
        if PluginState.cfa:
            node_ids = PluginState.cfa.node_id_from_addr(ea)
            if node_ids:
                # XXX add UI to choose state when several exist at this address
                PluginState.currentState = PluginState.cfa[node_ids[0]]
                PluginState.stmtmodel.setStringList(
                    PluginState.currentState.statements)
            else:
                PluginState.currentState = None
                PluginState.stmtmodel.setStringList([])
        PluginState.BinCATTaintedForm.updateCurrentEA(ea)
        PluginState.vtmodel.endResetModel()

    @staticmethod
    def startAnalysis(configStr=None):
        path = tempfile.mkdtemp(suffix='bincat')
        initfname = os.path.join(path, "init.ini")
        outfname = os.path.join(path, "out.ini")
        logfname = os.path.join(path, "analyzer.log")

        info("Current analyzer path: %s \n" % path)

        if configStr:
            with open(initfname, 'wb') as f:
                f.write(configStr)
        else:
            PluginState.currentConfig.write(initfname)

        PluginState.analyzer = Analyzer(initfname, outfname, logfname)
        PluginState.analyzer.run()


def PLUGIN_ENTRY():
    return bincat_plugin()
