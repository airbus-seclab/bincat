# -*- coding: utf-8 -*-
# version IDA 6.9
# runs the "bincat" command from ida

import os
import sys
import traceback
import tempfile
import logging
import idaapi
from idabincat.analyzer_conf import AnalyzerConfig

try:
    from PyQt5 import QtCore, QtWidgets, QtGui
except:
    idaapi.warning(
        "[BinCAT] Failed to load Qt libs from PyQt5 \n%s\n" %
        repr(sys.exc_info()))

# Logging
logging.basicConfig(level=logging.DEBUG)
bc_log = logging.getLogger('bincat')
bc_log.setLevel(logging.DEBUG)


class bincat_plugin(idaapi.plugin_t):
    # variables required by IDA
    flags = 0  # normal plugin
    wanted_name = "BinCAT"
    wanted_hotkey = "Ctrl-Shift-B"
    comment = "Interface to the BinCAT analyzer"
    help = ""
    initialized = False

    # IDA API methods: init, run, term
    def init(self):

        try:
            from pybincat import cfa as cfa_module
            global cfa_module
        except:
            bc_log.warning(
                "Failed to load 'pybincat.cfa' python module\n%s",
                repr(sys.exc_info()))
            return idaapi.PLUGIN_SKIP
        return idaapi.PLUGIN_OK

    def run(self, args):
        if self.initialized:
            return
        self.initialized = True

        PluginState.BinCATTaintedForm = BinCATTaintedForm_t()
        PluginState.BinCATTaintedForm.Show()

        PluginState.BinCATDebugForm = BinCATDebugForm_t()
        PluginState.BinCATDebugForm.Show()

        idaapi.set_dock_pos("BinCAT", "IDA View-A", idaapi.DP_TAB)

        # TODO : change to menu item ?
        ana_from_here_act = idaapi.action_desc_t(
            'bincat:ana_from_here', 'Analyze from here', handle_analyze_here(),
            'Ctrl-Shift-A', 'BinCAT action', -1)
        idaapi.register_action(ana_from_here_act)

        idaapi.attach_action_to_menu("Edit/BinCAT", "bincat:ana_from_here",
                                     idaapi.SETMENU_APP)
        PluginState.hooks = Hooks()
        PluginState.hooks.hook()

        bc_log.info("IDABinCAT ready.")

    def term(self):
        if PluginState.hooks:
            PluginState.hooks.unhook()
            PluginState.hooks = None


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


class BinCATConfigForm_t(QtWidgets.QDialog):

    def __init__(self, parent):
        super(BinCATConfigForm_t, self).__init__(parent)

        layout = QtWidgets.QGridLayout()

        lblDefaultBhv = QtWidgets.QLabel("Default behaviour")
        # Save config in IDB
        self.chkSave = QtWidgets.QCheckBox('&Save configuration to IDB',
                                           self)
        self.chkLoad = QtWidgets.QCheckBox('&Load configuration from IDB',
                                           self)

        self.btnStart = QtWidgets.QPushButton('&Save', self)
        self.btnStart.clicked.connect(self.save_config)

        self.btnCancel = QtWidgets.QPushButton('Cancel', self)
        self.btnCancel.clicked.connect(self.close)

        layout.addWidget(lblDefaultBhv, 0, 0)

        layout.addWidget(self.chkSave, 1, 0)
        layout.addWidget(self.chkLoad, 2, 0)
        layout.addWidget(self.btnStart, 3, 0)
        layout.addWidget(self.btnCancel, 3, 1)

        self.setLayout(layout)

        self.btnStart.setFocus()

    def save_config(self):
        return

    def show(self):
        self.setFixedSize(460, 200)
        self.setWindowTitle("BinCAT configuration")
        super(TaintLaunchForm_t, self).show()


class TaintLaunchForm_t(QtWidgets.QDialog):

    def rbRegistersHandler(self):
        self.cbRegisters.setEnabled(True)

    def rbMemoryHandler(self):
        self.ipMemory.setEnabled(True)

    def cbRegistersHandler(self, text):
        bc_log.debug("selected register is %s ", text)

    def launch_analysis(self):
        bc_log.info("Launching the analyzer")
        # Test if stop address is not empty
        if not self.ipStopAddr.text():
            idaapi.bc_log.warning(" Stop address is empty")
            return
        startAddr = int(self.ipStartAddr.text(), 16)
        stopAddr = int(self.ipStopAddr.text(), 16)
        PluginState.currentConfig.setStartStopAddr(startAddr, stopAddr)
        PluginState.startAnalysis()

        self.close()

    def bincat_config(self):
        # display config window
        bc_conf_form = BinCATConfigForm_t(self)
        bc_conf_form.exec_()

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
        PluginState.currentEA = idaapi.get_screen_ea()

        # Start address
        lblStartAddr = QtWidgets.QLabel(" Start address: ")
        self.ipStartAddr = QtWidgets.QLineEdit(self)
        self.ipStartAddr.setText(hex(PluginState.currentEA).rstrip('L'))

        # Use current basic block address as default stop address
        stopAddr = ""
        for block in idaapi.FlowChart(idaapi.get_func(idaapi.get_screen_ea())):
            if block.startEA <= PluginState.currentEA <= block.endEA:
                stopAddr = hex(block.endEA).rstrip('L')
        lblStopAddr = QtWidgets.QLabel(" Stop address: ")
        self.ipStopAddr = QtWidgets.QLineEdit(self)
        self.ipStopAddr.setText(stopAddr)

        # Start, cancel and analyzer config buttons
        self.btnLoad = QtWidgets.QPushButton('&Load analyzer config',
                                             self)
        self.btnLoad.clicked.connect(self.choose_file)

        self.btnEditConf = QtWidgets.QPushButton('&Edit analyzer config',
                                                 self)
        self.btnEditConf.clicked.connect(self.edit_config)

        self.btnBCConf = QtWidgets.QPushButton('Cfg', self)
        self.btnBCConf.clicked.connect(self.bincat_config)

        self.btnStart = QtWidgets.QPushButton('&Start', self)
        self.btnStart.clicked.connect(self.launch_analysis)

        self.btnCancel = QtWidgets.QPushButton('Cancel', self)
        self.btnCancel.clicked.connect(self.close)

        layout.addWidget(lblCstEditor, 0, 0)
        layout.addWidget(self.btnBCConf, 0, 1, QtCore.Qt.AlignRight)

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
        bc_log.debug("Analyzer cmdline: [%s]", cmdline)
        try:
            self.start(cmdline)
        except Exception as e:
            bc_log.error("BinCAT failed to launch the analyzer.py")
            bc_log.warning("Exception: %s\n%s", str(e), traceback.format_exc())
        else:
            bc_log.info("Analyzer started.")

    def procanalyzer_on_error(self, err):
        errors = ["Failed to start", "Crashed", "TimedOut", "Read Error",
                  "Write Error", "Unknown Error"]
        try:
            errtxt = errors[err]
        except IndexError:
            errtxt = "Unspecified error %s" % err
        bc_log.error("Analyzer error: %s", errtxt)

    def procanalyzer_on_state_change(self, new_state):
        states = ["Not running", "Starting", "Running"]
        bc_log.debug("Analyzer new state: %s", states[new_state])

    def procanalyzer_on_start(self):
        bc_log.info("Analyzer: starting process")

    def procanalyzer_on_finish(self):
        bc_log.info("Analyzer process terminated")
        exitcode = self.exitCode()
        if exitcode == 0:
            bc_log.debug("Parsing analyzer result file")

            PluginState.cfa = cfa_module.CFA.parse(self.outfname,
                                                   logs=self.logfname)
            # Update current RVA to start address (nodeid = 0)
            node0 = PluginState.cfa['0']

            startaddr_ea = node0.address.value
            PluginState.setCurrentEA(startaddr_ea, force=True)
        else:
            bc_log.error("analyzer returned exit code=%i", exitcode)
            bc_log.info("---- stdout ----------------")
            bc_log.info(str(self.readAllStandardOutput()))
            bc_log.info("---- stderr ----------------")
            bc_log.info(str(self.readAllStandardError()))
        bc_log.debug("---- logfile ---------------")
        if os.path.exists(self.logfname):
            bc_log.debug(open(self.logfname).read())
        bc_log.debug("----------------------------")


class BinCATDebugForm_t(idaapi.PluginForm):
    """
    BinCAT Debug form.
    """
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        layout = QtWidgets.QGridLayout()

        self.stmt_lbl = QtWidgets.QLabel("Statements")
        self.stmt_data = QtWidgets.QLabel()
        self.bytes_lbl = QtWidgets.QLabel("Bytes")
        self.bytes_data = QtWidgets.QLabel()

        self.stmt_data.setTextInteractionFlags(
            QtCore.Qt.TextSelectableByMouse |
            QtCore.Qt.TextSelectableByKeyboard)
        self.stmt_data.setWordWrap(True)
        self.bytes_data.setTextInteractionFlags(
            QtCore.Qt.TextSelectableByMouse |
            QtCore.Qt.TextSelectableByKeyboard)
        self.bytes_data.setWordWrap(True)

        layout.addWidget(self.stmt_lbl, 0, 0)
        layout.addWidget(self.stmt_data, 0, 1)
        layout.addWidget(self.bytes_lbl, 1, 0)
        layout.addWidget(self.bytes_data, 1, 1)
        layout.setColumnStretch(0, 0)
        layout.setColumnStretch(1, 1)
        self.parent.setLayout(layout)

    def update(self, state):
        if state:
            self.stmt_data.setText(state.statements)
            self.bytes_data.setText(state.bytes)
        else:
            self.stmt_data.setText("")
            self.bytes_data.setText("")

    def OnClose(self, form):
        pass

    def Show(self):
        return idaapi.PluginForm.Show(
            self, "BinCAT Debugging",
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
        # width from the model are not respected, not sure why...
        for idx, w in enumerate(PluginState.vtmodel.colswidths):
            self.vttable.setColumnWidth(idx, w)

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
        self.headers = ["Src region", "Location", "Dst region", "Value", "Taint"]
        self.colswidths = [90, 90, 90, 150, 150]
        #: list of Value (addresses)
        self.rows = []
        self.changedRows = set()
        self.diffFont = QtGui.QFont()
        self.diffFont.setBold(True)
        super(ValueTaintModel, self).__init__(*args, **kwargs)

    @staticmethod
    def rowcmp(row):
        """
        Used as key function to sort rows.
        Memory first, then registers.
        """
        if row.region == 'reg':
            return (1, row)
        else:
            return (0, row)

    def endResetModel(self):
        """
        Rebuild a list of rows
        """
        state = PluginState.currentState
        #: list of Values (addresses)
        self.rows = []
        self.changedRows = set()
        if state:
            self.rows = sorted(state.regaddrs, key=ValueTaintModel.rowcmp)

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
        if col == 0:  # region
            return region
        elif col == 1:  # addr
            if region in ["global", "stack", "heap"]:
                return regaddr.__valuerepr__()
            else:
                return str(regaddr.value)
        else:
            v = PluginState.currentState[regaddr]
            if not v:
                return ""
        if col == 2:  # destination region
            return v.region
        if col == 3:  # value
            return v.__valuerepr__()
        elif col == 4:  # taint
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
            idaapi.attach_action_to_popup(form, popup, "bincat:ana_from_here",
                                          "BinCAT/", idaapi.SETMENU_APP)


class PluginState(object):
    """
    Container for (static) plugin state related data & methods.
    """
    log_panel = None
    vtmodel = ValueTaintModel()
    currentEA = None
    cfa = None
    currentState = None
    currentConfig = AnalyzerConfig()
    #: Analyzer instance
    analyzer = None
    BinCATTaintedForm = None
    BinCATDebugForm = None
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
            else:
                PluginState.currentState = None
        PluginState.BinCATTaintedForm.updateCurrentEA(ea)
        PluginState.vtmodel.endResetModel()
        PluginState.BinCATDebugForm.update(PluginState.currentState)

    @staticmethod
    def startAnalysis(configStr=None):
        path = tempfile.mkdtemp(suffix='bincat')
        initfname = os.path.join(path, "init.ini")
        outfname = os.path.join(path, "out.ini")
        logfname = os.path.join(path, "analyzer.log")

        bc_log.debug("Current analyzer path: %s", path)

        if configStr:
            with open(initfname, 'wb') as f:
                f.write(configStr)
        else:
            PluginState.currentConfig.write(initfname)

        PluginState.analyzer = Analyzer(initfname, outfname, logfname)
        PluginState.analyzer.run()


def PLUGIN_ENTRY():
    return bincat_plugin()
