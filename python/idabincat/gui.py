# -*- coding: utf-8 -*-
# version IDA 6.9
# runs the "bincat" command from ida

import os
import logging
import idaapi
from PyQt5 import QtCore, QtWidgets, QtGui

# Logging
bc_log = logging.getLogger('bincat.gui')
bc_log.setLevel(logging.DEBUG)


class EditConfigurationFileForm_t(QtWidgets.QDialog):
    def __init__(self, parent, state):
        super(EditConfigurationFileForm_t, self).__init__(parent)
        self.s = state

        layout = QtWidgets.QGridLayout()

        self.configtxt = QtWidgets.QPlainTextEdit()
        self.configtxt.setSizePolicy(QtWidgets.QSizePolicy.Expanding,
                                     QtWidgets.QSizePolicy.Expanding)

        self.btn_start = QtWidgets.QPushButton('&Start', self)
        self.btn_start.clicked.connect(self.btn_launch_analyzer)

        self.btn_cancel = QtWidgets.QPushButton('Cancel', self)
        self.btn_cancel.clicked.connect(self.close)

        layout.addWidget(self.configtxt, 1, 0, 1, 0)
        layout.addWidget(self.btn_start, 2, 0)
        layout.addWidget(self.btn_cancel, 2, 1)
        self.setLayout(layout)

    def set_addresses(self, start_addr, stop_addr):
        start_addr = int(self.parent().ip_start_addr.text(), 16)
        stop_addr = int(self.parent().ip_stop_addr.text(), 16)
        self.s.current_config.set_start_stop_addr(start_addr, stop_addr)
        self.configtxt.appendPlainText(str(self.s.current_config))

    def set_config(self, config_txt):
        self.configtxt.appendPlainText(config_txt)

    def btn_launch_analyzer(self):
        self.s.start_analysis(self.configtxt.toPlainText())
        self.close()

    def show(self):
        self.setFixedSize(1000, 400)
        self.setWindowTitle("Edit configuration")
        super(EditConfigurationFileForm_t, self).show()


class BinCATConfigForm_t(QtWidgets.QDialog):
    def __init__(self, parent, state):
        super(BinCATConfigForm_t, self).__init__(parent)
        self.s = state

        layout = QtWidgets.QGridLayout()

        lbl_default_bhv = QtWidgets.QLabel("Default behaviour")
        # Save config in IDB
        self.chk_save = QtWidgets.QCheckBox('&Save configuration to IDB',
                                            self)
        self.chk_load = QtWidgets.QCheckBox('&Load configuration from IDB',
                                            self)

        self.btn_start = QtWidgets.QPushButton('&Save', self)
        self.btn_start.clicked.connect(self.save_config)

        self.btn_cancel = QtWidgets.QPushButton('Cancel', self)
        self.btn_cancel.clicked.connect(self.close)

        layout.addWidget(lbl_default_bhv, 0, 0)

        layout.addWidget(self.chk_save, 1, 0)
        layout.addWidget(self.chk_load, 2, 0)
        layout.addWidget(self.btn_start, 3, 0)
        layout.addWidget(self.btn_cancel, 3, 1)

        self.setLayout(layout)

        self.btn_start.setFocus()

    def save_config(self):
        return

    def show(self):
        self.setFixedSize(460, 200)
        self.setWindowTitle("BinCAT configuration")
        super(BinCATConfigForm_t, self).show()


class TaintLaunchForm_t(QtWidgets.QDialog):
    def __init__(self, parent, state):
        super(TaintLaunchForm_t, self).__init__(parent)
        self.s = state

        layout = QtWidgets.QGridLayout()
        lbl_cst_editor = QtWidgets.QLabel("BinCAT analysis parameters")
        self.s.current_ea = idaapi.get_screen_ea()

        # Start address
        lbl_start_addr = QtWidgets.QLabel(" Start address: ")
        self.ip_start_addr = QtWidgets.QLineEdit(self)
        self.ip_start_addr.setText(hex(self.s.current_ea).rstrip('L'))

        # Use current basic block address as default stop address
        stop_addr = ""
        for block in idaapi.FlowChart(idaapi.get_func(idaapi.get_screen_ea())):
            if block.startEA <= self.s.current_ea <= block.endEA:
                stop_addr = hex(block.endEA).rstrip('L')
        lbl_stop_addr = QtWidgets.QLabel(" Stop address: ")
        self.ip_stop_addr = QtWidgets.QLineEdit(self)
        self.ip_stop_addr.setText(stop_addr)

        # Start, cancel and analyzer config buttons
        self.btn_load = QtWidgets.QPushButton('&Load analyzer config',
                                              self)
        self.btn_load.clicked.connect(self.choose_file)

        self.btn_edit_conf = QtWidgets.QPushButton('&Edit analyzer config',
                                                   self)
        self.btn_edit_conf.clicked.connect(self.edit_config)

        self.btn_bc_conf = QtWidgets.QPushButton('Cfg', self)
        self.btn_bc_conf.clicked.connect(self.bincat_config)

        self.btn_start = QtWidgets.QPushButton('&Start', self)
        self.btn_start.clicked.connect(self.launch_analysis)

        self.btn_cancel = QtWidgets.QPushButton('Cancel', self)
        self.btn_cancel.clicked.connect(self.close)

        layout.addWidget(lbl_cst_editor, 0, 0)
        layout.addWidget(self.btn_bc_conf, 0, 1, QtCore.Qt.AlignRight)

        layout.addWidget(lbl_start_addr, 1, 0)
        layout.addWidget(self.ip_start_addr, 1, 1)

        layout.addWidget(lbl_stop_addr, 2, 0)
        layout.addWidget(self.ip_stop_addr, 2, 1)

        layout.addWidget(self.btn_load, 3, 0)
        layout.addWidget(self.btn_edit_conf, 3, 1)

        layout.addWidget(self.btn_start, 4, 0)
        layout.addWidget(self.btn_cancel, 4, 1)

        self.setLayout(layout)

        self.btn_start.setFocus()

    def rbRegistersHandler(self):
        self.cb_registers.setEnabled(True)

    def rbMemoryHandler(self):
        self.ip_memory.setEnabled(True)

    def cbRegistersHandler(self, text):
        bc_log.debug("selected register is %s ", text)

    def launch_analysis(self):
        bc_log.info("Launching the analyzer")
        # Test if stop address is not empty
        if not self.ip_stop_addr.text():
            idaapi.bc_log.warning(" Stop address is empty")
            return
        start_addr = int(self.ip_start_addr.text(), 16)
        stop_addr = int(self.ip_stop_addr.text(), 16)
        self.s.current_config.set_start_stop_addr(start_addr, stop_addr)
        self.s.start_analysis()

        self.close()

    def bincat_config(self):
        # display config window
        bc_conf_form = BinCATConfigForm_t(self, self.s)
        bc_conf_form.exec_()

    def edit_config(self):
        # display edit form
        start_addr = int(self.ip_start_addr.text(), 16)
        stop_addr = int(self.ip_stop_addr.text(), 16)
        editdlg = EditConfigurationFileForm_t(self, self.s)
        editdlg.set_addresses(start_addr, stop_addr)
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
        editdlg = EditConfigurationFileForm_t(self, self.s)
        editdlg.set_config(open(filename, 'r').read())
        editdlg.exec_()
        self.close()

    def show(self):
        self.setFixedSize(460, 200)
        self.setWindowTitle(" Analysis launcher: ")
        super(TaintLaunchForm_t, self).show()


class BinCATDebugForm_t(idaapi.PluginForm):
    """
    BinCAT Debug form.
    """
    def __init__(self, state):
        super(BinCATDebugForm_t, self).__init__()
        self.s = state

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

    def __init__(self, state, vtmodel):
        super(BinCATTaintedForm_t, self).__init__()
        self.s = state
        self.vtmodel = vtmodel

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
        self.vttable.setModel(self.vtmodel)
        self.vttable.verticalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)
        # width from the model are not respected, not sure why...
        for idx, w in enumerate(self.vtmodel.colswidths):
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

    def update_current_ea(self, ea):
        """
        :param ea: int or long
        """
        self.alabel.setText('RVA: 0x%08x' % ea)
        state = self.s.current_state
        if state:
            self.nilabel.setText('Node Id: %s' % state.node_id)
        else:
            self.nilabel.setText('No data')


class ValueTaintModel(QtCore.QAbstractTableModel):
    """
    Used as model in BinCATTaintedForm TableView widgets.

    Contains tainting and values for either registers or memory addresses
    """
    def __init__(self, state, *args, **kwargs):
        super(ValueTaintModel, self).__init__(*args, **kwargs)
        self.s = state
        self.headers = ["Src region", "Location", "Dst region", "Value",
                        "Taint"]
        self.colswidths = [90, 90, 90, 150, 150]
        #: list of Value (addresses)
        self.rows = []
        self.changed_rows = set()
        self.diff_font = QtGui.QFont()
        self.diff_font.setBold(True)

    @staticmethod
    def rowcmp(row):
        """
        Used as key function to sort rows.
        order: gp registers, zf, memory, other flags, segment registers
        """
        if row.region == 'reg':
            if row.value in ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi",
                             "edi"]:
                return (0, row)
            elif row.value == 'zf':
                return (1, row)
            elif row.value in ["cs", "ds", "ss", "es", "fs", "gs"]:
                return (4, row)
            else:
                return (3, row)
        else:
            return (2, row)

    def endResetModel(self):
        """
        Rebuild a list of rows
        """
        state = self.s.current_state
        #: list of Values (addresses)
        self.rows = []
        self.changed_rows = set()
        if state:
            self.rows = sorted(state.regaddrs, key=ValueTaintModel.rowcmp)

            # find parent state
            parents = [nodeid for nodeid in self.s.cfa.edges
                       if state.node_id in self.s.cfa.edges[nodeid]]
            for pnode in parents:
                pstate = self.s.cfa[pnode]
                for k in state.list_modified_keys(pstate):
                    if k in self.rows:
                        self.changed_rows.add(self.rows.index(k))

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
            if index.row() in self.changed_rows:
                return self.diff_font
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
            v = self.s.current_state[regaddr]
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


class HandleAnalyzeHere(idaapi.action_handler_t):
    """
    Action handler for BinCAT/ Taint from here
    base class is not a newstyle class...
    """
    def __init__(self, state):
        self.s = state

    def activate(self, ctx):
        f = idaapi.find_tform("IDA View-Tainting View")
        idaview = idaapi.PluginForm.FormToPyQtWidget(f)
        AnalyzerLauncher = TaintLaunchForm_t(idaview, self.s)
        AnalyzerLauncher.exec_()

        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class Hooks(idaapi.UI_Hooks):
    """
    Class Hooks for BinCAT menu
    """

    def __init__(self, state):
        super(Hooks, self).__init__()
        self.s = state

    def updating_actions(self, ctx):
        if ctx.form_type == idaapi.BWN_DISASM:
            idaview = idaapi.get_tform_idaview(ctx.form)
            place, x, y = idaapi.get_custom_viewer_place(idaview, False)
            # line =  get_custom_viewer_curline(idaview, False)
            if idaapi.isCode(idaapi.getFlags(place.toea())):
                # SetColor(place.toea(), CIC_ITEM, 0x0CE505)
                # idaapi.set_item_color(place.toea(), 0x23ffff)

                self.s.set_current_ea(place.toea())

    def populating_tform_popup(self, form, popup):
        if idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(form, popup, "bincat:ana_from_here",
                                          "BinCAT/", idaapi.SETMENU_APP)


class GUI(object):
    def __init__(self, state):
        """
        Instanciate BinCAT views
        """
        self.s = state
        self.vtmodel = ValueTaintModel(state)
        self.BinCATTaintedForm = BinCATTaintedForm_t(state, self.vtmodel)
        self.BinCATTaintedForm.Show()

        self.BinCATDebugForm = BinCATDebugForm_t(state)
        self.BinCATDebugForm.Show()

        idaapi.set_dock_pos("BinCAT", "IDA View-A", idaapi.DP_TAB)

        # TODO : change to menu item ?
        ana_from_here_act = idaapi.action_desc_t(
            'bincat:ana_from_here', 'Analyze from here',
            HandleAnalyzeHere(self.s), 'Ctrl-Shift-A', 'BinCAT action', -1)
        idaapi.register_action(ana_from_here_act)

        idaapi.attach_action_to_menu("Edit/BinCAT", "bincat:ana_from_here",
                                     idaapi.SETMENU_APP)
        self.hooks = Hooks(state)
        self.hooks.hook()

    def before_change_ea(self):
        self.vtmodel.beginResetModel()

    def after_change_ea(self):
        self.BinCATTaintedForm.update_current_ea(self.s.current_ea)
        self.vtmodel.endResetModel()
        self.BinCATDebugForm.update(self.s.current_state)

    def term(self):
        if self.hooks:
            self.hooks.unhook()
            self.hooks = None
