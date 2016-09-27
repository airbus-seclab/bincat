# -*- coding: utf-8 -*-
# version IDA 6.9
# runs the "bincat" command from ida

import os
import logging
import idaapi
from PyQt5 import QtCore, QtWidgets, QtGui
import idabincat.hexview as hexview
import pybincat.cfa as cfa

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

        self.btn_start = QtWidgets.QPushButton('&Save', self)
        self.btn_start.clicked.connect(self.btn_launch_analyzer)

        self.btn_cancel = QtWidgets.QPushButton('Cancel', self)
        self.btn_cancel.clicked.connect(self.close)

        layout.addWidget(self.configtxt, 1, 0, 1, 0)
        layout.addWidget(self.btn_start, 2, 0)
        layout.addWidget(self.btn_cancel, 2, 1)
        self.setLayout(layout)

    def sizeHint(self):
        return QtCore.QSize(700, 1200)

    def set_addresses(self, start_addr, stop_addr):
        start_addr = int(self.parent().ip_start_addr.text(), 16)
        stop_addr = int(self.parent().ip_stop_addr.text(), 16)
        self.s.current_config.set_start_stop_addr(start_addr, stop_addr)
        self.configtxt.appendPlainText(str(self.s.current_config))

    def set_config(self, config_txt):
        self.configtxt.appendPlainText(config_txt)

    def btn_launch_analyzer(self):
        self.s.current_config.reset_from_str(self.configtxt.toPlainText())
        self.close()

    def show(self):
        self.setFixedSize(1000, 400)
        self.setWindowTitle("Edit configuration")
        super(EditConfigurationFileForm_t, self).show()


class BinCATOptionsForm_t(QtWidgets.QDialog):
    def __init__(self, state):
        super(BinCATOptionsForm_t, self).__init__()
        self.s = state

        layout = QtWidgets.QGridLayout()

        lbl_default_bhv = QtWidgets.QLabel("Default behaviour")
        # Save config in IDB by default
        self.chk_save = QtWidgets.QCheckBox('Save &configuration to IDB')
        self.chk_load = QtWidgets.QCheckBox('&Load configuration from IDB')

        btn_start = QtWidgets.QPushButton('&Save', self)
        btn_start.clicked.connect(self.save_config)

        btn_cancel = QtWidgets.QPushButton('Cancel', self)
        btn_cancel.clicked.connect(self.close)

        lbl_plug_opts = QtWidgets.QLabel("Plugin options")
        self.chk_start = QtWidgets.QCheckBox('Start &plugin automatically')
        self.chk_remote = QtWidgets.QCheckBox('Use &remote bincat')
        lbl_url = QtWidgets.QLabel("Remote URL:")
        self.url = QtWidgets.QLineEdit(self)

        layout.addWidget(lbl_default_bhv, 0, 0)
        layout.addWidget(self.chk_save, 1, 0)
        layout.addWidget(self.chk_load, 2, 0)
        layout.addWidget(lbl_plug_opts, 3, 0)
        layout.addWidget(self.chk_start, 4, 0)
        layout.addWidget(self.chk_remote, 5, 0)
        layout.addWidget(lbl_url, 6, 0)
        layout.addWidget(self.url, 7, 0)
        layout.addWidget(btn_start, 8, 0)
        layout.addWidget(btn_cancel, 8, 1)

        self.setLayout(layout)

        btn_start.setFocus()

        self.chk_start.setChecked(
            self.s.options.get("autostart") == "True")
        self.chk_save.setChecked(
            self.s.options.get("save_to_idb") == "True")
        self.chk_load.setChecked(
            self.s.options.get("load_from_idb") == "True")
        self.chk_remote.setChecked(
            self.s.options.get("web_analyzer") == "True")
        url = self.s.options.get("server_url")
        self.url.setText(url)

    def save_config(self):
        self.s.options.set("autostart", str(self.chk_start.isChecked()))
        self.s.options.set("save_to_idb", str(self.chk_save.isChecked()))
        self.s.options.set("load_from_idb", str(self.chk_load.isChecked()))
        self.s.options.set("web_analyzer", str(self.chk_remote.isChecked()))
        self.s.options.set("server_url", self.url.text())
        self.s.options.save()
        self.close()
        return

    def show(self):
        self.setFixedSize(460, 200)
        self.setWindowTitle("BinCAT configuration")
        super(BinCATOptionsForm_t, self).show()


class TaintLaunchForm_t(QtWidgets.QDialog):
    def __init__(self, parent, state):
        super(TaintLaunchForm_t, self).__init__(parent)
        self.s = state

        layout = QtWidgets.QGridLayout()
        lbl_cst_editor = QtWidgets.QLabel("BinCAT analysis parameters")
        self.s.current_ea = idaapi.get_screen_ea()

        # Use current basic block address as default stop address
        stop_addr = 0
        try:
            for block in idaapi.FlowChart(idaapi.get_func(idaapi.get_screen_ea())):
                if block.startEA <= self.s.current_ea <= block.endEA:
                    stop_addr = block.endEA
        except:
            pass

        # Load config for address if it exists
        self.s.current_config.for_address(self.s, self.s.current_ea, stop_addr)

        # Start address
        lbl_start_addr = QtWidgets.QLabel(" Start address: ")
        self.ip_start_addr = QtWidgets.QLineEdit(self)
        self.ip_start_addr.setText(hex(self.s.current_ea).rstrip('L'))

        lbl_stop_addr = QtWidgets.QLabel(" Stop address: ")
        self.ip_stop_addr = QtWidgets.QLineEdit(self)
        self.ip_stop_addr.setText(hex(stop_addr).rstrip('L'))

        # Start, cancel and analyzer config buttons
        self.btn_load = QtWidgets.QPushButton('&Load analyzer config...')
        self.btn_load.clicked.connect(self.choose_file)

        self.btn_edit_conf = QtWidgets.QPushButton('&Edit analyzer config...')
        self.btn_edit_conf.clicked.connect(self.edit_config)

        self.chk_save = QtWidgets.QCheckBox('Save &configuration to IDB')
        self.chk_save.setChecked(
            self.s.options.get("save_to_idb") == "True")

        self.btn_start = QtWidgets.QPushButton('&Start')
        self.btn_start.clicked.connect(self.launch_analysis)

        self.btn_cancel = QtWidgets.QPushButton('Cancel')
        self.btn_cancel.clicked.connect(self.close)

        layout.addWidget(lbl_cst_editor, 0, 0)

        layout.addWidget(lbl_start_addr, 1, 0)
        layout.addWidget(self.ip_start_addr, 1, 1)

        layout.addWidget(lbl_stop_addr, 2, 0)
        layout.addWidget(self.ip_stop_addr, 2, 1)

        layout.addWidget(self.btn_load, 3, 0)
        layout.addWidget(self.btn_edit_conf, 3, 1)

        layout.addWidget(self.chk_save, 4, 0)

        layout.addWidget(self.btn_start, 5, 0)
        layout.addWidget(self.btn_cancel, 5, 1)

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

        if self.chk_save.isChecked():
            self.s.current_config.save_to_idb(
                int(self.ip_start_addr.text(), 16))

        self.s.start_analysis()

        self.close()

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

    def show(self):
        self.setFixedSize(460, 200)
        self.setWindowTitle(" Analysis launcher: ")
        super(TaintLaunchForm_t, self).show()


class Meminfo():
    """
        Helper class to access memory as a str
    """
    def __init__(self, state, region, ranges):
        self.state = state
        self.region = region
        self.ranges = ranges
        self.start = ranges[0][0]
        self.length = ranges[-1][1]-self.start

    @staticmethod
    def color_valtaint(strval, strtaint):
        if len(strval) != len(strtaint):
            raise ValueError("value and taint strings are of different length", strval, strtaint)
        color_str = ""
        for i, c in enumerate(strval):
            if strtaint[i] == 'F': # full taint
                color_str += "<font color='green'>"+c+"</font>"
            elif strtaint[i] == '0': # no taint
                color_str += c
            elif strtaint[i] == '?': # unknown taint
                color_str += "<font color='cyan'>"+c+"</font>"
            else: # no fully tainted
                color_str += "<font color='yellow'>"+c+"</font>"
        return color_str

    def char(self, index):
        """ relative get of ASCII char """
        if index < 0 or index >= self.length:
            raise IndexError
        abs_addr = index+self.start
        addr_value = cfa.Value(self.region, abs_addr, 32)
        in_range = filter(lambda r: abs_addr >= r[0] or abs_addr <= r[1], self.ranges)
        if not in_range:
            return "__"
        else:
            value = self.state[addr_value][0]
            if value.is_concrete():
                return chr(value.value)
            else:
                return "?"

    def __getitem__(self, index):
        """ relative get """
        if index < 0 or index >= self.length:
            raise IndexError
        abs_addr = index+self.start
        addr_value = cfa.Value(self.region, abs_addr, 32)
        in_range = filter(lambda r: abs_addr >= r[0] or abs_addr <= r[1], self.ranges)
        if not in_range:
            return "__"
        else:
            values = self.state[addr_value]
            return Meminfo.color_valtaint(values[0].__valuerepr__(16, True), values[0].__taintrepr__(16, True))


class BinCATHexForm_t(idaapi.PluginForm):
    """
    BinCAT hex form.
    """
    def __init__(self, state):
        super(BinCATHexForm_t, self).__init__()
        self.s = state
        self.shown = False
        self.created = False
        self.hexwidget = None
        self.region_select = None
        self.range_select = None
        self.layout = None
        self.mem_ranges = None

    @QtCore.pyqtSlot(str)
    def update_range(self, crange):
        cur_reg = self.region_select.currentText()
        cur_range = self.mem_ranges[cur_reg][crange]
        meminfo = Meminfo(self.s.current_state, cur_reg, [cur_range])
        self.layout.removeWidget(self.hexwidget)
        self.hexwidget = hexview.HexViewWidget(meminfo, self.parent)
        self.layout.addWidget(self.hexwidget, 1, 0, 1, 2)

    @QtCore.pyqtSlot(str)
    def update_region(self, region):
        if region != "":
            self.range_select.blockSignals(True)
            self.range_select.clear()
            for r in self.mem_ranges[region]:
                self.range_select.addItem("%08x-%08x" % r)
            self.range_select.blockSignals(False)
            self.update_range(0)

    def OnCreate(self, form):
        self.created = True
        self.parent = self.FormToPyQtWidget(form)
        self.layout = QtWidgets.QGridLayout()

        self.region_select = QtWidgets.QComboBox()
        self.region_select.currentTextChanged.connect(self.update_region)
        self.range_select = QtWidgets.QComboBox()
        self.range_select.currentIndexChanged.connect(self.update_range)

        self.layout.addWidget(self.region_select, 0, 0)
        self.layout.addWidget(self.range_select, 0, 1)
        self.parent.setLayout(self.layout)

    def update_current_ea(self, ea):
        """
        :param ea: int or long
        """
        if not (self.shown and self.created):
            return

        if self.s.current_state:
            self.mem_ranges = self.s.current_state.mem_ranges()
            self.region_select.blockSignals(True)
            self.region_select.clear()
            for k in self.mem_ranges.keys():
                self.region_select.addItem(k)
            self.region_select.blockSignals(False)

            self.range_select.blockSignals(True)
            self.range_select.clear()
            for r in self.mem_ranges.values()[0]:
                self.range_select.addItem("%08x-%08x" % r)
            self.range_select.blockSignals(False)
            self.update_range(0)


    def OnClose(self, form):
        self.shown = False
        pass

    def Show(self):
        self.shown = True
        return idaapi.PluginForm.Show(
            self, "BinCAT Hex",
            options=(idaapi.PluginForm.FORM_PERSIST |
                     idaapi.PluginForm.FORM_TAB))

class BinCATDebugForm_t(idaapi.PluginForm):
    """
    BinCAT Debug form.
    """
    def __init__(self, state):
        super(BinCATDebugForm_t, self).__init__()
        self.s = state
        self.shown = False
        self.created = False
        self.stmt_txt = ""
        self.bytes_txt = ""

    def OnCreate(self, form):
        self.created = True
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
        self.settxt()

        layout.addWidget(self.stmt_lbl, 0, 0)
        layout.addWidget(self.stmt_data, 0, 1)
        layout.addWidget(self.bytes_lbl, 1, 0)
        layout.addWidget(self.bytes_data, 1, 1)
        layout.setColumnStretch(0, 0)
        layout.setColumnStretch(1, 1)
        self.parent.setLayout(layout)

    def settxt(self):
        self.stmt_data.setText(self.stmt_txt)
        self.bytes_data.setText(self.bytes_txt)

    def update(self, state):
        if state:
            self.stmt_txt = state.statements.replace('____', '    ')
            self.bytes_txt = state.bytes
        else:
            self.stmt_txt = ""
            self.bytes_txt = ""
        if self.created and self.shown:
            self.settxt()

    def OnClose(self, form):
        self.shown = False
        pass

    def Show(self):
        self.shown = True
        return idaapi.PluginForm.Show(
            self, "BinCAT Debugging",
            options=(idaapi.PluginForm.FORM_PERSIST |
                     idaapi.PluginForm.FORM_TAB))


## http://stackoverflow.com/questions/35397943/how-to-make-a-fast-qtableview-with-html-formatted-and-clickable-cells
## Class to represent tainted data with colors in the BinCATTaintedForm_t
class RegisterItemDelegate(QtWidgets.QStyledItemDelegate):
    def paint(self, painter, options, index):
        self.initStyleOption(options, index)

        painter.save()

        doc = QtGui.QTextDocument()
        doc.setHtml(options.text)

        options.text = ""
        options.widget.style().drawControl(QtWidgets.QStyle.CE_ItemViewItem, options, painter)

        painter.translate(options.rect.left(), options.rect.top())
        clip = QtCore.QRectF(0, 0, options.rect.width(), options.rect.height())
        doc.drawContents(painter, clip)

        painter.restore()



class BinCATTaintedForm_t(idaapi.PluginForm):
    """
    BinCAT Tainted values form
    This form containes the values of tainted registers and memory
    """

    def __init__(self, state, vtmodel):
        super(BinCATTaintedForm_t, self).__init__()
        self.s = state
        self.vtmodel = vtmodel
        self.shown = False
        self.created = False
        self.rvatxt = ""

    def OnCreate(self, form):
        self.created = True
        self.currentrva = 0

        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        layout = QtWidgets.QGridLayout()

        splitter = QtWidgets.QSplitter()
        layout.addWidget(splitter, 0, 0)
        # Node id label
        self.nilabel = QtWidgets.QLabel('Node Id:')
        splitter.addWidget(self.nilabel)

        # Node combobox
        self.node_select = QtWidgets.QComboBox()
        for i in sorted(self.s.current_node_ids):
            self.node_select.addItem(i)
        if self.s.current_state:
            self.node_select.setCurrentText(self.s.current_state.node_id)
        self.node_select.currentTextChanged.connect(self.update_node)
        splitter.addWidget(self.node_select)

        # Node count
        self.ncnt_label = QtWidgets.QLabel('Node count:')
        splitter.addWidget(self.ncnt_label)

        # RVA address label
        self.alabel = QtWidgets.QLabel('RVA: %s' % self.rvatxt)
        splitter.addWidget(self.alabel)

        # Value Taint Table
        self.vttable = QtWidgets.QTableView()
        self.vttable.setItemDelegate(RegisterItemDelegate())
        self.vttable.setSortingEnabled(True)
        self.vttable.setModel(self.vtmodel)
        self.vttable.setShowGrid(False)
        self.vttable.verticalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)
        # width from the model are not respected, not sure why...
        for idx, w in enumerate(self.vtmodel.colswidths):
            self.vttable.setColumnWidth(idx, w)

        self.vttable.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.Interactive)
        self.vttable.horizontalHeader().setStretchLastSection(True)
        self.vttable.horizontalHeader().setMinimumHeight(36)

        layout.addWidget(self.vttable, 1, 0)

        layout.setRowStretch(1, 0)

        self.parent.setLayout(layout)

    def OnClose(self, form):
        self.shown = False

    def Show(self):
        self.shown = True
        return idaapi.PluginForm.Show(
            self, "BinCAT Tainting",
            options=(idaapi.PluginForm.FORM_PERSIST |
                     idaapi.PluginForm.FORM_TAB))

    @QtCore.pyqtSlot(str)
    def update_node(self, node):
        if node != "" and (not self.s.current_state or node != self.s.current_state.node_id):
            self.node_select.blockSignals(True)
            self.s.set_current_node(node)
            self.node_select.blockSignals(False)

    def update_current_ea(self, ea):
        """
        :param ea: int or long
        """
        self.rvatxt = '0x%08x' % ea
        if not (self.shown and self.created):
            return
        self.alabel.setText('RVA: %s' % self.rvatxt)
        state = self.s.current_state
        if state:
            self.node_select.blockSignals(True)
            self.node_select.clear()
            for i in sorted(self.s.current_node_ids, key=int):
                self.node_select.addItem(i)
            self.node_select.setCurrentText(self.s.current_state.node_id)
            self.node_select.blockSignals(False)
            self.ncnt_label.setText('Node Count: %s' % len(self.s.current_node_ids))
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
        self.headers = ["register", "Value"]
        self.colswidths = [90, 90]
        #: list of Value (addresses)
        self.rows = []
        self.changed_rows = set()
        self.default_font = QtGui.QFont("AnyStyle")
        self.mono_font = QtGui.QFont("Monospace")
        self.diff_font = QtGui.QFont("AnyStyle", weight=QtGui.QFont.Bold)
        self.diff_font_mono = QtGui.QFont("Monospace", weight=QtGui.QFont.Bold)

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
            self.rows = filter(lambda x : x.region == "reg", state.regaddrs)
            self.rows = sorted(self.rows, key=ValueTaintModel.rowcmp)

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
                if col in [1, 3]:
                    return self.diff_font_mono
                else:
                    return self.diff_font
            else:
                if col in [1, 3]:
                    return self.mono_font
                else:
                    return self.default_font
        elif role != QtCore.Qt.DisplayRole:
            return
        regaddr = self.rows[index.row()]
        region = regaddr.prettyregion

        if region != "reg":
            return
        if col == 0:  # register name
            return str(regaddr.value)
        v = self.s.current_state[regaddr]
        if not v:
            return ""
        if col == 1:  # value
            concatv = v[0]
            strval = ''
            for idx, nextv in enumerate(v[1:]):
                if idx > 50:
                    strval = concatv.__valuerepr__(16,True) + '...'
                    break
                concatv = concatv & nextv
            if not strval:
                strval = concatv.__valuerepr__(16,True)
            concatv = v[0]
            strtaint = ''
            for idx, nextv in enumerate(v[1:]):
                if idx > 50:
                    strtaint = concatv.__taintrepr__(16,True) + '...'
                    break
                concatv = concatv & nextv
            if not strtaint:
                strtaint = concatv.__taintrepr__(16,True)
            if strtaint != "":
                strval = Meminfo.color_valtaint(strval, strtaint)
            return strval

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
        self.s.gui.show_windows()

        AnalyzerLauncher = TaintLaunchForm_t(None, self.s)
        AnalyzerLauncher.exec_()

        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class HandleOptions(idaapi.action_handler_t):
    """
    Action handler for BinCAT/Options
    """
    def __init__(self, state):
        self.state = state

    def activate(self, ctx):
        # display config window
        bc_conf_form = BinCATOptionsForm_t(self.state)
        bc_conf_form.exec_()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class HandleShowWindows(idaapi.action_handler_t):
    """
    Action handler for BinCAT/Show windows
    """
    def __init__(self, gui):
        self.gui = gui

    def activate(self, ctx):
        self.gui.show_windows()
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
            if idaapi.isCode(idaapi.getFlags(place.toea())):
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
        self.BinCATDebugForm = BinCATDebugForm_t(state)
        self.BinCATHexForm = BinCATHexForm_t(state)

        self.show_windows()

        # XXX fix
        idaapi.set_dock_pos("BinCAT", "IDA View-A", idaapi.DP_TAB)

        # Analyse from here menu
        ana_from_here_act = idaapi.action_desc_t(
            'bincat:ana_from_here', 'Analyze from here...',
            HandleAnalyzeHere(self.s), 'Ctrl-Shift-A', 'BinCAT action', -1)
        idaapi.register_action(ana_from_here_act)
        idaapi.attach_action_to_menu("Edit/BinCAT/analyse",
                                     "bincat:ana_from_here",
                                     idaapi.SETMENU_APP)

        # "Show windows" menu
        show_windows_act = idaapi.action_desc_t(
            'bincat:show_windows', 'Show BinCAT windows',
            HandleShowWindows(self), '', 'BinCAT action', -1)
        idaapi.register_action(show_windows_act)
        idaapi.attach_action_to_menu("Edit/BinCAT/show_win",
                                     "bincat:show_windows",
                                     idaapi.SETMENU_APP)

        # "Options" menu
        options_act = idaapi.action_desc_t(
            'bincat:options_act', 'Options...',
            HandleOptions(self.s), '', 'BinCAT action', -1)
        idaapi.register_action(options_act)
        idaapi.attach_action_to_menu("Edit/BinCAT/show_win",
                                     "bincat:options_act",
                                     idaapi.SETMENU_APP)
        self.hooks = Hooks(state)
        self.hooks.hook()

    def show_windows(self):
        self.BinCATDebugForm.Show()
        self.BinCATTaintedForm.Show()
        self.BinCATHexForm.Show()

    def before_change_ea(self):
        self.vtmodel.beginResetModel()

    def after_change_ea(self):
        self.BinCATTaintedForm.update_current_ea(self.s.current_ea)
        self.vtmodel.endResetModel()
        self.BinCATDebugForm.update(self.s.current_state)
        self.BinCATHexForm.update_current_ea(self.s.current_ea)

    def term(self):
        if self.hooks:
            self.hooks.unhook()
            self.hooks = None
