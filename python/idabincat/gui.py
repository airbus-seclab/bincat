# -*- coding: utf-8 -*-
# version IDA 6.9
# runs the "bincat" command from ida
"""
    This file is part of BinCAT.
    Copyright 2014-2017 - Airbus Group

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
import os
import idc
import logging
import string
import idc
import idaapi
import idautils
from dump_binary import dump_binary
from PyQt5 import QtCore, QtWidgets, QtGui
import idabincat.hexview as hexview
import pybincat.cfa as cfa
from idabincat.plugin_options import PluginOptions
from analyzer_conf import AnalyzerConfig

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

        self.btn_save = QtWidgets.QPushButton('&Save', self)
        self.btn_save.clicked.connect(self.use_config)

        self.btn_cancel = QtWidgets.QPushButton('Cancel', self)
        self.btn_cancel.clicked.connect(self.reject)

        layout.addWidget(self.configtxt, 1, 0, 1, 0)
        layout.addWidget(self.btn_save, 2, 0)
        layout.addWidget(self.btn_cancel, 2, 1)
        self.setLayout(layout)
        self.configtxt.setPlainText(str(self.s.edit_config))
        self.configtxt.moveCursor(QtGui.QTextCursor.Start)

    def sizeHint(self):
        return QtCore.QSize(700, 1200)

    def set_config(self, config_txt):
        self.configtxt.setPlainText(config_txt)
        self.configtxt.moveCursor(QtGui.QTextCursor.Start)

    def use_config(self):
        self.s.edit_config = AnalyzerConfig.load_from_str(
            self.configtxt.toPlainText())
        self.accept()

    def show(self):
        self.setFixedSize(1000, 400)
        self.setWindowTitle("Edit configuration")
        self.configtxt.setFocus()
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
            PluginOptions.get("autostart") == "True")
        self.chk_save.setChecked(
            PluginOptions.get("save_to_idb") == "True")
        self.chk_load.setChecked(
            PluginOptions.get("load_from_idb") == "True")
        self.chk_remote.setChecked(
            PluginOptions.get("web_analyzer") == "True")
        url = PluginOptions.get("server_url")
        self.url.setText(url)

    def save_config(self):
        PluginOptions.set("autostart", str(self.chk_start.isChecked()))
        PluginOptions.set("save_to_idb", str(self.chk_save.isChecked()))
        PluginOptions.set("load_from_idb", str(self.chk_load.isChecked()))
        PluginOptions.set("web_analyzer", str(self.chk_remote.isChecked()))
        PluginOptions.set("server_url", self.url.text())
        PluginOptions.save()
        self.close()
        return

    def show(self):
        self.setFixedSize(460, 200)
        self.setWindowTitle("BinCAT configuration")
        super(BinCATOptionsForm_t, self).show()


class TaintLaunchForm_t(QtWidgets.QDialog):
    def update_from_edit_config(self):
        config = self.s.edit_config
        self.ip_start_addr.setText(config.analysis_ep)
        cut = config.stop_address or ""
        self.ip_stop_addr.setText(cut)

    def __init__(self, parent, state):
        super(TaintLaunchForm_t, self).__init__(parent)
        self.s = state

        layout = QtWidgets.QGridLayout()
        lbl_cst_editor = QtWidgets.QLabel("BinCAT analysis parameters")
        self.s.current_ea = idaapi.get_screen_ea()

        # Start address
        lbl_start_addr = QtWidgets.QLabel("Start address:")
        self.ip_start_addr = QtWidgets.QLineEdit(self)

        lbl_stop_addr = QtWidgets.QLabel("Stop address:")
        self.ip_stop_addr = QtWidgets.QLineEdit(self)

        # analysis configuration
        lbl_configuration = QtWidgets.QLabel("Analyzer configuration:")
        self.conf_select = QtWidgets.QComboBox(self)
        self.conf_select.addItems(
            self.s.configurations.names_cache + ['(new)'])
        # pre-select preferred conf, if any
        conf_name = self.s.configurations.get_pref(self.s.current_ea)
        if conf_name:
            idx = self.s.configurations.names_cache.index(conf_name)
            self.s.edit_config = self.s.configurations[conf_name]
        else:
            idx = len(self.s.configurations.names_cache)
            self.s.edit_config = self.s.configurations.new_config(
                self.s.current_ea, None)
        self.conf_select.currentIndexChanged.connect(self._load_config)

        self.conf_select.setCurrentIndex(idx)

        # Start, cancel and analyzer config buttons
        self.btn_load = QtWidgets.QPushButton('&Load analyzer config...')
        self.btn_load.clicked.connect(self.choose_file)

        self.btn_edit_conf = QtWidgets.QPushButton('&Edit analyzer config...')
        self.btn_edit_conf.clicked.connect(self.edit_config)

        self.chk_save = QtWidgets.QCheckBox('Save &configuration to IDB')
        self.chk_save.setChecked(
            PluginOptions.get("save_to_idb") == "True")

        self.chk_remap = QtWidgets.QCheckBox('&Remap binary')
        self.chk_remap.setChecked(self.s.remap_binary)

        self.btn_start = QtWidgets.QPushButton('&Start')
        self.btn_start.clicked.connect(self.launch_analysis)

        self.btn_cancel = QtWidgets.QPushButton('Cancel')
        self.btn_cancel.clicked.connect(self.close)

        layout.addWidget(lbl_cst_editor, 0, 0)

        layout.addWidget(lbl_start_addr, 1, 0)
        layout.addWidget(self.ip_start_addr, 1, 1)

        layout.addWidget(lbl_stop_addr, 2, 0)
        layout.addWidget(self.ip_stop_addr, 2, 1)

        layout.addWidget(lbl_configuration, 3, 0)
        layout.addWidget(self.conf_select, 3, 1)

        layout.addWidget(self.btn_load, 4, 0)
        layout.addWidget(self.btn_edit_conf, 4, 1)

        layout.addWidget(self.chk_save, 5, 0)
        layout.addWidget(self.chk_remap, 5, 1)

        layout.addWidget(self.btn_start, 6, 0)
        layout.addWidget(self.btn_cancel, 6, 1)

        self.setLayout(layout)

        self.btn_start.setFocus()

        # Load config for address if it exists
        self.update_from_edit_config()

    def rbRegistersHandler(self):
        self.cb_registers.setEnabled(True)

    def rbMemoryHandler(self):
        self.ip_memory.setEnabled(True)

    def cbRegistersHandler(self, text):
        bc_log.debug("selected register is %s ", text)

    def launch_analysis(self):
        bc_log.info("Launching the analyzer")
        try:
            start_addr = int(self.ip_start_addr.text(), 16)
        except ValueError as e:
            bc_log.error('Provided start address is invalid (%s)', e)
            return
        start_addr = int(self.ip_start_addr.text(), 16)
        if self.ip_stop_addr.text() == "":
            stop_addr = None
        else:
            stop_addr = self.ip_stop_addr.text()
        self.s.edit_config.analysis_ep = start_addr
        self.s.edit_config.stop_address = stop_addr

        ea_int = int(self.ip_start_addr.text(), 16)

        # if requested, also save under user-specified slot
        if self.chk_save.isChecked():
            idx = self.conf_select.currentIndex()
            if idx == len(self.s.configurations.names_cache):
                # new config, prompt name
                config_name, res = QtWidgets.QInputDialog.getText(
                    self,
                    "Configuration name",
                    "Under what name should this new configuration be saved?",
                    text="0x%0X" % self.s.current_ea)
                if not res:
                    return
            else:
                config_name = self.s.configurations.names_cache[idx]
            self.s.configurations[config_name] = self.s.edit_config
            self.s.configurations.set_pref(ea_int, config_name)

        # always save config under "(last used)" slot
        config_name = "(last used)"
        self.s.configurations[config_name] = self.s.edit_config
        self.s.configurations.set_pref(ea_int, config_name)

        if self.chk_remap.isChecked():
            if (self.s.remapped_bin_path is None or
                    not os.path.isfile(self.s.remapped_bin_path)):
                fname = idaapi.askfile_c(1, "*.*", "Save remapped binary")
                if not fname:
                    bc_log.error(
                        'No filename provided. You can provide a filename or '
                        'uncheck the "Remap binary" option.')
                    return
                dump_binary(fname)
                self.s.remapped_bin_path = fname
            self.s.remap_binary = True
            self.s.edit_config.binary_filepath = self.s.remapped_bin_path
            self.s.edit_config.code_va = "0x0"
            self.s.edit_config.code_phys = "0x0"
            size = os.stat(self.s.edit_config.binary_filepath).st_size
            self.s.edit_config.code_length = "0x%0X" % size
            self.s.edit_config.replace_section_mappings(
                [("ph2", 0, size, 0, size)])
        else:
            self.s.remap_binary = False

        # XXX copy?
        self.s.current_config = self.s.edit_config

        self.s.start_analysis()

        self.close()

    def edit_config(self):
        # display edit form
        start_addr = self.ip_start_addr.text()
        stop_addr = self.ip_stop_addr.text()
        self.s.edit_config.analysis_ep = start_addr
        self.s.edit_config.stop_address = stop_addr
        editdlg = EditConfigurationFileForm_t(self, self.s)
        if editdlg.exec_() == QtWidgets.QDialog.Accepted:
            self.update_from_edit_config()

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
        if editdlg.exec_() == QtWidgets.QDialog.Accepted:
            self.update_from_edit_config()

    def show(self):
        self.setFixedSize(460, 200)
        self.setWindowTitle(" Analysis launcher: ")
        super(TaintLaunchForm_t, self).show()

    @QtCore.pyqtSlot(int)
    def _load_config(self, index):
        if index == len(self.s.configurations.names_cache):
            # new config
            self.s.edit_config = self.s.configurations.new_config(
                self.s.current_ea, None)
        else:
            name = self.s.configurations.names_cache[index]
            self.s.edit_config = self.s.configurations[name]
        self.update_from_edit_config()


class Meminfo():
    """
    Helper class to access memory as a str
    """
    def __init__(self, state, region, ranges):
        self.state = state
        self.region = region
        #: list of ranges: [[begin int, end int], ...]
        self.ranges = ranges
        self.start = ranges[0][0]
        self.length = ranges[-1][1]-self.start+1
        self.char_cache = {}
        self.html_cache = {}

    @staticmethod
    def color_valtaint(strval, strtaint):
        if len(strval) != len(strtaint):
            raise ValueError("value and taint strings are of different length",
                             strval, strtaint)
        color_str = ""
        for i, c in enumerate(strval):
            if strtaint[i] == 'F':  # full taint
                color_str += "<font color='green'>"+c+"</font>"
            elif strtaint[i] == '0':  # no taint
                color_str += c
            elif strtaint[i] == '?':  # unknown taint
                color_str += "<font color='blue'>"+c+"</font>"
            else:  # not fully tainted
                color_str += "<font color='#c1ad01'>"+c+"</font>"
        return color_str

    def char(self, idx):
        """ relative get of ASCII char """
        if idx in self.char_cache:
            return self.char_cache[idx]
        try:
            values = self[idx]
        except IndexError:
            # between two ranges
            return ""
        if len(values) == 0 or values[0] is None:
            res = "_"
        else:
            value = values[0]
            # value
            if value.is_concrete():
                char = chr(value.value)
                if char in string.printable:
                    res = char
                else:
                    res = '.'
            else:
                res = "?"
            # taint
            if value.ttop != 0 or value.tbot != 0:
                # top or bot
                res = "<font color='blue'>%s</font>" % res
            elif value.taint == 0:
                pass
            elif value.taint == 0xFF:
                res = "<font color='green'>%s</font>" % res
            else:
                res = "<font color='#c1ad01'>%s</font>" % res

        self.char_cache[idx] = res
        return res

    def html_color(self, idx):
        # often used => cache
        if idx in self.html_cache:
            return self.html_cache[idx]
        try:
            values = self[idx]
        except IndexError:
            return ""
        if len(values) == 0 or values[0] is None:
            res = "__"
        else:
            res = Meminfo.color_valtaint(
                values[0].__valuerepr__(16, True),
                values[0].__taintrepr__(16, True))
        self.html_cache[idx] = res
        return res

    def hexstr(self, idx):
        if isinstance(idx, slice):
            return "".join(
                [self.hexstr(i) for i in
                 range(idx.start, idx.stop+1, idx.step if idx.step else 1)])
        values = self[idx]
        return values[0].__valuerepr__(16, True)

    def __getitem__(self, idx):
        """ relative get - returns [Value, Value, ...]"""
        abs_addr = self.abs_addr_from_idx(idx)
        if not abs_addr:
            raise IndexError
        addr_value = cfa.Value(self.region, abs_addr, 32)
        in_range = filter(
            lambda r: abs_addr >= r[0] and abs_addr <= r[1], self.ranges)
        if not in_range or self.state is None:
            res = []
        else:
            res = self.state[addr_value]
        return res

    def get_type(self, idx):
        abs_addr = self.abs_addr_from_idx(idx)
        if not abs_addr:
            return ""
        addr_value = cfa.Value(self.region, abs_addr, 32)
        in_range = filter(
            lambda r: abs_addr >= r[0] and abs_addr <= r[1], self.ranges)
        if not in_range:
            return ""
        t = self.state.regtypes.get(addr_value, None)
        if t:
            return t[0]
        else:
            return ""

    def abs_addr_from_idx(self, idx):
        """
        convert idx relative to meminfo start to physical addr
        """
        if idx < 0 or idx > self.length:
            return
        return idx+self.start


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
        self.current_region = None
        self.current_range_idx = None
        #: region name (1 letter) -> address
        self.last_visited = dict((k, None) for k in cfa.PRETTY_REGIONS.keys())
        self.pretty_to_int_map = \
            dict((v, k) for k, v in cfa.PRETTY_REGIONS.items())

    @QtCore.pyqtSlot(int)
    def handle_selection_range_changed(self, bindex):
        if bindex < 0:
            return
        cur_reg = self.current_region
        start, stop = self.mem_ranges[cur_reg][self.current_range_idx]
        if bindex > stop-start:
            return
        self.last_visited[cur_reg] = bindex + start

    @QtCore.pyqtSlot(int, int, bool)
    def handle_new_override(self, abs_start, abs_end, re_run):
        # add override for each byte
        mask, res = QtWidgets.QInputDialog.getText(
            None,
            "Add Taint override",
            "Taint value each byte in the range %0X-%0X (e.g. 0x00, 0xFF)"
            % (abs_start, abs_end),
            text="0xFF")
        if not res:
            return
        region = cfa.PRETTY_REGIONS[self.current_region]
        if region == 'global':
            region = 'mem'
        for addr in range(abs_start, abs_end+1):
            ea = self.s.current_ea
            addrstr = "%s[0x%02X]" % (region, addr)
            self.s.overrides.append((ea, addrstr, mask))
        if re_run:
            self.s.re_run()

    @QtCore.pyqtSlot(str)
    def update_range(self, crangeidx):
        if self.current_range_idx == crangeidx:
            return
        self.current_range_idx = crangeidx
        cur_reg = self.pretty_to_int_map[self.region_select.currentText()]
        new_range = self.mem_ranges[cur_reg][crangeidx]
        # XXX only create a new Meminfo object on EA change, load ranges from
        # state in Meminfo __init__ ?
        meminfo = Meminfo(self.s.current_state, cur_reg, [new_range])
        self.hexwidget.setNewMem(meminfo)
        self.last_visited[cur_reg] = new_range[0]

    @QtCore.pyqtSlot(str)
    def update_region(self, pretty_region):
        region = self.pretty_to_int_map[pretty_region]
        self.current_region = region
        if region == "":
            return
        self.range_select.blockSignals(True)
        self.range_select.clear()
        for r in self.mem_ranges[region]:
            self.range_select.addItem("%08x-%08x" % r)
        self.range_select.blockSignals(False)
        # find address range idx correponding to last visited addr for
        # region
        newrangeidx = 0
        lva = self.last_visited[region]
        if lva is not None:
            for ridx, (start, stop) in enumerate(self.mem_ranges[region]):
                if lva >= start and lva <= stop:
                    newrangeidx = ridx
                    break
        self.current_range_idx = None
        self.update_range(newrangeidx)
        self.range_select.setCurrentIndex(newrangeidx)

    def OnCreate(self, form):
        self.created = True
        self.parent = self.FormToPyQtWidget(form)
        self.layout = QtWidgets.QGridLayout()

        self.region_select = QtWidgets.QComboBox()
        self.region_select.currentTextChanged.connect(self.update_region)
        self.range_select = QtWidgets.QComboBox()
        self.range_select.currentIndexChanged.connect(self.update_range)
        self.hexwidget = hexview.HexViewWidget(
            Meminfo(None, None, [[0, -1]]), self.parent)
        self.hexwidget._hsm.selectionRangeChanged.connect(
            self.handle_selection_range_changed)
        self.hexwidget.newOverride.connect(self.handle_new_override)
        self.layout.addWidget(self.hexwidget, 1, 0, 1, 2)

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
            # merge region separated by less than 0x100 bytes
            for region in self.mem_ranges:
                last_addr = None
                merged = []
                for start, stop in self.mem_ranges[region]:
                    if last_addr and start - last_addr < 0x100:
                        merged[-1] = (merged[-1][0], stop)
                    else:
                        merged.append((start, stop))
                    last_addr = stop
                self.mem_ranges[region] = merged

            former_region = self.region_select.currentText()
            newregion = ""
            newregidx = -1
            self.region_select.blockSignals(True)
            self.region_select.clear()
            for ridx, k in enumerate(self.mem_ranges.keys()):
                pretty_reg = cfa.PRETTY_REGIONS.get(k, k)
                self.region_select.addItem(pretty_reg)
                if pretty_reg == former_region:
                    newregion = pretty_reg
                    newregidx = ridx
                if newregion == "":
                    newregion = pretty_reg
                    newregidx = 0
            self.region_select.setCurrentIndex(newregidx)
            self.region_select.blockSignals(False)

            self.range_select.blockSignals(True)
            self.range_select.clear()
            for r in self.mem_ranges.values()[0]:
                self.range_select.addItem("%08x-%08x" % r)
            self.range_select.blockSignals(False)
            self.update_region(newregion)

    def OnClose(self, form):
        self.shown = False

    def Show(self):
        if self.shown:
            return
        self.shown = True
        return idaapi.PluginForm.Show(
            self, "BinCAT Hex",
            options=(idaapi.PluginForm.FORM_PERSIST |
                     idaapi.PluginForm.FORM_MENU |
                     idaapi.PluginForm.FORM_SAVE |
                     idaapi.PluginForm.FORM_RESTORE |
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

    def Show(self):
        if self.shown:
            return
        self.shown = True
        return idaapi.PluginForm.Show(
            self, "BinCAT Debugging",
            options=(idaapi.PluginForm.FORM_PERSIST |
                     idaapi.PluginForm.FORM_SAVE |
                     idaapi.PluginForm.FORM_RESTORE |
                     idaapi.PluginForm.FORM_TAB))


class RegisterItemDelegate(QtWidgets.QStyledItemDelegate):
    """
    http://stackoverflow.com/questions/35397943/how-to-make-a-fast-qtableview-with-html-formatted-and-clickable-cells
    Represents tainted data with colors in the BinCATTaintedForm_t
    """
    def paint(self, painter, options, index):
        self.initStyleOption(options, index)

        painter.save()

        doc = QtGui.QTextDocument()
        doc.setHtml(options.text)

        options.text = ""
        options.widget.style().drawControl(
            QtWidgets.QStyle.CE_ItemViewItem, options, painter)

        painter.translate(options.rect.left(), options.rect.top())
        clip = QtCore.QRectF(0, 0, options.rect.width(), options.rect.height())
        doc.drawContents(painter, clip)

        painter.restore()


class BinCATTaintedForm_t(idaapi.PluginForm):
    """
    BinCAT Tainted values form
    This form displays the values of tainted registers
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

        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        layout = QtWidgets.QGridLayout(self.parent)

        splitter = QtWidgets.QSplitter(self.parent)
        layout.addWidget(splitter, 0, 0)
        # Node id label
        self.nilabel = QtWidgets.QLabel('Nodes at this address:')
        splitter.addWidget(self.nilabel)

        # Node combobox
        self.node_select = QtWidgets.QComboBox()
        self.node_select.currentTextChanged.connect(self.update_node)
        splitter.addWidget(self.node_select)

        # RVA address label
        self.alabel = QtWidgets.QLabel('RVA: %s' % self.rvatxt)
        splitter.addWidget(self.alabel)

        # Goto combo box
        self.nextnodes_combo = QtWidgets.QComboBox()
        self.nextnodes_combo.currentTextChanged.connect(self.goto_next)
        splitter.addWidget(self.nextnodes_combo)
        # leave space for comboboxes in splitter, rather than between widgets
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setStretchFactor(2, 0)
        splitter.setStretchFactor(3, 1)

        # Value Taint Table
        self.vttable = QtWidgets.QTableView(self.parent)
        self.vttable.setItemDelegate(RegisterItemDelegate())
        self.vttable.setSortingEnabled(True)
        self.vttable.setModel(self.vtmodel)
        self.vttable.setShowGrid(False)
        self.vttable.verticalHeader().setVisible(False)
        self.vttable.verticalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)
        self.vttable.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.vttable.customContextMenuRequested.connect(
            self._handle_context_menu_requested)
        # width from the model are not respected, not sure why...
        for idx, w in enumerate(self.vtmodel.colswidths):
            self.vttable.setColumnWidth(idx, w)

        self.vttable.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)
        self.vttable.horizontalHeader().setStretchLastSection(True)
        self.vttable.horizontalHeader().setMinimumHeight(36)

        layout.addWidget(self.vttable, 1, 0)

        layout.setRowStretch(1, 0)

        self.parent.setLayout(layout)

        if isinstance(self.s.current_ea, int):
            self.update_current_ea(self.s.current_ea)

    def OnClose(self, form):
        self.shown = False

    def Show(self):
        if self.shown:
            return
        self.shown = True
        return idaapi.PluginForm.Show(
            self, "BinCAT Tainting",
            options=(idaapi.PluginForm.FORM_PERSIST |
                     idaapi.PluginForm.FORM_SAVE |
                     idaapi.PluginForm.FORM_RESTORE |
                     idaapi.PluginForm.FORM_TAB))

    @QtCore.pyqtSlot(str)
    def update_node(self, node):
        if node != "" and (not self.s.current_state or
                           node != self.s.current_state.node_id):
            self.node_select.blockSignals(True)
            self.s.set_current_node(node.split(' ')[0])
            self.node_select.blockSignals(False)

    @QtCore.pyqtSlot(str)
    def goto_next(self, node):
        if self.nextnodes_combo.currentIndex() == 0:
            return
        idaapi.jumpto(int(node.split(' ')[3], 16))

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
            # nodes at current EA
            self.node_select.blockSignals(True)
            self.node_select.clear()
            nodes = sorted(self.s.current_node_ids, key=int)
            for idx, node in enumerate(nodes):
                self.node_select.addItem(
                    node + ' (%d other nodes)' % (len(nodes)-1))
                if str(node) == self.s.current_state.node_id:
                    self.node_select.setCurrentIndex(idx)
            self.node_select.setEnabled(len(nodes) != 1)
            self.node_select.blockSignals(False)
            # next nodes
            self.nextnodes_combo.blockSignals(True)
            self.nextnodes_combo.clear()
            next_states = self.s.cfa.next_states(self.s.current_state.node_id)
            next_nodes = ["node %s at 0x%0X" % (s.node_id, s.address.value)
                          for s in next_states]
            if len(next_nodes) == 0:
                self.nextnodes_combo.addItem("No data")
                self.nextnodes_combo.setEnabled(False)
            else:
                for nid in next_nodes:
                    self.nextnodes_combo.addItem(
                        "goto next node (%d)" % len(next_nodes))
                    self.nextnodes_combo.addItem(str(nid))
                self.nextnodes_combo.setEnabled(True)
            self.nextnodes_combo.blockSignals(False)
        else:
            # nodes at current EA
            self.node_select.blockSignals(True)
            self.node_select.clear()
            self.node_select.addItem("No data")
            self.node_select.setEnabled(False)
            self.node_select.blockSignals(False)
            # next nodes
            self.nextnodes_combo.blockSignals(True)
            self.nextnodes_combo.clear()
            self.nextnodes_combo.addItem("No next node")
            self.nextnodes_combo.setEnabled(False)
            self.nextnodes_combo.blockSignals(False)

    def _handle_context_menu_requested(self, qpoint):
        menu = QtWidgets.QMenu(self.vttable)
        add_taint_override = QtWidgets.QAction(
            "Add taint override", self.vttable)
        add_taint_override.triggered.connect(
            lambda: self._add_taint_override(self.vttable.indexAt(qpoint)))
        menu.addAction(add_taint_override)
        # add header height to qpoint, else menu is misplaced. not sure why...
        qpoint2 = qpoint + \
            QtCore.QPoint(0, self.vttable.horizontalHeader().height())
        menu.exec_(self.vttable.mapToGlobal(qpoint2))

    def _add_taint_override(self, index):
        regname = self.vtmodel.rows[index.row()].value
        mask, res = QtWidgets.QInputDialog.getText(
            None,
            "Add Taint override for %s" % regname,
            "Taint value for %s (e.g. TAINT_ALL, TAINT_NONE, 0b001, 0xabc)" %
            regname, text="TAINT_ALL")
        if not res:
            return
        htext = "reg[%s]" % regname
        self.s.overrides.append((self.s.current_ea, htext, mask))


class ValueTaintModel(QtCore.QAbstractTableModel):
    """
    Used as model in BinCATTaintedForm TableView widgets.

    Contains tainting and values for registers
    """
    def __init__(self, state, *args, **kwargs):
        super(ValueTaintModel, self).__init__(*args, **kwargs)
        self.s = state
        self.headers = ["register", "value"]
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
            self.rows = filter(lambda x: x.region == "reg", state.regaddrs)
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
        elif role == QtCore.Qt.ToolTipRole:
            regaddr = self.rows[index.row()]
            t = self.s.current_state.regtypes.get(regaddr, None)
            if t:
                return t[0]
            return
        elif role != QtCore.Qt.DisplayRole:
            return
        regaddr = self.rows[index.row()]

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
                    strval = concatv.__valuerepr__(16, True) + '...'
                    break
                concatv = concatv & nextv
            if not strval:
                strval = concatv.__valuerepr__(16, True)
            concatv = v[0]
            strtaint = ''
            for idx, nextv in enumerate(v[1:]):
                if idx > 50:
                    strtaint = concatv.__taintrepr__(16, True) + '...'
                    break
                concatv = concatv & nextv
            if not strtaint:
                strtaint = concatv.__taintrepr__(16, True)
            if strtaint != "":
                strval = Meminfo.color_valtaint(strval, strtaint)
            return strval

    def rowCount(self, parent):
        return len(self.rows)

    def columnCount(self, parent):
        return len(self.headers)


class BinCATOverridesForm_t(idaapi.PluginForm):
    """
    BinCAT Overrides display form
    Displays taint overrides defined by the user.
    An override is defined by:
    * an address
    * a register name (memory: not supported yet)
    * a taint value
    """

    def __init__(self, state, overrides_model):
        super(BinCATOverridesForm_t, self).__init__()
        self.s = state
        self.model = overrides_model
        self.shown = False
        self.created = False

    def OnCreate(self, form):
        self.created = True

        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        layout = QtWidgets.QGridLayout()

        # title label
        self.label = QtWidgets.QLabel('List of taint overrides (user-defined)')
        layout.addWidget(self.label, 0, 0)

        # Overrides Taint Table
        self.table = BinCATOverridesView(self.model)
        self.table.verticalHeader().setVisible(False)
        self.table.setSortingEnabled(True)
        self.table.setModel(self.model)
        self.s.overrides.register_callbacks(
            self.model.beginResetModel, self.model.endResetModel)
        self.table.verticalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)

        self.table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        # self.table.horizontalHeader().setMinimumHeight(36)

        layout.addWidget(self.table, 1, 0)

        self.btn_run = QtWidgets.QPushButton('&Re-run analysis', self.parent)
        self.btn_run.clicked.connect(self.s.re_run)
        layout.addWidget(self.btn_run, 2, 0)

        layout.setRowStretch(1, 0)

        self.parent.setLayout(layout)

    def OnClose(self, form):
        self.shown = False

    def Show(self):
        if self.shown:
            return
        self.shown = True
        return idaapi.PluginForm.Show(
            self, "BinCAT Overrides",
            options=(idaapi.PluginForm.FORM_PERSIST |
                     idaapi.PluginForm.FORM_SAVE |
                     idaapi.PluginForm.FORM_RESTORE |
                     idaapi.PluginForm.FORM_TAB))


class OverridesModel(QtCore.QAbstractTableModel):
    def __init__(self, state, *args, **kwargs):
        super(OverridesModel, self).__init__(*args, **kwargs)
        self.s = state
        self.headers = ["eip", "addr or reg", "taint"]

    def data(self, index, role):
        if role not in (QtCore.Qt.ForegroundRole, QtCore.Qt.DisplayRole,
                        QtCore.Qt.EditRole, QtCore.Qt.ToolTipRole):
            return
        col = index.column()
        row = index.row()
        if role == QtCore.Qt.ToolTipRole:
            if col == 1:
                return "Example valid addresses: reg[eax], mem[0x1234]"
            if col == 2:
                return ("Example taint values: 0x1234 (reg or mem), "
                        "TAINT_ALL (reg only), TAINT_NONE (reg only)")
            return
        if role == QtCore.Qt.ForegroundRole:
            # basic syntax checking
            if col not in (1, 2):
                return
            txt = self.s.overrides[row][col]
            if col == 1:
                if txt.endswith(']'):
                    if (txt.startswith('reg[') or
                            txt.startswith('heap[0x') or
                            txt.startswith('mem[0x') or
                            txt.startswith('stack[0x')):
                        return
            else:  # Taint column
                if txt in ("TAINT_ALL", "TAINT_NONE"):
                    if self.s.overrides[row][1].startswith("reg"):
                        return
                if txt.startswith("0x") or txt.startswith("0b"):
                    return
            return QtGui.QBrush(QtCore.Qt.red)
        rawdata = self.s.overrides[row][col]
        if col == 0:
            return "%x" % rawdata
        else:
            return str(rawdata)

    def setData(self, index, value, role):
        if role != QtCore.Qt.EditRole:
            return False
        col = index.column()
        row = index.row()
        if col == 0:
            if not all(c in 'abcdefABCDEF0123456789' for c in value):
                return False
            value = int(value, 16)
        if row > len(self.s.overrides):
            # new row
            r = [""] * len(self.headers)
            r[col] = value
            self.s.overrides.append(r)
        else:
            # existing row
            r = list(self.s.overrides[row])
            r[col] = value
            self.s.overrides[row] = r
        return True  # success

    def headerData(self, section, orientation, role):
        if orientation != QtCore.Qt.Horizontal:
            return
        if role == QtCore.Qt.DisplayRole:
            return self.headers[section]

    def flags(self, index):
        return (QtCore.Qt.ItemIsEditable
                | QtCore.Qt.ItemIsSelectable
                | QtCore.Qt.ItemIsEnabled)

    def rowCount(self, parent):
        return len(self.s.overrides)

    def columnCount(self, parent):
        return len(self.headers)

    def remove_row(self, checked):
        del self.s.overrides[BinCATOverridesView.clickedIndex]


class BinCATOverridesView(QtWidgets.QTableView):
    clickedIndex = None

    def __init__(self, model, parent=None):
        super(BinCATOverridesView, self).__init__(parent)
        self.m = model
        self.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectItems)
        self.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)

    def contextMenuEvent(self, event):
        if (self.m.rowCount(None) == 0 or
                len(self.selectedIndexes()) == 0):
            return
        menu = QtWidgets.QMenu(self)
        action = QtWidgets.QAction('Remove', self)
        action.triggered.connect(self.m.remove_row)
        menu.addAction(action)
        BinCATOverridesView.clickedIndex = self.indexAt(event.pos()).row()
        menu.popup(QtGui.QCursor.pos())

    def remove_row(self):
        try:
            index = self.table.selectedIndexes()[0].row()
        except IndexError:
            bc_log.warning("Could not identify selected row")
            return
        self.m.remove_row(index)


# Configurations list - panel, view, model


class BinCATConfigurationsForm_t(idaapi.PluginForm):
    def __init__(self, state, configurations_model):
        super(BinCATConfigurationsForm_t, self).__init__()
        self.s = state
        self.model = configurations_model
        self.shown = False
        self.created = False

    def OnCreate(self, form):
        self.created = True

        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        layout = QtWidgets.QGridLayout()

        # title label
        self.label = QtWidgets.QLabel('List of analysis configurations')
        layout.addWidget(self.label, 0, 0)

        # Configurations Table
        self.table = BinCATConfigurationsView(self.model)
        self.table.verticalHeader().setVisible(False)
        self.table.setSortingEnabled(True)
        self.table.setModel(self.model)
        self.s.configurations.register_callbacks(
            self.model.beginResetModel, self.model.endResetModel)
        self.table.verticalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)

        self.table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)

        layout.addWidget(self.table, 1, 0, 1, 2)

        self.edit_conf = QtWidgets.QPushButton('&Edit', self.parent)
        self.edit_conf.clicked.connect(self._edit)
        layout.addWidget(self.edit_conf, 2, 0)

        self.export_conf = QtWidgets.QPushButton('&Export', self.parent)
        self.export_conf.clicked.connect(self._export)
        layout.addWidget(self.export_conf, 2, 1)

        layout.setRowStretch(1, 0)

        self.parent.setLayout(layout)

    def OnClose(self, form):
        self.shown = False

    def Show(self):
        if self.shown:
            return
        self.shown = True
        return idaapi.PluginForm.Show(
            self, "BinCAT Configurations",
            options=(idaapi.PluginForm.FORM_PERSIST |
                     idaapi.PluginForm.FORM_SAVE |
                     idaapi.PluginForm.FORM_RESTORE |
                     idaapi.PluginForm.FORM_TAB))

    def _edit(self):
        selectionModel = self.table.selectionModel()
        if not selectionModel.hasSelection():
            return
        index = selectionModel.selectedRows()[0].row()
        name = self.s.configurations.names_cache[index]
        editdlg = EditConfigurationFileForm_t(self.parent, self.s)
        editdlg.set_config(str(self.s.configurations[name]))
        if editdlg.exec_() == QtWidgets.QDialog.Accepted:
            self.s.configurations[name] = self.s.edit_config

    def _export(self):
        selectionModel = self.table.selectionModel()
        if not selectionModel.hasSelection():
            return
        index = selectionModel.selectedRows()[0].row()
        name = self.s.configurations.names_cache[index]
        fname = idaapi.askfile_c(1, "*.ini", "Save exported configuration")
        if fname:
            with open(fname, 'w') as f:
                f.write(str(self.s.configurations[name]))


class ConfigurationsModel(QtCore.QAbstractTableModel):
    def __init__(self, state, *args, **kwargs):
        super(ConfigurationsModel, self).__init__(*args, **kwargs)
        self.s = state
        self.headers = ["configuration name"]

    def data(self, index, role):
        if role not in (QtCore.Qt.EditRole, QtCore.Qt.DisplayRole):
            return
        row = index.row()
        name = self.s.configurations.names_cache[row]
        return name

    def setData(self, index, value, role):
        if role != QtCore.Qt.EditRole:
            return False
        row = index.row()
        oldname = self.s.configurations.names_cache[row]
        # ensure names are unique
        for idx, name in enumerate(self.s.configurations.names_cache):
            if name == value and idx != row:
                return False
        if row > len(self.s.configurations):
            return False
        conf = self.s.configurations[oldname]
        del self.s.configurations[oldname]
        self.s.configurations[value] = conf
        return True

    def headerData(self, section, orientation, role):
        if orientation != QtCore.Qt.Horizontal:
            return
        if role == QtCore.Qt.DisplayRole:
            return self.headers[section]

    def flags(self, index):
        return (QtCore.Qt.ItemIsEditable
                | QtCore.Qt.ItemIsSelectable
                | QtCore.Qt.ItemIsEnabled)

    def rowCount(self, parent):
        return len(self.s.configurations)

    def columnCount(self, parent):
        return len(self.headers)

    def remove_row(self, checked):
        idx = BinCATConfigurationsView.clickedIndex
        name = self.s.configurations.names_cache[idx]
        del self.s.configurations[name]


class BinCATConfigurationsView(QtWidgets.QTableView):
    clickedIndex = None

    def __init__(self, model, parent=None):
        super(BinCATConfigurationsView, self).__init__(parent)
        self.m = model
        self.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectItems)
        self.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)

    def contextMenuEvent(self, event):
        if (self.m.rowCount(None) == 0 or
                len(self.selectedIndexes()) == 0):
            return
        menu = QtWidgets.QMenu(self)
        action = QtWidgets.QAction('Remove', self)
        action.triggered.connect(self.m.remove_row)
        menu.addAction(action)
        BinCATConfigurationsView.clickedIndex = self.indexAt(event.pos()).row()
        menu.popup(QtGui.QCursor.pos())

    def remove_row(self):
        try:
            index = self.table.selectedIndexes()[0].row()
        except IndexError:
            bc_log.warning("Could not identify selected row")
            return
        self.m.remove_row(index)


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


class HandleAddOverride(idaapi.action_handler_t):
    """
    Action handler for BinCAT/Add Override
    base class is not a newstyle class...
    """
    def __init__(self, state):
        self.s = state

    def activate(self, ctx):
        self.s.gui.show_windows()

        highlighted = idaapi.get_highlighted_identifier()
        if highlighted is None:
            highlighted = ''
        address = self.s.current_ea
        mask, res = QtWidgets.QInputDialog.getText(
            None,
            "Add Taint override for %s" % highlighted,
            "Taint value for %s (e.g. TAINT_ALL, TAINT_NONE, 0b001, 0xabc)" %
            highlighted, text="TAINT_ALL")
        if not res:
            return 1  # refresh IDA windows
        # guess whether highlighted text is register or address
        try:
            # is it a register?
            idautils.procregs.__getattr__(highlighted)
        except AttributeError:
            # assume it's a memory address
            htype = "mem"
        except TypeError:
            # IDA bug, assume it's a memory address
            bc_log.warning(
                "IDA bug encountered while trying to determine whether "
                "highlighted identifier %s is a memory address or register - "
                "assuming it's a memory address, edit value in Overrides "
                "window if that's incorrect", highlighted)
            htype = "mem"

        else:
            htype = "reg"
        htext = "%s[%s]" % (htype, highlighted)
        self.s.overrides.append((address, htext, mask))
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


class HandleRemap(idaapi.action_handler_t):
    """
    Action handler for BinCAT/Options
    """
    def __init__(self, state):
        self.state = state

    def activate(self, ctx):
        # display config window
        fname = idaapi.askfile_c(1, "*.*", "Save to binary")
        if fname:
            dump_binary(fname)
            self.state.remapped_bin_path = fname
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

    def __init__(self, state, gui):
        super(Hooks, self).__init__()
        self.s = state
        self.gui = gui

    def ready_to_run(self):
        self.gui.show_windows()

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
            idaapi.attach_action_to_popup(form, popup, "bincat:add_override",
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
        self.overrides_model = OverridesModel(state)
        self.BinCATOverridesForm = BinCATOverridesForm_t(
            state, self.overrides_model)
        self.configurations_model = ConfigurationsModel(state)
        self.BinCATConfigurationsForm = BinCATConfigurationsForm_t(
            state, self.configurations_model)

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
        # Add taint override menu
        add_taint_override_act = idaapi.action_desc_t(
            'bincat:add_override', 'Add taint override...',
            HandleAddOverride(self.s), 'Ctrl-Shift-O')
        idaapi.register_action(add_taint_override_act)

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
        idaapi.attach_action_to_menu("Edit/BinCAT/options",
                                     "bincat:options_act",
                                     idaapi.SETMENU_APP)

        # "Remap" menu
        remap_act = idaapi.action_desc_t(
            'bincat:remap_act', 'Dump remapped binary...',
            HandleRemap(self.s), '', 'BinCAT action', -1)
        idaapi.register_action(remap_act)
        idaapi.attach_action_to_menu("Edit/BinCAT/dump_mapped",
                                     "bincat:remap_act",
                                     idaapi.SETMENU_APP)
        self.hooks = Hooks(state, self)
        self.hooks.hook()

    def show_windows(self):
        self.BinCATDebugForm.Show()
        self.BinCATTaintedForm.Show()
        self.BinCATOverridesForm.Show()
        self.BinCATConfigurationsForm.Show()
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
