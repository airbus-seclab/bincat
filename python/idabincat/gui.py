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
import logging
import string
import re
import idaapi
import ida_kernwin
import ida_bytes
import idautils
from PyQt5 import QtCore, QtWidgets, QtGui
from PyQt5.QtCore import Qt
import pybincat.cfa as cfa
import idabincat.hexview as hexview
from idabincat.dump_binary import dump_binary
from idabincat.plugin_options import PluginOptions
from idabincat.analyzer_conf import AnalyzerConfig, ConfigHelpers, X64_GPR, X86_GPR

# Logging
bc_log = logging.getLogger('bincat.gui')
bc_log.setLevel(logging.DEBUG)

GREENS = [
    (169, 241, 100),
    (207, 207, 154),
    (192, 195, 188),
    (158, 199, 191),
    (195, 238, 153),
    (179, 179, 135),
    (118, 155, 148),
    (195, 207, 184),
    (241, 242, 184),
    (209, 230, 189),
    (152, 153, 120),
    ( 77,  98,  94),
    (254, 255, 202),
    ( 99, 133, 126),
    ( 86, 115, 109),
]

BLUES_AND_YELLOWS = [
    (173, 109,   0),
    (  2,  28,  66),
    (173, 170,   0),
    ( 41,   2,  67),
    (140,  88,   0),
    (  4,  68, 162),
    (246, 241,   0),
    ( 57,   2,  94),
    (207, 130,   0),
    (  4,  49, 114),
    (100,  98,   0),
    (246, 155,   0),
    ( 71,   3, 116),
    (100,  63,   0),
    (207, 203,   0),
    ( 99,   3, 165),
    (140, 137,   0),
    (  5,  58, 136),
    ( 84,   3, 139),
    (  4,  39,  92),
]


COLS = GREENS  # BLUES_AND_YELLOWS


def taint_color(n):
    r, g, b = COLS[n % len(COLS)]
    return b | g << 8 | r << 16


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
        self.s.edit_config.update_overrides(self.s.overrides, self.s.nops,
                                            self.s.skips)
        self.configtxt.setPlainText(str(self.s.edit_config.edit_str()))
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


class Meminfo(object):
    """
    Helper class to access memory as a str
    """
    def __init__(self, unrel, region, ranges):
        self.unrel = unrel
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
        if not values or values[0] is None:
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
        if not values or values[0] is None:
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
        if abs_addr is None:
            raise IndexError
        addr_value = cfa.Value(self.region, abs_addr, 32)
        in_range = [r for r in self.ranges if abs_addr >= r[0] and abs_addr <= r[1]]
        if not in_range or self.unrel is None:
            res = []
        else:
            res = self.unrel[addr_value]
        return res

    def get_type(self, idx):
        abs_addr = self.abs_addr_from_idx(idx)
        if not abs_addr:
            return ""
        addr_value = cfa.Value(self.region, abs_addr, 32)
        in_range = [r for r in self.ranges if abs_addr >= r[0] and abs_addr <= r[1]]
        if not in_range:
            return ""
        t = self.unrel.getregtype(addr_value)
        if t:
            return t
        return ""

    def abs_addr_from_idx(self, idx):
        """
        convert idx relative to meminfo start to physical addr
        """
        if idx < 0 or idx > self.length:
            return None
        return idx+self.start


class BinCATMemForm_t(ida_kernwin.PluginForm):
    """
    BinCAT memory display form.
    """
    def __init__(self, state):
        super(BinCATMemForm_t, self).__init__()
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
        #: region name (0+ characters) -> address
        self.last_visited = dict((k, None) for k in list(cfa.PRETTY_REGIONS.keys()))
        self.pretty_to_int_map = \
            dict((v, k) for k, v in list(cfa.PRETTY_REGIONS.items()))

    def handle_selection_range_changed(self, bindex):
        if bindex < 0:
            return
        cur_reg = self.current_region
        start, stop = self.mem_ranges[cur_reg][self.current_range_idx]
        if bindex > stop-start:
            return
        self.last_visited[cur_reg] = bindex + start

    def handle_new_override(self, abs_start, abs_end, re_run):
        # add override for each byte
        mask, res = QtWidgets.QInputDialog.getText(
            None,
            "Add override...",
            "Override each byte in the range %0X-%0X (e.g. |00|!|00| (value=0, untainted), !|FF| (fully tainted, do not change value))"
            % (abs_start, abs_end),
            text="!|FF|")
        if not res:
            return

        region = cfa.PRETTY_REGIONS[self.current_region]
        if region == 'global':
            region = 'mem'
        for addr in range(abs_start, abs_end+1):
            ea = self.s.current_ea
            addrstr = "%s[0x%02X]" % (region, addr)
            self.s.add_or_replace_override(ea, addrstr, mask)
        if re_run:
            self.s.re_run()

    def update_range(self, crangeidx):
        if self.current_range_idx == crangeidx:
            return
        self.current_range_idx = crangeidx
        pretty_region = self.region_select.currentText()
        if pretty_region not in self.pretty_to_int_map:
            self.pretty_to_int_map[pretty_region] = pretty_region  # ex: /h\d+/
        cur_reg = self.pretty_to_int_map[pretty_region]
        new_range = self.mem_ranges[cur_reg][crangeidx]
        # XXX only create a new Meminfo object on EA change, load ranges from
        # node in Meminfo __init__ ?
        meminfo = Meminfo(self.s.current_unrel, cur_reg, [new_range])
        self.hexwidget.setNewMem(meminfo)
        self.last_visited[cur_reg] = new_range[0]

    def update_region(self, pretty_region):
        if pretty_region not in self.pretty_to_int_map:
            self.pretty_to_int_map[pretty_region] = pretty_region  # ex: /h\d+/
        region = self.pretty_to_int_map[pretty_region]
        self.current_region = region
        self.range_select.blockSignals(True)
        self.range_select.clear()
        for r in self.mem_ranges[region]:
            self.range_select.addItem("%08x-%08x" % r)
        self.range_select.blockSignals(False)
        # find address range idx correponding to last visited addr for
        # region
        newrangeidx = 0
        lva = self.last_visited.get(region, None)
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

        if self.s.current_unrel:
            self.mem_ranges = self.s.current_unrel.mem_ranges()
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

            if not self.mem_ranges:
                # happens in backward mode: nodes having no defined memory
                return
            former_region = self.region_select.currentText()
            newregion = None
            newregidx = -1
            self.region_select.blockSignals(True)
            self.region_select.clear()
            for ridx, k in enumerate(self.mem_ranges.keys()):
                pretty_reg = cfa.PRETTY_REGIONS.get(k, k)
                self.region_select.addItem(pretty_reg)
                if pretty_reg == former_region:
                    newregion = pretty_reg
                    newregidx = ridx
                if newregion is None:
                    newregion = pretty_reg
                    newregidx = 0
            self.region_select.setCurrentIndex(newregidx)
            self.region_select.blockSignals(False)

            self.range_select.blockSignals(True)
            self.range_select.clear()

            for r in list(self.mem_ranges.values())[0]:
                self.range_select.addItem("%08x-%08x" % r)
            self.range_select.blockSignals(False)
            self.update_region(newregion)

    def OnClose(self, form):
        self.shown = False

    def Show(self):
        if self.shown:
            return
        self.shown = True
        return ida_kernwin.PluginForm.Show(
            self, "BinCAT Memory",
            options=(ida_kernwin.PluginForm.WOPN_PERSIST |
                     ida_kernwin.PluginForm.WOPN_MENU |
                     ida_kernwin.PluginForm.WCLS_SAVE |
                     ida_kernwin.PluginForm.WOPN_RESTORE |
                     ida_kernwin.PluginForm.WOPN_TAB))


class BinCATConfigForm_t(ida_kernwin.PluginForm):
    """
    BinCAT initial configuration form
    This form allows the definition and edition of
    initial registers and memory
    """

    def __init__(self, state, cfgregmodel, cfgmemmodel):
        super(BinCATConfigForm_t, self).__init__()
        self.s = state
        self.cfgregmodel = cfgregmodel
        self.cfgmemmodel = cfgmemmodel
        self.shown = False
        self.created = False
        self.index = None

    def OnCreate(self, form):
        self.created = True

        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        layout = QtWidgets.QGridLayout(self.parent)

        # ----------- TABLES -----------------------
        # Splitter for reg & mem tables
        tables_split = QtWidgets.QSplitter(Qt.Vertical, self.parent)
        layout.addWidget(tables_split, 0, 0)

        # Inital config: registers table
        self.regs_table = QtWidgets.QTableView(self.parent)
        self.regs_table.setItemDelegate(RegisterItemDelegate())
        self.regs_table.setModel(self.cfgregmodel)
        self.regs_table.setShowGrid(False)
        self.regs_table.verticalHeader().setVisible(False)
        self.regs_table.verticalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)
        self.regs_table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.Interactive)
        self.regs_table.horizontalHeader().setMinimumHeight(36)
        # Make it editable
        self.regs_table.setEditTriggers(
            QtWidgets.QAbstractItemView.AllEditTriggers)
        # Custom menu
        self.regs_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.regs_table.customContextMenuRequested.connect(
            self._regs_table_menu)

        tables_split.addWidget(self.regs_table)

        # Inital config: mem table
        self.mem_table = QtWidgets.QTableView(self.parent)
        self.mem_table.setItemDelegate(RegisterItemDelegate())
        self.mem_table.setModel(self.cfgmemmodel)
        self.mem_table.setShowGrid(True)
        self.mem_table.verticalHeader().setVisible(False)
        self.mem_table.verticalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)
        # Make it editable
        self.mem_table.setEditTriggers(
            QtWidgets.QAbstractItemView.NoEditTriggers
            | QtWidgets.QAbstractItemView.DoubleClicked)

        self.mem_table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.Interactive)
        self.mem_table.horizontalHeader().setStretchLastSection(True)
        self.mem_table.horizontalHeader().setMinimumHeight(36)
        # Custom menu
        self.mem_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.mem_table.customContextMenuRequested.connect(
            self._mem_table_menu)

        tables_split.addWidget(self.mem_table)

        # Coredump path, hidden by default
        self.lbl_core_path = QtWidgets.QLabel()
        self.lbl_core_path.hide()
        tables_split.addWidget(self.lbl_core_path)

        # For backward we just show a help text
        self.lbl_back_help = QtWidgets.QLabel("Backward mode uses overrides, initial "
                                              "configuration makes no sense in this mode.")
        self.lbl_back_help.hide()
        tables_split.addWidget(self.lbl_back_help)

        # ----------- Config options -----------------------
        # Horizontal splitter for config boxes
        cfg_split = QtWidgets.QSplitter(self.parent)
        layout.addWidget(cfg_split, 1, 0)
        # Config name label
        self.curlabel = QtWidgets.QLabel('Current config:')
        cfg_split.addWidget(self.curlabel)

        # current config combo
        self.cfg_select = QtWidgets.QComboBox()
        self.cfg_select.currentIndexChanged.connect(self._load_config)
        cfg_split.addWidget(self.cfg_select)

        # Duplicate that config button
        self.btn_dup_cfg = QtWidgets.QPushButton('Duplicate')
        self.btn_dup_cfg.clicked.connect(lambda: self._save_config(None, True))
        cfg_split.addWidget(self.btn_dup_cfg)

        # Delete that config button
        self.btn_del_cfg = QtWidgets.QPushButton('Delete')
        self.btn_del_cfg.clicked.connect(self._del_config)
        self.btn_del_cfg.setIcon(self.btn_del_cfg.style().standardIcon(
            QtWidgets.QStyle.SP_TrashIcon))
        cfg_split.addWidget(self.btn_del_cfg)

        # Edit that config button
        self.btn_edit_cfg = QtWidgets.QPushButton('&Edit...')
        self.btn_edit_cfg.clicked.connect(self._edit_config)
        self.btn_edit_cfg.setIcon(self.btn_edit_cfg.style().standardIcon(
            QtWidgets.QStyle.SP_FileDialogContentsView))
        cfg_split.addWidget(self.btn_edit_cfg)

        # Load config button
        self.btn_load = QtWidgets.QPushButton('&Load...')
        self.btn_load.setIcon(self.btn_load.style().standardIcon(
            QtWidgets.QStyle.SP_DialogOpenButton))
        self.btn_load.clicked.connect(self._load_file)
        cfg_split.addWidget(self.btn_load)

        # Export config button
        self.btn_export = QtWidgets.QPushButton('Export...')
        self.btn_export.setIcon(self.btn_export.style().standardIcon(
            QtWidgets.QStyle.SP_DialogOpenButton))
        self.btn_export.clicked.connect(self._export_file)
        cfg_split.addWidget(self.btn_export)

        # leave space for comboboxes in cfg_split, rather than between widgets
        cfg_split.setStretchFactor(0, 0)
        cfg_split.setStretchFactor(1, 1)
        cfg_split.setStretchFactor(2, 0)

        # Horizontal splitter for addresses
        addr_split = QtWidgets.QSplitter(self.parent)
        layout.addWidget(addr_split, 2, 0)

        # Start address
        lbl_start_addr = QtWidgets.QLabel("Start addr:")
        self.ip_start_addr = QtWidgets.QLineEdit(self.parent)
        self.btn_copy_start = QtWidgets.QPushButton('<- Current')
        self.btn_copy_start.clicked.connect(self._copy_start)

        # Stop address
        lbl_stop_addr = QtWidgets.QLabel("Stop addr:")
        self.ip_stop_addr = QtWidgets.QLineEdit(self.parent)
        self.btn_copy_stop = QtWidgets.QPushButton('<- Current')
        self.btn_copy_stop.clicked.connect(self._copy_stop)

        self.radio_group = QtWidgets.QButtonGroup()
        self.radio_forward = QtWidgets.QRadioButton("Forward")
        self.radio_backward = QtWidgets.QRadioButton("Backward")
        self.radio_forward.toggled.connect(self._forward_toggled)

        self.radio_group.addButton(self.radio_forward)
        self.radio_group.addButton(self.radio_backward)

        self.radio_forward.setChecked(True)

        addr_split.addWidget(lbl_start_addr)
        addr_split.addWidget(self.ip_start_addr)
        addr_split.addWidget(self.btn_copy_start)
        addr_split.addWidget(lbl_stop_addr)
        addr_split.addWidget(self.ip_stop_addr)
        addr_split.addWidget(self.btn_copy_stop)
        addr_split.addWidget(self.radio_forward)
        addr_split.addWidget(self.radio_backward)

        addr_split.setStretchFactor(0, 0)
        addr_split.setStretchFactor(1, 1)  # ip_start
        addr_split.setStretchFactor(2, 0)  # btn copy start
        addr_split.setStretchFactor(3, 0)  # lbl_stop
        addr_split.setStretchFactor(4, 1)  # ip_stop
        addr_split.setStretchFactor(5, 0)
        addr_split.setStretchFactor(6, 0)
        addr_split.setStretchFactor(7, 0)

        # ----------- Analysis buttons -----------------------
        # Horizontal splitter for buttons
        btn_split = QtWidgets.QSplitter(self.parent)
        layout.addWidget(btn_split, 3, 0)

        self.btn_start = QtWidgets.QPushButton('&Start')
        self.btn_start.clicked.connect(self.launch_analysis)
        btn_split.addWidget(self.btn_start)

        self.chk_remap = QtWidgets.QCheckBox('&Remap binary')
        # Only check by default if the file is not an ELF
        if ConfigHelpers.get_file_type() != "elf":
            self.chk_remap.setChecked(self.s.remap_binary)

        btn_split.addWidget(self.chk_remap)
        # Save config button
        self.btn_save_cfg = QtWidgets.QPushButton('&Save')
        self.btn_save_cfg.clicked.connect(self._save_config)
        btn_split.addWidget(self.btn_save_cfg)

        self.chk_save = QtWidgets.QCheckBox('Save &configuration to IDB')
        self.chk_save.setChecked(PluginOptions.get("save_to_idb") == "True")
        btn_split.addWidget(self.chk_save)

        self.parent.setLayout(layout)

        self.cfg_select.clear()
        self.cfg_select.addItems(
            self.s.configurations.names_cache + ['(new)'])

    def _forward_toggled(self, checked):
        if not checked:  # Backward checked
            # Backward uses overrides so we hide the main config
            idaapi.warning("Backward mode is _experimental_, expect bugs !")
            self.regs_table.hide()
            self.mem_table.hide()
            self.lbl_back_help.show()
        else:
            self.lbl_back_help.hide()
            self.regs_table.show()
            self.mem_table.show()

    def _regs_table_menu(self, qpoint):
        menu = QtWidgets.QMenu(self.regs_table)
        all_taint_top = QtWidgets.QAction(
            "Set all taints to top", self.regs_table)
        all_taint_top.triggered.connect(self.cfgregmodel.all_taint_top)
        menu.addAction(all_taint_top)
        # add header height to qpoint, else menu is misplaced. not sure why...
        qpoint2 = qpoint + \
            QtCore.QPoint(0, self.mem_table.horizontalHeader().height())
        menu.exec_(self.regs_table.mapToGlobal(qpoint2))

    def _mem_table_menu(self, qpoint):
        menu = QtWidgets.QMenu(self.mem_table)
        add_mem_entry = QtWidgets.QAction(
            "Add memory entry", self.mem_table)
        add_mem_entry.triggered.connect(
            lambda: self._add_mem_entry(self.mem_table.indexAt(qpoint)))
        menu.addAction(add_mem_entry)
        remove_mem_entry = QtWidgets.QAction(
            "Remove memory entry", self.mem_table)
        remove_mem_entry.triggered.connect(
            lambda: self._remove_mem_entry(self.mem_table.indexAt(qpoint)))
        menu.addAction(remove_mem_entry)
        # add header height to qpoint, else menu is misplaced. not sure why...
        qpoint2 = qpoint + \
            QtCore.QPoint(0, self.mem_table.horizontalHeader().height())
        menu.exec_(self.mem_table.mapToGlobal(qpoint2))

    def _add_mem_entry(self, index):
        self.cfgmemmodel.add_mem_entry(index.row())
        return

    def _remove_mem_entry(self, index):
        self.cfgmemmodel.remove_mem_entry(index.row())
        return

    def _copy_start(self):
        self.ip_start_addr.setText("0x%X" % idaapi.get_screen_ea())

    def _copy_stop(self):
        self.ip_stop_addr.setText("0x%X" % idaapi.get_screen_ea())

    def get_analysis_method(self):
        if self.radio_forward.isChecked():
            analysis_method = "forward_binary"
        else:
            analysis_method = "backward"
        return analysis_method

    def _update_edit_config(self):
        try:
            start_addr = int(self.ip_start_addr.text(), 16)
        except ValueError as e:
            bc_log.error('Provided start address is invalid (%s)', e)
            return
        if self.ip_stop_addr.text() == "":
            stop_addr = None
        else:
            stop_addr = self.ip_stop_addr.text()
        analysis_method = self.get_analysis_method()

        self.s.edit_config.remap = self.chk_remap.isChecked()
        self.s.edit_config.analysis_ep = start_addr
        self.s.edit_config.stop_address = stop_addr
        self.s.edit_config.analysis_method = analysis_method

    def launch_analysis(self):
        bc_log.info("Launching the analyzer")

        # Update start_addr/stop_addr/method
        self._update_edit_config()

        # always save config under "(last used)" slot
        self._save_config("(last used)")

        # if requested, also save under user-specified slot
        if self.chk_save.isChecked():
            self._save_config()

        if self.chk_remap.isChecked():
            if (self.s.remapped_bin_path is None or
                        not os.path.isfile(self.s.remapped_bin_path)
                        or not self.s.remapped_sections):
                fname = ConfigHelpers.askfile(None, "Save remapped binary")
                if not fname:
                    bc_log.error(
                        'No filename provided. You can provide a filename or '
                        'uncheck the "Remap binary" option.')
                    return
                sections = dump_binary(fname)
                if not sections:
                    bc_log.error("Could not remap binary")
                    return
                self.s.remapped_bin_path = fname
                self.s.remapped_sections = sections
            self.s.remap_binary = True
            self.s.edit_config.binary_filepath = self.s.remapped_bin_path
            self.s.edit_config.format = "manual"
            self.s.edit_config.replace_section_mappings(self.s.remapped_sections)
        else:
            if self.s.edit_config.format != "elf":
                bc_log.warning("This file format is not natively supported by"
                               "BinCAT, you should probably remap the binary.")
            self.s.remap_binary = False

        self.s.current_config = self.s.edit_config
        self.s.start_analysis()

    # callback when the "Export" button is clicked
    def _export_file(self):
        fname = ConfigHelpers.askfile("*.ini", "Save exported configuration")
        if fname:
            with open(fname, 'w') as f:
                f.write(str(self.s.edit_config))

    # callback when the "Load" button is clicked
    def _load_file(self):
        options = QtWidgets.QFileDialog.Options()
        default_filename = os.path.join(os.path.dirname(__file__),
                                        'init.ini')
        filename, _ = QtWidgets.QFileDialog.getOpenFileName(
            self.parent, "Choose configuration file", default_filename,
            "Configuration files (*.ini)", options=options)
        if not filename or not os.path.exists(filename):
            return

        self.s.edit_config = AnalyzerConfig.load_from_str(
            open(filename, 'r').read())
        self.update_from_edit_config()
        # if the current config is "new", ask for a name
        if self.index == len(self.s.configurations.names_cache):
            self._save_config()

    # callback when the "Delete" button is clicked
    def _del_config(self):
        # check if we have a config,
        if (self.index and
                self.index > 0 and  # last used is special
                self.index != len(self.s.configurations.names_cache)):  # (new)
            name = self.s.configurations.names_cache[self.index]
            del self.s.configurations[name]
            self.update_config_list()

    # Called when the edit combo is changed
    def _load_config(self, index):
        if not self.s.current_ea:
            self.s.current_ea = idaapi.get_screen_ea()
        self.index = index
        if index == len(self.s.configurations.names_cache):
            # new config
            self.s.edit_config = self.s.configurations.new_config(
                self.s.current_ea, None, self.get_analysis_method())
        else:
            name = self.s.configurations.names_cache[index]
            self.s.edit_config = self.s.configurations[name]
        self.update_from_edit_config()

    # Update various fields from the current edit_config
    # useful when the configuration was edited manually
    def update_from_edit_config(self):
        # load overrides, skips, nops
        config = self.s.edit_config
        self.s.overrides.clear()
        self.s.overrides.extend(config.overrides)
        self.s.nops.clear()
        self.s.nops.extend(config.nops)
        self.s.skips.clear()
        self.s.skips.extend(config.skips)
        self.cfgregmodel.beginResetModel()
        self.cfgmemmodel.beginResetModel()
        self.chk_remap.setChecked(config.remap)
        # If we have a coredump, disable mem/regs
        if config.coredump:
            self.regs_table.setEnabled(False)
            self.mem_table.setEnabled(False)
            self.lbl_core_path.setText("Coredump path: "+config.coredump)
            self.lbl_core_path.show()
        else:
            self.regs_table.setEnabled(True)
            self.mem_table.setEnabled(True)
            self.lbl_core_path.hide()
        self.ip_start_addr.setText(str(config.analysis_ep))
        cut = config.stop_address or ""
        self.ip_stop_addr.setText(cut)
        if config.analysis_method == "forward_binary":
            self.radio_forward.setChecked(True)
        else:
            self.radio_backward.setChecked(True)
        self.cfgregmodel.endResetModel()
        self.cfgmemmodel.endResetModel()

    def update_config_list(self, to_select=None):
        self.cfg_select.clear()
        self.cfg_select.addItems(
            self.s.configurations.names_cache + ['(new)'])
        if to_select:
            self.cfg_select.setCurrentText(to_select)

    # callback when the "save" button is clicked
    def _save_config(self, config_name=None, always_prompt=False):
        ea_int = int(self.ip_start_addr.text(), 16)
        should_update = False
        if not config_name:
            idx = self.cfg_select.currentIndex()
            bc_log.debug("Saving config, idx = %d, cache: %s", idx, repr(self.s.configurations.names_cache))
            if always_prompt or idx == self.cfg_select.count()-1:
                # new config, prompt name
                config_name, res = QtWidgets.QInputDialog.getText(
                    self.parent,
                    "Configuration name",
                    "Under what name should this new configuration be saved?",
                    text="0x%0X" % self.s.current_ea)
                if not res:
                    return
                should_update = True
            else:
                config_name = self.s.configurations.names_cache[idx]
        self.s.configurations[config_name] = self.s.edit_config
        self.s.configurations.set_pref(ea_int, config_name)
        if should_update:
            self.update_config_list(config_name)

    # callback when the "edit" button is clicked
    def _edit_config(self):
        # Update start_addr/stop_addr/method
        self._update_edit_config()
        editdlg = EditConfigurationFileForm_t(self.parent, self.s)
        if editdlg.exec_() == QtWidgets.QDialog.Accepted:
            self.update_from_edit_config()

    def OnClose(self, form):
        self.shown = False

    def Show(self):
        if self.shown:
            return
        self.shown = True
        return ida_kernwin.PluginForm.Show(
            self, "BinCAT Configuration",
            options=(ida_kernwin.PluginForm.WOPN_PERSIST |
                     ida_kernwin.PluginForm.WCLS_SAVE |
                     ida_kernwin.PluginForm.WOPN_MENU |
                     ida_kernwin.PluginForm.WOPN_RESTORE |
                     ida_kernwin.PluginForm.WOPN_TAB))


class BinCATDebugForm_t(ida_kernwin.PluginForm):
    """
    BinCAT Debug form: display IL and instruction bytes, if present in BinCAT
    output.
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

        self.stmt_lbl = QtWidgets.QLabel("IL statements")
        self.stmt_data = QtWidgets.QLabel()
        self.bytes_lbl = QtWidgets.QLabel("Instruction bytes")
        self.bytes_data = QtWidgets.QLabel()

        self.stmt_data.setTextInteractionFlags(
            Qt.TextSelectableByMouse |
            Qt.TextSelectableByKeyboard)
        self.stmt_data.setWordWrap(True)
        self.bytes_data.setTextInteractionFlags(
            Qt.TextSelectableByMouse |
            Qt.TextSelectableByKeyboard)
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

    def update(self, node):
        if node:
            self.stmt_txt = node.statements.replace('____', '    ')
            self.bytes_txt = node.bytes
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
        return ida_kernwin.PluginForm.Show(
            self, "BinCAT IL",
            options=(ida_kernwin.PluginForm.WOPN_PERSIST |
                     ida_kernwin.PluginForm.WCLS_SAVE |
                     ida_kernwin.PluginForm.WOPN_RESTORE |
                     ida_kernwin.PluginForm.WOPN_TAB))


class RegisterItemDelegate(QtWidgets.QStyledItemDelegate):
    """
    http://stackoverflow.com/questions/35397943/how-to-make-a-fast-qtableview-with-html-formatted-and-clickable-cells
    Represents tainted data with colors in the BinCATRegistersForm_t
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


class BinCATRegistersForm_t(ida_kernwin.PluginForm):
    """
    BinCAT Register values form
    This form displays the values of tainted registers
    """

    def __init__(self, state, regsinfo_model):
        super(BinCATRegistersForm_t, self).__init__()
        self.s = state
        self.regsinfo_model = regsinfo_model
        self.shown = False
        self.created = False
        self.rvatxt = ""

    def OnCreate(self, form):
        self.created = True

        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        layout = QtWidgets.QGridLayout(self.parent)

        splitter1 = QtWidgets.QSplitter(self.parent)
        layout.addWidget(splitter1, 0, 0)

        # RVA address label
        self.alabel = QtWidgets.QLabel('RVA: %s' % self.rvatxt)
        splitter1.addWidget(self.alabel)

        # Next node id label
        self.nnlabel = QtWidgets.QLabel('Next node(s):')
        splitter1.addWidget(self.nnlabel)

        # Goto combo box
        self.nextnodes_combo = QtWidgets.QComboBox()
        self.nextnodes_combo.currentTextChanged.connect(self.goto_next)
        splitter1.addWidget(self.nextnodes_combo)
        # leave space for comboboxes in splitter, rather than between widgets
        splitter1.setStretchFactor(0, 0)
        splitter1.setStretchFactor(1, 0)
        splitter1.setStretchFactor(2, 1)

        splitter2 = QtWidgets.QSplitter(self.parent)
        layout.addWidget(splitter2, 1, 0)

        # Node id label
        self.nilabel = QtWidgets.QLabel('Node:')
        splitter2.addWidget(self.nilabel)

        # Node combobox
        self.node_select = QtWidgets.QComboBox()
        self.node_select.currentTextChanged.connect(self.update_node)
        splitter2.addWidget(self.node_select)

        # Unrel id label
        self.unrellabel = QtWidgets.QLabel('Path:')
        splitter2.addWidget(self.unrellabel)

        # Unrel combobox
        self.unrel_select = QtWidgets.QComboBox()
        self.unrel_select.currentTextChanged.connect(self.update_unrel)
        splitter2.addWidget(self.unrel_select)

        splitter2.setStretchFactor(0, 0)
        splitter2.setStretchFactor(1, 1)
        splitter2.setStretchFactor(2, 0)
        splitter2.setStretchFactor(3, 1)

        # Registers Info Table
        self.regs_table = QtWidgets.QTableView(self.parent)
        self.regs_table.setItemDelegate(RegisterItemDelegate())
        self.regs_table.setSortingEnabled(True)
        self.regs_table.setModel(self.regsinfo_model)
        self.regs_table.setShowGrid(False)
        self.regs_table.verticalHeader().setVisible(False)
        self.regs_table.verticalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)
        self.regs_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.regs_table.customContextMenuRequested.connect(
            self._handle_context_menu_requested)
        # width from the model are not respected, not sure why...
        for idx, w in enumerate(self.regsinfo_model.colswidths):
            self.regs_table.setColumnWidth(idx, w)

        self.regs_table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)
        self.regs_table.horizontalHeader().setStretchLastSection(True)
        self.regs_table.horizontalHeader().setMinimumHeight(36)

        layout.addWidget(self.regs_table, 2, 0)

        layout.setRowStretch(2, 0)

        self.parent.setLayout(layout)

        if isinstance(self.s.current_ea, int):
            self.update_current_ea(self.s.current_ea)

    def OnClose(self, form):
        self.shown = False

    def Show(self):
        if self.shown:
            return
        self.shown = True
        return ida_kernwin.PluginForm.Show(
            self, "BinCAT Registers",
            options=(ida_kernwin.PluginForm.WOPN_PERSIST |
                     ida_kernwin.PluginForm.WCLS_SAVE |
                     ida_kernwin.PluginForm.WOPN_RESTORE |
                     ida_kernwin.PluginForm.WOPN_TAB))

    def update_node(self, node):
        node_id = node.split(' ')[0]
        if node != "" and (not self.s.current_node or
                           node_id != self.s.current_node.node_id):
            self.node_select.blockSignals(True)
            self.s.set_current_node(node_id)
            self.node_select.blockSignals(False)

    def update_unrel(self, unrel):
        unrel_id = unrel.split(' ')[0]
        node_id = self.node_select.currentText().split(' ')[0]
        if unrel != "" and (not self.s.current_unrel or
                            unrel_id != self.s.current_unrel.unrel_id):
            self.node_select.blockSignals(True)
            self.s.set_current_node(node_id, unrel_id=unrel_id)
            self.node_select.blockSignals(False)

    def goto_next(self, node):
        if self.nextnodes_combo.currentIndex() == 0:
            return
        idaapi.jumpto(int(node.split(' ')[3], 16))

    def update_current_ea(self, ea):
        """
        :param ea: int or long
        """
        self.rvatxt = '0x%08X' % ea
        if not (self.shown and self.created):
            return
        self.alabel.setText('RVA: %s' % self.rvatxt)
        node = self.s.current_node
        if node:
            # nodes & unrels at current EA
            self.node_select.blockSignals(True)
            self.unrel_select.blockSignals(True)
            self.node_select.clear()
            self.unrel_select.clear()
            node_ids = sorted(self.s.current_node_ids, key=int)
            unrel_ids = sorted(list(self.s.current_node.unrels.keys()), key=int)
            for idx, node_id in enumerate(node_ids):
                self.node_select.addItem(
                    node_id + ' (%d other nodes)' % (len(node_ids)-1))
                if str(node_id) == self.s.current_node.node_id:
                    self.node_select.setCurrentIndex(idx)
            for idx, unrel_id in enumerate(unrel_ids):
                self.unrel_select.addItem(
                    unrel_id + ' (%d other paths)' % (len(unrel_ids)-1))
                if str(unrel_id) == self.s.current_unrel.unrel_id:
                    self.unrel_select.setCurrentIndex(idx)
            self.node_select.setEnabled(len(node_ids) != 1)
            self.unrel_select.setEnabled(len(unrel_ids) != 1)
            self.node_select.blockSignals(False)
            self.unrel_select.blockSignals(False)
            # next nodes
            self.nextnodes_combo.blockSignals(True)
            self.nextnodes_combo.clear()
            next_nodes = self.s.cfa.next_nodes(self.s.current_node.node_id)
            next_nodes_txt = ["node %s at 0x%0X" % (s.node_id, s.address.value)
                              for s in next_nodes]
            if len(next_nodes_txt) == 0:
                self.nextnodes_combo.addItem("No data")
                self.nextnodes_combo.setEnabled(False)
            else:
                for nid in next_nodes_txt:
                    self.nextnodes_combo.addItem("")
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
        menu = QtWidgets.QMenu(self.regs_table)
        add_override = QtWidgets.QAction(
            "Add override...", self.regs_table)
        add_override.triggered.connect(
            lambda: self._add_override(self.regs_table.indexAt(qpoint)))
        menu.addAction(add_override)
        # add header height to qpoint, else menu is misplaced. not sure why...
        qpoint2 = qpoint + \
            QtCore.QPoint(0, self.regs_table.horizontalHeader().height())
        menu.exec_(self.regs_table.mapToGlobal(qpoint2))

    def _add_override(self, index):
        regname = self.regsinfo_model.rows[index.row()].value
        mask, res = QtWidgets.QInputDialog.getText(
            None,
            "Add override for %s" % regname,
            "Override [value]!taint for %s (e.g. !TAINT_ALL, !TAINT_NONE, 0x00|!|ffffffff|, )" %
            regname, text="!TAINT_ALL")
        if not res:
            return
        htext = "reg[%s]" % regname
        self.s.add_or_replace_override(self.s.current_ea, htext, mask)


class InitConfigMemModel(QtCore.QAbstractTableModel):
    """
    Used as model in BinCATConfigForm_t TableView memory widget.

    Contains tainting and values for memory
    """
    def __init__(self, state, *args, **kwargs):
        super(InitConfigMemModel, self).__init__(*args, **kwargs)
        self.s = state
        self.headers = ["region", "address", "value"]
        #: list of Value (addresses)
        self.rows = []
        self.mono_font = QtGui.QFont("Monospace")
        self.config = None
        self.mem_addr_re = re.compile(
            r"(?P<region>[^[]+)\[(?P<address>[^\]]+)\]")

    def flags(self, index):
        flags = (Qt.ItemIsSelectable
                 | Qt.ItemIsEnabled)
        flags |= Qt.ItemIsEditable
        return flags

    def endResetModel(self):
        """
        Rebuild a list of rows
        """
        if self.s.edit_config is not None:
            self.config = self.s.edit_config
        else:
            return
        #: list of Values (addresses)
        if self.config:
            self.rows = self.config.state.mem
        else:
            self.rows = []

        super(InitConfigMemModel, self).endResetModel()

    def headerData(self, section, orientation, role):
        if orientation != Qt.Horizontal:
            return
        if role == Qt.DisplayRole:
            return self.headers[section]

    def setData(self, index, value, role):
        if role != Qt.EditRole:
            return False
        col = index.column()
        row = index.row()
        if row > len(self.rows):
            return False
        else:
            # existing row
            self.rows[row][col] = value
            if self.config:
                self.config.state.set_mem(self.rows)
        return True   # success

    def data(self, index, role):
        col = index.column()
        if role == Qt.FontRole:
            return self.mono_font
        elif role == Qt.ToolTipRole:  # add tooltip ?
            return
        elif role != Qt.DisplayRole and role != Qt.EditRole:
            return

        mem = self.rows[index.row()]
        return mem[col]

    def remove_mem_entry(self, index):
        if index < len(self.rows) and index >= 0:
            del self.rows[index]
            self.config.state.set_mem(self.rows)
            self.endResetModel()

    def add_mem_entry(self, index):
        default = ["mem", "0x0", "0x0"]
        if index >= len(self.rows) or index < 0:
            self.rows.append(default)
        else:
            self.rows.insert(index+1, default)
        self.config.state.set_mem(self.rows)
        self.endResetModel()

    def rowCount(self, parent):
        return len(self.rows)

    def columnCount(self, parent):
        return len(self.headers)


class InitConfigRegModel(QtCore.QAbstractTableModel):
    """
    Used as model in BinCATConfigForm_t TableView register's widget.

    Contains tainting and values for registers
    """
    def __init__(self, state, *args, **kwargs):
        super(InitConfigRegModel, self).__init__(*args, **kwargs)
        self.s = state
        self.headers = ["register", "value", "top", "taint"]
        #: list of Value (addresses)
        self.rows = []
        self.mono_font = QtGui.QFont("Monospace")
        self.config = None
        # regex to parse init syntax for registers
        # example: reg[eax] = 100?0xF!0xF0
        self.reg_re = re.compile(
            r"(?P<value>[^!?]+)(\?(?P<top>[^!]+))?(!(?P<taint>.*))?")

    def flags(self, index):
        flags = (Qt.ItemIsSelectable
                 | Qt.ItemIsEnabled)
        if index.column() > 0:
            flags |= Qt.ItemIsEditable
        return flags

    def all_taint_top(self):
        for i in xrange(0, len(self.rows)):
            size = ConfigHelpers.register_size(ConfigHelpers.get_arch(),
                                               self.rows[i][0])
            if size >= 8:
                self.rows[i][-1] = "0?0x"+"F"*(size/4)
        self.endResetModel()

    def endResetModel(self):
        """
        Rebuild a list of rows
        """
        if self.s.edit_config is not None:
            self.config = self.s.edit_config
        else:
            return
        #: list of Values (addresses)
        if self.config:
            self.rows = self.config.state.regs
        else:
            self.rows = []
        super(InitConfigRegModel, self).endResetModel()

    def headerData(self, section, orientation, role):
        if orientation != Qt.Horizontal:
            return
        if role == Qt.DisplayRole:
            return self.headers[section]

    def setData(self, index, value, role):
        if role != Qt.EditRole:
            return False
        col = index.column()
        row = index.row()
        if col == 0:
            return False
        if row > len(self.rows):
            return False
        else:
            # existing row
            self.rows[row][col] = value
            if self.config:
                self.config.state.set_regs(self.rows)
        return True  # success

    def data(self, index, role):
        col = index.column()
        if role == Qt.FontRole:
            return self.mono_font
        elif role == Qt.ToolTipRole:  # add tooltip ?
            return
        elif role != Qt.DisplayRole and role != Qt.EditRole:
            return

        reg = self.rows[index.row()]
        return reg[col]

    def rowCount(self, parent):
        return len(self.rows)

    def columnCount(self, parent):
        return len(self.headers)


class RegistersInfoModel(QtCore.QAbstractTableModel):
    """
    Used as model in BinCATRegistersForm TableView widgets.

    Contains tainting and values for registers
    """
    def __init__(self, state, *args, **kwargs):
        super(RegistersInfoModel, self).__init__(*args, **kwargs)
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
            value = row.value
            # GPR first
            if value in X86_GPR+X64_GPR and  ord(value[1]) > 0x39:
                return (0, row)
            elif value == 'zf':
                return (5, row)
            elif value in ["cs", "ds", "ss", "es", "fs", "gs"]:
                return (6, row)
            else:
                # used for arm* and x64
                if value.startswith(("r", "x")) and 0x30 <= ord(value[1]) <= 0x39:
                    if len(value) == 2:
                        # r0, r1, ..., r9
                        return (3, row)
                    else:
                        # r10, r11, ...
                        return (4, row)
                else:
                    return (5, row)
        else:
            return (7, row)

    def endResetModel(self):
        """
        Rebuild a list of rows
        """
        node = self.s.current_node
        unrel = self.s.current_unrel
        #: list of Values (addresses)
        self.rows = []
        self.changed_rows = set()
        if node and unrel:
            self.rows = [x for x in unrel.regaddrs if x.region == "reg"]
            self.rows = sorted(self.rows, key=RegistersInfoModel.rowcmp)

            # find parent nodes
            parents = [nodeid for nodeid in self.s.cfa.edges
                       if node.node_id in self.s.cfa.edges[nodeid]]
            for pnode in parents:
                pnode = self.s.cfa[pnode]
                for punrel in list(node.unrels.values()):
                    for k in unrel.list_modified_keys(punrel):
                        if k in self.rows:
                            self.changed_rows.add(self.rows.index(k))

        super(RegistersInfoModel, self).endResetModel()

    def headerData(self, section, orientation, role):
        if orientation != Qt.Horizontal:
            return
        if role == Qt.DisplayRole:
            return self.headers[section]
        elif role == Qt.SizeHintRole:
            return QtCore.QSize(self.colswidths[section], 20)

    def data(self, index, role):
        col = index.column()
        if role == Qt.SizeHintRole:
            # XXX not obeyed. why?
            return QtCore.QSize(self.colswidths[col], 20)
        elif role == Qt.FontRole:
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
        elif role == Qt.ToolTipRole:
            regaddr = self.rows[index.row()]
            t = self.s.current_unrel.getregtype(regaddr)
            if t:
                return t
            return
        elif role == Qt.BackgroundRole:
            regaddr = self.rows[index.row()]
            t = self.s.current_unrel.getregtype(regaddr)
            if t:
                if t.startswith("region "):
                    return QtGui.QBrush(Qt.lightGray)
                else:
                    return QtGui.QBrush(QtGui.QColor(0xad, 0xd8, 0xe6))
            return
        elif role != Qt.DisplayRole:
            return
        regaddr = self.rows[index.row()]

        if col == 0:  # register name
            return str(regaddr.value)
        v = self.s.current_unrel[regaddr]
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


class BinCATOverridesForm_t(ida_kernwin.PluginForm):
    """
    BinCAT Overrides display form
    Displays taint overrides defined by the user.
    An override is defined by:
    * an address
    * a register name (memory: not supported yet)
    * a taint value
    """

    def __init__(self, state, overrides_model, nops_model, skips_model):
        super(BinCATOverridesForm_t, self).__init__()
        self.s = state
        self.overrides_model = overrides_model
        self.nops_model = nops_model
        self.skips_model = skips_model
        self.shown = False
        self.created = False

    def OnCreate(self, form):
        self.created = True

        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        layout = QtWidgets.QGridLayout()


        # Overrides
        self.overrides_label = QtWidgets.QLabel(
            'List of value and taint overrides (user-defined)')
        self.overrides_table = BinCATTableView(self.overrides_model)
        self.overrides_table.verticalHeader().setVisible(False)
        self.overrides_table.setSortingEnabled(True)
        self.overrides_table.setModel(self.overrides_model)
        self.s.overrides.register_callbacks(
            self.overrides_model.beginResetModel,
            self.overrides_model.endResetModel)
        self.overrides_table.verticalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)

        self.overrides_table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)
        self.overrides_table.horizontalHeader().setStretchLastSection(True)

        # Nops
        self.nops_label = QtWidgets.QLabel('Instructions replaced with NOPs')
        self.nops_table = BinCATTableView(self.nops_model)
        self.nops_table.verticalHeader().setVisible(False)
        self.nops_table.setSortingEnabled(True)
        self.nops_table.setModel(self.nops_model)
        self.s.nops.register_callbacks(
            self.nops_model.beginResetModel,
            self.nops_model.endResetModel)
        self.nops_table.verticalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)

        self.nops_table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)
        self.nops_table.horizontalHeader().setStretchLastSection(True)

        # Skips
        self.skips_label = QtWidgets.QLabel('Skipped functions')
        self.skips_table = BinCATTableView(self.skips_model)
        self.skips_table.verticalHeader().setVisible(False)
        self.skips_table.setSortingEnabled(True)
        self.skips_table.setModel(self.skips_model)
        self.s.skips.register_callbacks(
            self.skips_model.beginResetModel,
            self.skips_model.endResetModel)
        self.skips_table.verticalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)

        self.skips_table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeToContents)
        self.skips_table.horizontalHeader().setStretchLastSection(True)

        layout.addWidget(self.overrides_label, 0, 0)
        layout.addWidget(self.overrides_table, 1, 0)
        layout.addWidget(self.nops_label, 2, 0)
        layout.addWidget(self.nops_table, 3, 0)
        layout.addWidget(self.skips_label, 4, 0)
        layout.addWidget(self.skips_table, 5, 0)

        self.btn_run = QtWidgets.QPushButton('&Re-run analysis', self.parent)
        self.btn_run.clicked.connect(self.s.re_run)
        layout.addWidget(self.btn_run, 6, 0)

        layout.setRowStretch(1, 0)
        layout.setRowStretch(2, 0)
        layout.setRowStretch(3, 0)

        self.parent.setLayout(layout)

    def OnClose(self, form):
        self.shown = False

    def Show(self):
        if self.shown:
            return
        self.shown = True
        return ida_kernwin.PluginForm.Show(
            self, "BinCAT Overrides",
            options=(ida_kernwin.PluginForm.WOPN_PERSIST |
                     ida_kernwin.PluginForm.WCLS_SAVE |
                     ida_kernwin.PluginForm.WOPN_RESTORE |
                     ida_kernwin.PluginForm.WOPN_TAB))


class OverridesModel(QtCore.QAbstractTableModel):
    def __init__(self, state, *args, **kwargs):
        super(OverridesModel, self).__init__(*args, **kwargs)
        self.s = state
        self.clickedIndex = None
        self.headers = ["eip", "addr or reg", "[value][!taint]"]

    def data(self, index, role):
        if role not in (Qt.ForegroundRole, Qt.DisplayRole,
                        Qt.EditRole, Qt.ToolTipRole):
            return
        col = index.column()
        row = index.row()
        if role == Qt.ToolTipRole:
            if col == 1:
                return "Example valid addresses: reg[eax], mem[0x1234]"
            if col == 2:
                return ("Example override values: !0x1234 (reg or mem), "
                        "!TAINT_ALL (reg only), !TAINT_NONE (reg only), "
                        "0x12?0x12", "|FF|!|10|")
            return
        if role == Qt.ForegroundRole:
            # basic syntax checking
            if col not in (1, 2):
                return
            txt = self.s.overrides[row][col]
            if col == 1:
                if txt.endswith(']'):
                    if (txt.startswith('reg[') or
                            txt.startswith('heap[0x') or
                            txt.startswith('mem[0x')):
                        return
            else:  # Value + Taint column
                if not self.s.overrides[row][1].startswith("reg"):
                    if "TAINT_ALL" in txt or "TAINT_NONE" in txt:
                        return QtGui.QBrush(Qt.red)
                pattern = (
                    # value (optional) - hex, oct, dec, bin, or string
                    r"^((0[xbo][0-9a-fA-F]+|\|[0-9a-fA-F]+\||[0-9]+)"
                    # if value is present: optional top mask - hex, oct or bin
                    "(\?0[xbo][0-9a-fA-F]+|[0-9]+)?)?"
                    # taint - same as value, PLUS TAINT_* for
                    # registers
                    "(!(0[xbo][0-9a-fA-F]+|\|[0-9a-fA-F]+\||[0-9]+|"
                    "TAINT_ALL|TAINT_NONE)"
                    # if taint is present: optional top mask - same as value
                    # top mask
                    "(\?0[xbo][0-9a-fA-F]+|[0-9]+)?)?$")
                if re.match(pattern, txt):
                    return
            return QtGui.QBrush(Qt.red)
        rawdata = self.s.overrides[row][col]
        if col == 0:
            return "%x" % rawdata
        else:
            return str(rawdata)

    def setData(self, index, value, role):
        if role != Qt.EditRole:
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
            self.s.overrides[row] = tuple(r)
        return True  # success

    def headerData(self, section, orientation, role):
        if orientation != Qt.Horizontal:
            return
        if role == Qt.DisplayRole:
            return self.headers[section]

    def flags(self, index):
        return (Qt.ItemIsEditable
                | Qt.ItemIsSelectable
                | Qt.ItemIsEnabled)

    def rowCount(self, parent):
        return len(self.s.overrides)

    def columnCount(self, parent):
        return len(self.headers)

    def remove_row(self, checked):
        del self.s.overrides[self.clickedIndex]

    def remove_all(self):
        self.s.overrides.clear()


class BinCATTableView(QtWidgets.QTableView):

    def __init__(self, model, parent=None):
        super(BinCATTableView, self).__init__(parent)
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
        action = QtWidgets.QAction('Remove all', self)
        action.triggered.connect(self.m.remove_all)
        menu.addAction(action)
        self.m.clickedIndex = self.indexAt(event.pos()).row()
        menu.popup(QtGui.QCursor.pos())

    def remove_all(self):
        self.m.remove_all()

    def remove_row(self):
        try:
            index = self.table.selectedIndexes()[0].row()
        except IndexError:
            bc_log.warning("Could not identify selected row")
            return
        self.m.remove_row(index)


class SkipsModel(QtCore.QAbstractTableModel):
    def __init__(self, state, *args, **kwargs):
        super(SkipsModel, self).__init__(*args, **kwargs)
        self.s = state
        self.clickedIndex = None
        self.headers = ["address or function name", "arg_nb", "ret_val"]

    def data(self, index, role):
        if role not in (Qt.DisplayRole, Qt.EditRole, Qt.ToolTipRole):
            return
        col = index.column()
        row = index.row()
        if role == Qt.ToolTipRole:
            if col == 0:
                return "Example valid values: 'kill', '0x1234'"
            if col == 1:
                return "Number of arguments that the function expects (int)"
            if col == 2:
                return "Value & taint of the return value. Ex. 0xFF!0xFF (value=0xFF, fully tainted)"
        return self.s.skips[row][col]

    def setData(self, index, value, role):
        if role != Qt.EditRole:
            return False
        col = index.column()
        row = index.row()
        if col == 1:
            if not all(c in '0123456789' for c in value):
                return False
        if row > len(self.s.skips):
            # new row
            r = [""] * len(self.headers)
            r[col] = value
            self.s.skips.append(r)
        else:
            # existing row
            r = list(self.s.skips[row])
            r[col] = value
            self.s.skips[row] = tuple(r)
        return True  # success

    def headerData(self, section, orientation, role):
        if orientation != Qt.Horizontal:
            return
        if role == Qt.DisplayRole:
            return self.headers[section]

    def flags(self, index):
        return (Qt.ItemIsEditable
                | Qt.ItemIsSelectable
                | Qt.ItemIsEnabled)

    def rowCount(self, parent):
        return len(self.s.skips)

    def columnCount(self, parent):
        return len(self.headers)

    def remove_row(self, checked):
        del self.s.skips[self.clickedIndex]

    def remove_all(self):
        self.s.skips.clear()


class NopsModel(QtCore.QAbstractTableModel):
    def __init__(self, state, *args, **kwargs):
        super(NopsModel, self).__init__(*args, **kwargs)
        self.s = state
        self.clickedIndex = None
        self.headers = ["address or function name"]

    def data(self, index, role):
        if role not in (Qt.DisplayRole, Qt.EditRole, Qt.ToolTipRole):
            return
        row = index.row()
        if role == Qt.ToolTipRole:
            return "Example valid values: 'kill', '0x1234'"
        return self.s.nops[row][0]

    def setData(self, index, value, role):
        if role != Qt.EditRole:
            return False
        row = index.row()
        if row > len(self.s.nops):
            # new row
            self.s.nops.append([value])
        else:
            # existing row
            self.s.nops[row] = (value, )
        return True  # success

    def headerData(self, section, orientation, role):
        if orientation != Qt.Horizontal:
            return
        if role == Qt.DisplayRole:
            return self.headers[section]

    def flags(self, index):
        return (Qt.ItemIsEditable
                | Qt.ItemIsSelectable
                | Qt.ItemIsEnabled)

    def rowCount(self, parent):
        return len(self.s.nops)

    def columnCount(self, parent):
        return len(self.headers)

    def remove_row(self, checked):
        del self.s.nops[self.clickedIndex]

    def remove_all(self):
        self.s.nops.clear()


class HandleAnalyzeHere(idaapi.action_handler_t):
    """
    Action handler for BinCAT/ Taint from here
    base class is not a newstyle class...
    """
    def __init__(self, state):
        self.s = state

    def activate(self, ctx):
        self.s.gui.show_windows()

        self.s.gui.BinCATConfigForm.launch_analysis()

        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class HandleAddOverride(idaapi.action_handler_t):
    """
    Action handler for BinCAT/Add Override
    """
    def __init__(self, state):
        self.s = state

    def activate(self, ctx):
        self.s.gui.show_windows()

        v = ida_kernwin.get_current_viewer()
        thing = ida_kernwin.get_highlight(v)
        if thing and thing[1]:
            highlighted = thing[0]
        else:
           return 0
        address = self.s.current_ea
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
        mask, res = QtWidgets.QInputDialog.getText(
            None,
            "Add override for %s" % highlighted,
            "Override value for %s (e.g. !TAINT_ALL (reg only), "
            "!TAINT_NONE (reg only), !0b001, !0xabc)" %
            highlighted, text=("!TAINT_ALL" if htype == "reg" else "!|FF|"))
        if not res:
            return 1  # refresh IDA windows
        htext = "%s[%s]" % (htype, highlighted)
        self.s.add_or_replace_override(address, htext, mask)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class HandleNopThisInstruction(idaapi.action_handler_t):
    """
    Action handler for BinCAT/Replace this instruction with nop
    """
    def __init__(self, state):
        self.s = state

    def activate(self, ctx):
        self.s.gui.show_windows()

        self.s.nops.append(["0x%x" % self.s.current_ea])
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class HandleSkipThisFunction(idaapi.action_handler_t):
    """
    Action handler for BinCAT/Skip this function...
    """
    def __init__(self, state):
        self.s = state

    def activate(self, ctx):
        self.s.gui.show_windows()
        argret, res = QtWidgets.QInputDialog.getText(
            None,
            "Skip function",
            "Enter number of arguments and return value, separated by a "
            "comma. Example: \"1,0xFF!0xFF\"",
            text=("1, 0xFFFFFFFF!0xFFFFFFFF"))
        if not res:
            return 1  # refresh IDA windows

        arg, ret = argret.split(',')
        self.s.skips.append(
            ("0x%x" % self.s.current_ea, arg.strip(), ret.strip()))
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class HandleOptions(idaapi.action_handler_t):
    """
    Action handler for BinCAT/Options
    """
    def __init__(self, state):
        self.s = state

    def activate(self, ctx):
        # display config window
        bc_conf_form = BinCATOptionsForm_t(self.s)
        bc_conf_form.exec_()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class HandleRemap(idaapi.action_handler_t):
    """
    Action handler for BinCAT/Options
    """
    def __init__(self, state):
        self.s = state

    def activate(self, ctx):
        # display config window
        fname = ConfigHelpers.askfile("*.*", "Save to binary")
        if fname:
            dump_binary(fname)
            self.s.remapped_bin_path = fname
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
        win_type = ctx.widget_type
        if win_type == idaapi.BWN_DISASM:
            ea = ctx.cur_ea
            if ida_bytes.is_code(idaapi.get_full_flags(ea)):
                self.s.set_current_ea(ea)

    def populating_widget_popup(self, form, popup):
        win_type = idaapi.get_widget_type(form)
        if win_type == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(
                form, popup, "bincat:ana_from_here",
                "BinCAT/", idaapi.SETMENU_APP)
            idaapi.attach_action_to_popup(
                form, popup, "bincat:add_override",
                "BinCAT/", idaapi.SETMENU_APP)
            idaapi.attach_action_to_popup(
                form, popup, "bincat:nop_instruction",
                "BinCAT/", idaapi.SETMENU_APP)
            idaapi.attach_action_to_popup(
                form, popup, "bincat:skip_function",
                "BinCAT/", idaapi.SETMENU_APP)


class GUI(object):
    def __init__(self, state):
        """
        Instanciate BinCAT views
        """
        self.s = state
        self.regsinfo_model = RegistersInfoModel(state)
        self.configregmodel = InitConfigRegModel(state)
        self.configmemmodel = InitConfigMemModel(state)
        self.BinCATRegistersForm = BinCATRegistersForm_t(state, self.regsinfo_model)
        self.BinCATConfigForm = BinCATConfigForm_t(
            state, self.configregmodel, self.configmemmodel)
        self.BinCATDebugForm = BinCATDebugForm_t(state)
        self.BinCATMemForm = BinCATMemForm_t(state)
        self.overrides_model = OverridesModel(state)
        self.nops_model = NopsModel(state)
        self.skips_model = SkipsModel(state)
        self.BinCATOverridesForm = BinCATOverridesForm_t(
            state, self.overrides_model, self.nops_model, self.skips_model)

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
        # Add override menu
        add_taint_override_act = idaapi.action_desc_t(
            'bincat:add_override', 'Add override...',
            HandleAddOverride(self.s), 'Ctrl-Shift-O')
        idaapi.register_action(add_taint_override_act)

        # Nop menu
        nop_instruction_act = idaapi.action_desc_t(
            'bincat:nop_instruction', 'Replace this instruction with nop',
            HandleNopThisInstruction(self.s))
        idaapi.register_action(nop_instruction_act)

        # Skip function menu
        skip_instruction_act = idaapi.action_desc_t(
            'bincat:skip_function',
            'Skip function that starts at current address...',
            HandleSkipThisFunction(self.s))
        idaapi.register_action(skip_instruction_act)

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

    def focus_registers(self):
        try:
            if getattr(idaapi, "activate_widget"):
                widget = idaapi.find_widget("BinCAT Registers")
                if widget:
                    idaapi.activate_widget(widget, True)
        except AttributeError:
            # IDA 6.95 does not support this
            pass

    def show_windows(self):
        # XXX hide debug form by default (issue #27)
        self.BinCATDebugForm.Show()
        self.BinCATRegistersForm.Show()
        self.BinCATOverridesForm.Show()
        self.BinCATMemForm.Show()
        self.BinCATConfigForm.Show()

    def before_change_ea(self):
        self.regsinfo_model.beginResetModel()

    def after_change_ea(self):
        self.BinCATRegistersForm.update_current_ea(self.s.current_ea)
        self.regsinfo_model.endResetModel()
        self.BinCATDebugForm.update(self.s.current_node)
        self.BinCATMemForm.update_current_ea(self.s.current_ea)

    def term(self):
        if self.hooks:
            self.hooks.unhook()
            self.hooks = None
        self.BinCATConfigForm.Close(ida_kernwin.PluginForm.WCLS_SAVE)
        self.BinCATRegistersForm.Close(ida_kernwin.PluginForm.WCLS_SAVE)
        self.BinCATDebugForm.Close(ida_kernwin.PluginForm.WCLS_SAVE)
        self.BinCATMemForm.Close(ida_kernwin.PluginForm.WCLS_SAVE)
        self.BinCATOverridesForm.Close(ida_kernwin.PluginForm.WCLS_SAVE)
        self.regsinfo_model = None
        self.overrides_model = None
        self.configurations_model = None
        idaapi.unregister_action("bincat:show_windows")
        idaapi.unregister_action("bincat:remap_act")
        idaapi.unregister_action("bincat:options_act")
        idaapi.unregister_action("bincat:ana_from_here")
