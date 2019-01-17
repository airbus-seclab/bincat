# -*- coding: utf8 -*-
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
# This file is derived from work by Willi Ballenthin
# Downloaded from https://github.com/williballenthin/python-pyqt5-hexview
#
# Modified by Raphaël Rigo <raphael.rigo@airbus.com>

import base64
import binascii
import logging
from collections import namedtuple

from PyQt5 import QtGui
from PyQt5.QtGui import QColor
from PyQt5.QtGui import QIcon
from PyQt5.QtGui import QBrush
from PyQt5.QtGui import QPixmap
from PyQt5.QtGui import QPainter
from PyQt5.QtGui import QMouseEvent
from PyQt5.QtGui import QKeySequence
from PyQt5.QtGui import QFontDatabase
from PyQt5.QtGui import QFont
from PyQt5.QtGui import QTextDocument
import PyQt5.QtCore as QtCore
from PyQt5.QtCore import Qt
from PyQt5.QtCore import QSize
from PyQt5.QtCore import QMimeData
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtCore import QModelIndex
from PyQt5.QtCore import QItemSelection
from PyQt5.QtCore import QItemSelectionModel
from PyQt5.QtCore import QRectF
from PyQt5.QtCore import QAbstractTableModel
from PyQt5.QtWidgets import QMenu
from PyQt5.QtWidgets import QStyle
from PyQt5.QtWidgets import QAction
from PyQt5.QtWidgets import QWidget
from PyQt5.QtWidgets import QTableView
from PyQt5.QtWidgets import QHeaderView
from PyQt5.QtWidgets import QSizePolicy
from PyQt5.QtWidgets import QApplication
from PyQt5.QtWidgets import QInputDialog
from PyQt5.QtWidgets import QStyledItemDelegate
from PyQt5.QtWidgets import QAbstractItemView

from .hexview_auto import Ui_Form as HexViewBase
from .common import h
from .common import LoggingObject

# Logging
logging.basicConfig(level=logging.DEBUG)
bc_log = logging.getLogger('bincat.hexview')
bc_log.setLevel(logging.DEBUG)


class HexItemDelegate(QStyledItemDelegate):
    pixcache = {}

    def __init__(self, model, parent, *args):
        super(HexItemDelegate, self).__init__(parent)
        # compute size hint for hex view
        dh = QTextDocument()
        dh.setHtml("<font color='green'>DF</font>")
        self.hex_hint = QtCore.QSize(dh.idealWidth()-dh.documentMargin(), 22)
        # compute size hint for char view
        dc = QTextDocument()
        dc.setHtml("W")
        self.char_hint = QtCore.QSize(dc.idealWidth()-dc.documentMargin(), 22)
        self._model = model

    def get_pixmap(self, txt, hl, rect, brush):
        """
        store pixmap cache. Switch to LRU cache if too much memory is used.
        """
        if (hl, txt) in HexItemDelegate.pixcache:
            return HexItemDelegate.pixcache[(hl, txt)]

        # FIXME use correct size? on non-hdpi screen, 15x22 real size
        pixmap = QPixmap(rect.width(), rect.height())
        if hl:
            # Carefully measured using the gimp. YMMV.
            # Used to be done using proper Qt API calls before pixmap cache was
            # introduced in revision 731562b77ece9301f61de6626432891dfc34ba91
            pixmap.fill(QColor.fromRgb(48, 140, 198))
        else:
            pixmap.fill(brush.color())

        doc = QTextDocument()
        doc.setHtml(txt)
        painter = QPainter()
        painter.begin(pixmap)
        doc.drawContents(painter)
        painter.end()
        HexItemDelegate.pixcache[txt] = pixmap
        return pixmap

    def paint(self, qpainter, option, qindex):
        self.initStyleOption(option, qindex)

        qpainter.save()

        pixmap = self.get_pixmap(option.text,
                                 option.state & QStyle.State_Selected,
                                 option.rect, option.backgroundBrush)

        qpainter.translate(option.rect.left(), option.rect.top())
        qpainter.drawPixmap(0, 0, pixmap)
        qpainter.restore()

    def sizeHint(self, option, qindex):
        if qindex.column() < 0x10:
            return self.hex_hint
        else:
            return self.char_hint


class HexTableModel(QAbstractTableModel):
    FILTER = ''.join(
        [(len(repr(chr(x))) == 3 or chr(x) == "\\") and chr(x) or
         '.' for x in range(256)])

    def __init__(self, meminfo, parent=None, *args):
        super(HexTableModel, self).__init__(parent, *args)
        self._meminfo = None
        self._rowcount = None
        self.setNewMem(meminfo)

    def setNewMem(self, meminfo):
        self._meminfo = meminfo
        self._length = self._meminfo.length
        self._firstcol = self._meminfo.start % 16
        self._lastcol = self._meminfo.ranges[-1][1] % 16
        self._rowcount = (self._firstcol + self._length + 0xf) // 0x10

    def qindex2index(self, index):
        """
        from a QIndex (row/column coordinate system), get the buffer index of
        the byte
        """
        r = index.row()
        c = index.column()
        if c > 0x10:
            return (0x10 * r) + c - 0x11 - self._firstcol
        else:
            return (0x10 * r) + c - self._firstcol

    def index2qindexb(self, index):
        """
        from a buffer index, get the QIndex (row/column coordinate system) of
        the byte pane
        """
        index += self._firstcol
        r = index // 0x10
        c = index % 0x10
        return self.index(r, c)

    def index2qindexc(self, index):
        """
        from a buffer index, get the QIndex (row/column coordinate system) of
        the char pane
        """
        index += self._firstcol
        r = (index // 0x10)
        c = index % 0x10 + 0x11
        return self.index(r, c)

    def rowCount(self, parent):
        return self._rowcount

    def columnCount(self, parent):
        return 0x21

    def data(self, index, role):
        if not index.isValid():
            return None
        if role not in (Qt.ToolTipRole, Qt.DisplayRole, Qt.BackgroundRole):
            return None

        elif index.row() == (self._rowcount-1):
            col = index.column()
            if col > 0x10:
                col -= 0x11
            if col > self._lastcol:
                return None

        col = index.column()
        bindex = self.qindex2index(index)
        if bindex < 0:
            return None
        if bindex >= self._firstcol + self._length:
            return None
        if col == 0x10:
            return ""
        if role == Qt.DisplayRole:
            if col < 0x10:
                return self._meminfo.html_color(bindex)
            else:
                return self._meminfo.char(bindex)
        else:
            t = self._meminfo.get_type(bindex)
            if role == Qt.ToolTipRole:
                return t
            else:
                if t:
                    if t.startswith("region "):
                        return QtGui.QBrush(Qt.lightGray)
                    else:
                        return QtGui.QBrush(QtGui.QColor(0xad, 0xd8, 0xe6))
                else:
                    return QtGui.QBrush(Qt.white)

    @property
    def data_length(self):
        return self._length + self._firstcol

    def headerData(self, section, orientation, role):
        # if role == QtCore.Qt.SizeHintRole:
        #     return QtCore.QSize(21, 20)
        if role != Qt.DisplayRole:
            return None

        elif orientation == Qt.Horizontal:
            if section < 0x10:
                return "%01X" % (section)
            else:
                return ""
        elif orientation == Qt.Vertical:
            return "%08X" % (section * 0x10 + (self._meminfo.start & 0xFFFFFFF0))

        else:
            return None

    def _emit_data_changed(self, start_bindex, end_bindex):
        for i in range(start_bindex, end_bindex):
            # mark data changed to encourage re-rendering of cell
            qib = self.index2qindexb(i)
            qic = self.index2qindexc(i)
            self.dataChanged.emit(qib, qib)
            self.dataChanged.emit(qic, qic)


class HexItemSelectionModel(QItemSelectionModel):
    selectionRangeChanged = pyqtSignal([int])

    def __init__(self, model, view):
        """
        :type view: HexTableView
        """
        super(HexItemSelectionModel, self).__init__(model)
        self._model = model
        self._view = view

        self._start_qindex = None
        self._view.leftMousePressedIndex.connect(self._handle_mouse_pressed)
        self._view.leftMouseMovedIndex.connect(self._handle_mouse_moved)
        self._view.leftMouseReleasedIndex.connect(self._handle_mouse_released)

        self.start = None
        self.end = None

    def _bselect(self, selection, start_bindex, end_bindex):
        """
        add the given buffer indices to the given QItemSelection,
        both byte and char panes
        """
        selection.select(self._model.index2qindexb(start_bindex),
                         self._model.index2qindexb(end_bindex))
        selection.select(self._model.index2qindexc(start_bindex),
                         self._model.index2qindexc(end_bindex))

    def _do_select(self, start_bindex, end_bindex):
        """
        select the given range by buffer indices

        selects items like this:

            ..................
            ......xxxxxxxxxxxx
            xxxxxxxxxxxxxxxxxx
            xxxxxxxxxxxxxxxxxx
            xxxxxxxxxxxx......
            ..................

        *not* like this:

            ..................
            ......xxxxxx......
            ......xxxxxx......
            ......xxxxxx......
            ......xxxxxx......
            ..................
         """
        self.select(QItemSelection(), QItemSelectionModel.Clear)
        if start_bindex > end_bindex:
            start_bindex, end_bindex = end_bindex, start_bindex

        start_qindex = self._model.index2qindexb(start_bindex)
        start_row = start_qindex.row()
        start_col = start_qindex.column()
        #: binary index of the 1st column on the row containing start_bindex
        start_row_start_idx = start_bindex - start_col
        #: binary index of the last column on the row containing start_bindex
        start_row_end_idx = start_bindex + (0xf-start_col)
        end_qindex = self._model.index2qindexb(end_bindex)
        end_row = end_qindex.row()
        end_col = end_qindex.column()
        end_row_start_idx = end_bindex - end_col
        end_row_end_idx = end_bindex + (0xf-end_col)

        selection = QItemSelection()
        if end_row == start_row:
            # all on one line
            self._bselect(selection, start_bindex, end_bindex)
        elif end_row - start_row == 1:
            # two lines
            self._bselect(selection, start_bindex, start_row_end_idx)
            self._bselect(selection, end_row_start_idx, end_bindex)
        else:
            # many lines
            self._bselect(selection, start_bindex, start_row_end_idx)
            self._bselect(selection, start_row_start_idx + 0x10,
                          end_row_end_idx - 0x10)
            self._bselect(selection, end_row_start_idx, end_bindex)

        self.select(selection, QItemSelectionModel.SelectCurrent)
        self.start = start_bindex
        self.end = end_bindex
        self.selectionRangeChanged.emit(end_bindex)

    def bselect(self, start_bindex, end_bindex):
        """  the public interface to _do_select """
        return self._do_select(start_bindex, end_bindex)

    def handle_move_key(self, key):
        if (self._start_qindex == self._model.index2qindexc(self.start) or
                self._start_qindex == self._model.index2qindexb(self.start)):
            i = self.end
        else:
            i = self.start
        if key == QKeySequence.MoveToEndOfDocument:
            i = self._model.data_length - 1
        elif key == QKeySequence.MoveToEndOfLine:
            i_col = self._model.index2qindexb(i).column()
            i = i + 0xf - i_col
        elif key == QKeySequence.MoveToNextChar:
            i += 1
        elif key == QKeySequence.MoveToNextLine:
            i += 0x10
        elif key == QKeySequence.MoveToNextPage:
            i += 0x40
        elif key == QKeySequence.MoveToNextWord:
            i += 1
        elif key == QKeySequence.MoveToPreviousChar:
            i -= 1
        elif key == QKeySequence.MoveToPreviousLine:
            i -= 0x10
        elif key == QKeySequence.MoveToPreviousPage:
            i -= 0x40
        elif key == QKeySequence.MoveToPreviousWord:
            i -= 1
        elif key == QKeySequence.MoveToStartOfDocument:
            i = 0x0
        elif key == QKeySequence.MoveToStartOfLine:
            i_col = self._model.index2qindexb(i).column()
            i = i - i_col
        else:
            raise RuntimeError("Unexpected movement key: %s" % (key))

        # this behavior selects the smallest or largest cell in the
        #   same column as the out-of-bounds index
        if i < 0:
            i %= 0x10
        if i > self._model.data_length:
            i %= 0x10
            i = self._model.data_length - 0x10 + i

        self.bselect(i, i)

    def handle_select_key(self, key):
        i = None
        j = None
        if (self._start_qindex == self._model.index2qindexc(self.start) or
                self._start_qindex == self._model.index2qindexb(self.start)):
            i = self.end
            j = self.start
        else:
            i = self.start
            j = self.end

        if key == QKeySequence.SelectEndOfDocument:
            i = self._model.data_length - 1
        elif key == QKeySequence.SelectEndOfLine:
            i_col = self._model.index2qindexb(i).column()
            i = i + 0xf - i_col
        elif key == QKeySequence.SelectNextChar:
            i += 1
        elif key == QKeySequence.SelectNextLine:
            i += 0x10
        elif key == QKeySequence.SelectNextPage:
            i += 0x40
        elif key == QKeySequence.SelectNextWord:
            i += 1
        elif key == QKeySequence.SelectPreviousChar:
            i -= 1
        elif key == QKeySequence.SelectPreviousLine:
            i -= 0x10
        elif key == QKeySequence.SelectPreviousPage:
            i -= 0x40
        elif key == QKeySequence.SelectPreviousWord:
            i -= 1
        elif key == QKeySequence.SelectStartOfDocument:
            i = 0x0
        elif key == QKeySequence.SelectStartOfLine:
            i_col = self._model.index2qindexb(i).column()
            i = i - i_col
        else:
            raise RuntimeError("Unexpected select key: %s" % (key))

        # this behavior selects the smallest or largest cell in the
        #   same column as the out-of-bounds index
        if i < 0:
            i %= 0x10
        if i > self._model.data_length:
            i %= 0x10
            i = self._model.data_length - 0x10 + i

        # need to explicitly reset start_qindex so that the current index
        #   doesn't get confused when coming from a selection of a single cell
        #   (in the check at the start of this function to decide which end of
        #    the selection was most recently active)
        self._start_qindex = self._model.index2qindexc(j)

        self.bselect(i, j)

    def _update_selection(self, qindex1, qindex2):
        """  select the given range by qmodel indices """
        m = self.model()
        self._do_select(m.qindex2index(qindex1), m.qindex2index(qindex2))

    def _handle_mouse_pressed(self, qindex):
        self._start_qindex = qindex
        self._update_selection(qindex, qindex)

    def _handle_mouse_moved(self, qindex):
        self._update_selection(self._start_qindex, qindex)

    def _handle_mouse_released(self, qindex):
        self._update_selection(self._start_qindex, qindex)
        self._start_qindex = None


class HexTableView(QTableView, LoggingObject):
    """ table view that handles click events for better selection handling """
    leftMousePressed = pyqtSignal([QMouseEvent])
    leftMousePressedIndex = pyqtSignal([QModelIndex])
    leftMouseMoved = pyqtSignal([QMouseEvent])
    leftMouseMovedIndex = pyqtSignal([QModelIndex])
    leftMouseReleased = pyqtSignal([QMouseEvent])
    leftMouseReleasedIndex = pyqtSignal([QModelIndex])
    moveKeyPressed = pyqtSignal([QKeySequence])
    selectKeyPressed = pyqtSignal([QKeySequence])

    def __init__(self, *args, **kwargs):
        super(HexTableView, self).__init__(*args, **kwargs)
        self.leftMousePressed.connect(self._handle_mouse_press)
        self.leftMouseMoved.connect(self._handle_mouse_move)
        self.leftMouseReleased.connect(self._handle_mouse_release)

        self._press_start_index = None
        self._press_current_index = None
        self._press_end_index = None
        self._is_tracking_mouse = False

    def _reset_press_state(self):
        self._press_start_index = None
        self._press_current_index = None
        self._press_end_index = None

    def mousePressEvent(self, event):
        super(HexTableView, self).mousePressEvent(event)
        if event.buttons() & Qt.LeftButton:
            self.leftMousePressed.emit(event)

    def mouseMoveEvent(self, event):
        super(HexTableView, self).mouseMoveEvent(event)
        if event.buttons() & Qt.LeftButton:
            self.leftMouseMoved.emit(event)

    def mouseReleaseEvent(self, event):
        super(HexTableView, self).mousePressEvent(event)
        if event.buttons() & Qt.LeftButton:
            self.leftMouseReleased.emit(event)

    def keyPressEvent(self, event):
        move_keys = (
            QKeySequence.MoveToEndOfDocument,
            QKeySequence.MoveToEndOfLine,
            QKeySequence.MoveToNextChar,
            QKeySequence.MoveToNextLine,
            QKeySequence.MoveToNextPage,
            QKeySequence.MoveToNextWord,
            QKeySequence.MoveToPreviousChar,
            QKeySequence.MoveToPreviousLine,
            QKeySequence.MoveToPreviousPage,
            QKeySequence.MoveToPreviousWord,
            QKeySequence.MoveToStartOfDocument,
            QKeySequence.MoveToStartOfLine,
        )

        for move_key in move_keys:
            if event.matches(move_key):
                self.moveKeyPressed.emit(move_key)
                return

        t = event.text()
        KeyMapping = namedtuple("KeyMapping", ["source", "destination"])
        vim_move_mappings = (
            KeyMapping("j", QKeySequence.MoveToNextLine),
            KeyMapping("k", QKeySequence.MoveToPreviousLine),
            KeyMapping("h", QKeySequence.MoveToPreviousChar),
            KeyMapping("l", QKeySequence.MoveToNextChar),
            KeyMapping("^", QKeySequence.MoveToStartOfLine),
            KeyMapping("$", QKeySequence.MoveToEndOfLine),
        )
        for vim_mapping in vim_move_mappings:
            if vim_mapping.source == t:
                self.moveKeyPressed.emit(vim_mapping.destination)
                return

        select_keys = (
            QKeySequence.SelectAll,
            QKeySequence.SelectEndOfDocument,
            QKeySequence.SelectEndOfLine,
            QKeySequence.SelectNextChar,
            QKeySequence.SelectNextLine,
            QKeySequence.SelectNextPage,
            QKeySequence.SelectNextWord,
            QKeySequence.SelectPreviousChar,
            QKeySequence.SelectPreviousLine,
            QKeySequence.SelectPreviousPage,
            QKeySequence.SelectPreviousWord,
            QKeySequence.SelectStartOfDocument,
            QKeySequence.SelectStartOfLine,
        )

        for select_key in select_keys:
            if event.matches(select_key):
                self.selectKeyPressed.emit(select_key)
                return

        t = event.text()
        KeyMapping = namedtuple("KeyMapping", ["source", "destination"])
        vim_select_mappings = (
            KeyMapping("J", QKeySequence.SelectNextLine),
            KeyMapping("K", QKeySequence.SelectPreviousLine),
            KeyMapping("H", QKeySequence.SelectPreviousChar),
            KeyMapping("L", QKeySequence.SelectNextChar),
        )
        for vim_mapping in vim_select_mappings:
            if vim_mapping.source == t:
                self.selectKeyPressed.emit(vim_mapping.destination)
                return

    def _handle_mouse_press(self, key_event):
        self._reset_press_state()

        self._press_start_index = self.indexAt(key_event.pos())
        self._is_tracking_mouse = True

        self.leftMousePressedIndex.emit(self._press_start_index)

    def _handle_mouse_move(self, key_event):
        if self._is_tracking_mouse:
            i = self.indexAt(key_event.pos())
            if i != self._press_current_index:
                self._press_current_index = i
                self.leftMouseMovedIndex.emit(i)

    def _handle_mouse_release(self, key_event):
        self._press_end_index = self.indexAt(key_event.pos())
        self._is_tracking_mouse = False

        self.leftMouseReleasedIndex.emit(self._press_end_index)


Origin = namedtuple("Origin", ["offset", "name"])


class HexViewWidget(QWidget, HexViewBase, LoggingObject):
    originsChanged = pyqtSignal()
    newOverride = pyqtSignal(int, int, bool)

    def __init__(self, meminfo, parent=None):
        super(HexViewWidget, self).__init__()
        self.setupUi(self)
        self._meminfo = meminfo
        self._model = HexTableModel(self._meminfo)

        self._origins = []

        # ripped from pyuic5 ui/hexview.ui
        #   at commit 6c9edffd32706097d7eba8814d306ea1d997b25a
        # so we can add our custom HexTableView instance
        self.view = HexTableView(self)
        sizePolicy = QSizePolicy(
            QSizePolicy.MinimumExpanding, QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(
            self.view.sizePolicy().hasHeightForWidth())
        self.view.setSizePolicy(sizePolicy)
        self.view.setMinimumSize(QSize(660, 0))
        self.view.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        self.view.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.view.setSelectionMode(QAbstractItemView.NoSelection)
        self.view.setShowGrid(False)
        self.view.setWordWrap(False)
        self.view.setObjectName("view")
        self.view.verticalHeader().setSectionResizeMode(
            QHeaderView.ResizeToContents)
        self.mainLayout.insertWidget(0, self.view)
        # end rip

        # TODO: provide a HexViewWidget.setModel method, and don't build it
        # ourselves
        self.view.setModel(self._model)
        self.hheader = self.view.horizontalHeader()
        self.hheader.setSectionResizeMode(QHeaderView.ResizeToContents)
        # separator column
        self.hheader.setSectionResizeMode(0x10, QHeaderView.Interactive)
        self.view.setColumnWidth(0x10, 5)

        self._hsm = HexItemSelectionModel(self._model, self.view)
        self.view.setSelectionModel(self._hsm)

        self.view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.view.customContextMenuRequested.connect(
            self._handle_context_menu_requested)

        self._hsm.selectionRangeChanged.connect(
            self._handle_selection_range_changed)

        self.originsChanged.connect(self._handle_origins_changed)

        self.view.moveKeyPressed.connect(self._hsm.handle_move_key)
        self.view.selectKeyPressed.connect(self._hsm.handle_select_key)

        f = QFont("Monospace")
        f = QFontDatabase.systemFont(QFontDatabase.FixedFont)

        self.view.setFont(f)
        self.statusLabel.setFont(f)

        self.view.setItemDelegate(HexItemDelegate(self._model, self))

        self.statusLabel.setText("")

    def setNewMem(self, meminfo):
        self._model.beginResetModel()
        self._meminfo = meminfo
        self._model.setNewMem(meminfo)
        self._model.endResetModel()

    def getModel(self):
        return self._model

    def getSelectionModel(self):
        return self._hsm

    def scrollTo(self, index):
        qi = self._model.index2qindexb(index)
        self.view.scrollTo(qi)

    def _render_status_text(self):
        txt = []
        start = self._hsm.start
        end = self._hsm.end
        if start not in (None, -1) and end not in (None, -1):
            txt.append("sel: [{:s}, {:s}]".format(hex(start), hex(end)))
            txt.append("len: {:s}".format(hex(end - start + 1)))
            for origin in self._origins:
                txt.append("from '{:s}': {:s}".format(
                    origin.name, hex(start - origin.offset)))
        self.statusLabel.setText(" ".join(txt))

    def _handle_selection_range_changed(self, end_bindex):
        self._render_status_text()
        self.scrollTo(end_bindex)

    def _handle_origins_changed(self):
        self._render_status_text()

    def get_context_menu(self, qpoint):
        """ override this method to customize the context menu """
        menu = QMenu(self)
        index = self.view.indexAt(qpoint)

        def add_action(menu, text, handler, icon=None):
            a = None
            if icon is None:
                a = QAction(text, self)
            else:
                a = QAction(icon, text, self)
            a.triggered.connect(handler)
            menu.addAction(a)

        add_action(menu, "Copy selection (binary)", self._handle_copy_binary)
        copy_menu = menu.addMenu("Copy...")
        add_action(copy_menu, "Copy selection (binary)",
                   self._handle_copy_binary)
        add_action(copy_menu, "Copy selection (text)", self._handle_copy_text)
        add_action(copy_menu, "Copy selection (hex)", self._handle_copy_hex)
        add_action(copy_menu, "Copy selection (base64)",
                   self._handle_copy_base64)

        menu.addSeparator()  # --------------------------------------
        add_action(menu, "Add origin", lambda: self._handle_add_origin(index))

        if self._hsm.start is not None and self._hsm.end is not None:
            menu.addSeparator()  # --------------------------------------
            add_action(menu, "Override value or taint for selection...",
                       lambda: self._handle_add_taint_override(False))
            add_action(menu, "Override value or taint for selection and re-run...",
                       lambda: self._handle_add_taint_override(True))
        return menu

    def _handle_context_menu_requested(self, qpoint):
        self.get_context_menu(qpoint).exec_(self.view.mapToGlobal(qpoint))

    @property
    def _selected_data(self):
        start = self._hsm.start
        end = self._hsm.end
        return self._meminfo.hexstr(slice(start, end))

    def _handle_copy_binary(self):
        mime = QMimeData()
        # mime type suggested here: http://stackoverflow.com/a/6783972/87207
        try:
            mime.setData("application/octet-stream",
                         binascii.a2b_hex(self._selected_data))
        except TypeError:
            raise Exception("TOP values are not supported yet")
        QApplication.clipboard().setMimeData(mime)

    def _handle_copy_text(self):
        mime = QMimeData()
        try:
            mime.setText(binascii.a2b_hex(self._selected_data))
        except TypeError:
            raise Exception("TOP values are not supported yet")
        QApplication.clipboard().setMimeData(mime)

    def _handle_copy_hex(self):
        mime = QMimeData()
        mime.setText(self._selected_data)
        QApplication.clipboard().setMimeData(mime)

    def _handle_copy_base64(self):
        mime = QMimeData()
        try:
            mime.setText(base64.b64encode(
                binascii.a2b_hex(self._selected_data)))
        except TypeError:
            raise Exception("TOP values are not supported yet")
        QApplication.clipboard().setMimeData(mime)

    def add_origin(self, origin):
        self._origins.append(origin)
        self.originsChanged.emit()

    def remove_origin(self, origin):
        self._origins.remove(origin)
        self.originsChanged.emit()

    def _handle_add_taint_override(self, re_run):
        start_idx, end_idx = self._hsm.start, self._hsm.end
        abs_start = self._meminfo.abs_addr_from_idx(start_idx)
        abs_end = self._meminfo.abs_addr_from_idx(end_idx)
        self.newOverride.emit(abs_start, abs_end, re_run)

    def _handle_add_origin(self, qindex):
        index = self.getModel().qindex2index(qindex)
        name, ok = QInputDialog.getText(self, "Add origin...", "Origin name:")
        if ok and name:
            self.add_origin(Origin(index, name))
