import os
import base64
import binascii
from collections import namedtuple

import intervaltree

from PyQt5.QtGui import QIcon
from PyQt5.QtGui import QBrush
from PyQt5.QtGui import QPixmap
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
from PyQt5.QtWidgets import QSizePolicy
from PyQt5.QtWidgets import QApplication
from PyQt5.QtWidgets import QInputDialog
from PyQt5.QtWidgets import QStyledItemDelegate
from PyQt5.QtWidgets import QAbstractItemView

from .hexview_auto import Ui_Form as HexViewBase
from .common import h
from .common import LoggingObject
from .tablecellstylemodels import row_start_index
from .tablecellstylemodels import row_end_index
from .tablecellstylemodels import row_number
from .tablecellstylemodels import ROLE_BORDER
from .tablecellstylemodels import ColorModel
from .tablecellstylemodels import BorderModel

NamedColor = namedtuple("NamedColor", ["name", "qcolor"])
QT_COLORS = (
        NamedColor("red", Qt.red),
        NamedColor("green", Qt.green),
        NamedColor("blue", Qt.blue),
        NamedColor("black", Qt.black),
        NamedColor("dark red", Qt.darkRed),
        NamedColor("dark green", Qt.darkGreen),
        NamedColor("dark blue", Qt.darkBlue),
        NamedColor("cyan", Qt.cyan),
        NamedColor("magenta", Qt.magenta),
        NamedColor("yellow", Qt.yellow),
        NamedColor("gray", Qt.gray),
        NamedColor("dark cyan", Qt.darkCyan),
        NamedColor("dark magenta", Qt.darkMagenta),
        NamedColor("dark yellow", Qt.darkYellow),
        NamedColor("dark gray", Qt.darkGray),
        NamedColor("light gray", Qt.lightGray),
)


def make_color_icon(color):
        pixmap = QPixmap(10, 10)
        pixmap.fill(color)
        return QIcon(pixmap)


class HexItemDelegate(QStyledItemDelegate):
    def __init__(self, model, parent, *args):
        super(HexItemDelegate, self).__init__(parent)
        self._model = model

    def paint(self, qpainter, option, qindex):
        super(HexItemDelegate, self).paint(qpainter, option, qindex)
        border = self._model.data(qindex, ROLE_BORDER)

        if border is None:
            self.initStyleOption(option, qindex)

            qpainter.save()

            doc = QTextDocument()
            doc.setHtml(option.text)

            option.text = ""
            option.widget.style().drawControl(QStyle.CE_ItemViewItem, option, qpainter)

            qpainter.translate(option.rect.left(), option.rect.top())
            clip = QRectF(0, 0, option.rect.width(), option.rect.height())
            doc.drawContents(qpainter, clip)

            qpainter.restore()
            return

        qpainter.setPen(border.theme.color)
        r = option.rect
        if border.top:
            qpainter.drawLine(r.topLeft(), r.topRight())

        if border.bottom:
            qpainter.drawLine(r.bottomLeft(), r.bottomRight())

        if border.left:
            qpainter.drawLine(r.topLeft(), r.bottomLeft())

        if border.right:
            qpainter.drawLine(r.topRight(), r.bottomRight())


class HexTableModel(QAbstractTableModel):
    FILTER = ''.join([(len(repr(chr(x)))==3 or chr(x) == "\\") and chr(x) or '.' for x in range(256)])

    def __init__(self, meminfo, parent=None, *args):
        super(HexTableModel, self).__init__(parent, *args)
        self._meminfo = meminfo
        self._colors = ColorModel(self)
        self._borders = BorderModel(self)

        self._colors.rangeChanged.connect(self._handle_color_range_changed)
        self._borders.rangeChanged.connect(self._handle_border_range_changed)

    def getColorModel(self):
        return self._colors

    def setColorModel(self, color_model):
        self._colors.rangeChanged.disconnect(self._handle_color_range_changed)
        self._colors = color_model
        self._colors.rangeChanged.connect(self._handle_color_range_changed)
        # TODO: re-render all cells

    def getBorderModel(self):
        return self._borders

    def setBorderModel(self, color_model):
        self._borders.rangeChanged.disconnect(self._handle_border_range_changed)
        self._borders = color_model
        self._borders.rangeChanged.connect(self._handle_border_range_changed)
        # TODO: re-render all cells

    @staticmethod
    def qindex2index(index):
        """ from a QIndex (row/column coordinate system), get the buffer index of the byte """
        r = index.row()
        c = index.column()
        if c > 0x10:
            return (0x10 * r) + c - 0x11
        else:
            return (0x10 * r) + c

    def index2qindexb(self, index):
        """ from a buffer index, get the QIndex (row/column coordinate system) of the byte pane """
        r = index // 0x10
        c = index % 0x10
        return self.index(r, c)

    def index2qindexc(self, index):
        """ from a buffer index, get the QIndex (row/column coordinate system) of the char pane """
        r = (index // 0x10)
        c = index % 0x10 + 0x11
        return self.index(r, c)

    def rowCount(self, parent):
        length = self._meminfo.length
        if length % 0x10 != 0:
            return (length // 0x10) + 1
        else:
            return length // 0x10

    def columnCount(self, parent):
        return 0x21

    def data(self, index, role):
        if not index.isValid():
            return None

        elif self.qindex2index(index) >= self._meminfo.length:
            return None

        col = index.column()
        bindex = self.qindex2index(index)
        if role == Qt.DisplayRole:
            if col == 0x10:
                return ""
            if col < 0x10:
                return self._meminfo[bindex]
            else:
                return self._meminfo.char(bindex)

        elif role == Qt.BackgroundRole:
            # don't color the divider column
            if col == 0x10:
                return None

            color = self._colors.get_color(bindex)
            if color is not None:
                return QBrush(color)
            return None

        elif role == ROLE_BORDER:
            if col == 0x10:
                return None
            return self._borders.get_border(bindex)

        else:
            return None

    @property
    def data_length(self):
        return self._meminfo.length

    def headerData(self, section, orientation, role):
        if role != Qt.DisplayRole:
            return None

        elif orientation == Qt.Horizontal:
            if section < 0x10:
                return "%01X" % (section)
            else:
                return ""
        elif orientation == Qt.Vertical:
            return "%08X" % (section * 0x10 + self._meminfo.start)

        else:
            return None

    def _emit_data_changed(self, start_bindex, end_bindex):
        for i in range(start_bindex, end_bindex):
            # mark data changed to encourage re-rendering of cell
            qib = self.index2qindexb(i)
            qic = self.index2qindexc(i)
            self.dataChanged.emit(qib, qib)
            self.dataChanged.emit(qic, qic)

    def _handle_color_range_changed(self, range):
        self._emit_data_changed(range.begin, range.end + 1)

    def _handle_border_range_changed(self, range):
        self._emit_data_changed(range.begin, range.end + 1)


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
        """ add the given buffer indices to the given QItemSelection, both byte and char panes """
        selection.select(self._model.index2qindexb(start_bindex), self._model.index2qindexb(end_bindex))
        selection.select(self._model.index2qindexc(start_bindex), self._model.index2qindexc(end_bindex))

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

        selection = QItemSelection()
        if row_number(end_bindex) - row_number(start_bindex) == 0:
            # all on one line
            self._bselect(selection, start_bindex, end_bindex)
        elif row_number(end_bindex) - row_number(start_bindex) == 1:
            # two lines
            self._bselect(selection, start_bindex, row_end_index(start_bindex))
            self._bselect(selection, row_start_index(end_bindex), end_bindex)
        else:
            # many lines
            self._bselect(selection, start_bindex, row_end_index(start_bindex))
            self._bselect(selection, row_start_index(start_bindex) + 0x10, row_end_index(end_bindex) - 0x10)
            self._bselect(selection, row_start_index(end_bindex), end_bindex)

        self.select(selection, QItemSelectionModel.SelectCurrent)
        self.start = start_bindex
        self.end = end_bindex
        self.selectionRangeChanged.emit(end_bindex)

    def bselect(self, start_bindex, end_bindex):
        """  the public interface to _do_select """
        return self._do_select(start_bindex, end_bindex)

    def handle_move_key(self, key):
        if self._start_qindex == self._model.index2qindexc(self.start) or \
            self._start_qindex == self._model.index2qindexb(self.start):
            i = self.end
        else:
            i = self.start
        if key == QKeySequence.MoveToEndOfDocument:
            i = self._model.data_length - 1
        elif key == QKeySequence.MoveToEndOfLine:
            i = row_end_index(i)
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
            i = row_start_index(i)
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
        if self._start_qindex == self._model.index2qindexc(self.start) or \
            self._start_qindex == self._model.index2qindexb(self.start):
            i = self.end
            j = self.start
        else:
            i = self.start
            j = self.end

        if key == QKeySequence.SelectEndOfDocument:
            i = self._model.data_length - 1
        elif key == QKeySequence.SelectEndOfLine:
            i = row_end_index(i)
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
            i = row_start_index(i)
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

    def __init__(self, meminfo, parent=None):
        super(HexViewWidget, self).__init__()
        self.setupUi(self)
        self._meminfo = meminfo
        self._model = HexTableModel(self._meminfo)

        self._colored_regions = intervaltree.IntervalTree()
        self._origins = []

        # ripped from pyuic5 ui/hexview.ui
        #   at commit 6c9edffd32706097d7eba8814d306ea1d997b25a
        # so we can add our custom HexTableView instance
        self.view = HexTableView(self)
        sizePolicy = QSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.view.sizePolicy().hasHeightForWidth())
        self.view.setSizePolicy(sizePolicy)
        self.view.setMinimumSize(QSize(660, 0))
        self.view.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        self.view.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.view.setSelectionMode(QAbstractItemView.NoSelection)
        self.view.setShowGrid(False)
        self.view.setWordWrap(False)
        self.view.setObjectName("view")
        self.view.horizontalHeader().setDefaultSectionSize(35)
        self.view.horizontalHeader().setMinimumSectionSize(35)
        self.view.verticalHeader().setDefaultSectionSize(31)
        self.mainLayout.insertWidget(0, self.view)
        # end rip

        # TODO: provide a HexViewWidget.setModel method, and don't build it ourselves
        self.view.setModel(self._model)
        for i in range(0x10):
            self.view.setColumnWidth(i, 35)
        self.view.setColumnWidth(0x10, 15)
        for i in range(0x11, 0x22):
            self.view.setColumnWidth(i, 21)

        self._hsm = HexItemSelectionModel(self._model, self.view)
        self.view.setSelectionModel(self._hsm)

        self.view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.view.customContextMenuRequested.connect(self._handle_context_menu_requested)

        self._hsm.selectionRangeChanged.connect(self._handle_selection_range_changed)

        self.originsChanged.connect(self._handle_origins_changed)

        self.view.moveKeyPressed.connect(self._hsm.handle_move_key)
        self.view.selectKeyPressed.connect(self._hsm.handle_select_key)

        f = QFont("Monospace")
        f = QFontDatabase.systemFont(QFontDatabase.FixedFont)


        self.view.setFont(f)
        self.statusLabel.setFont(f)

        self.view.setItemDelegate(HexItemDelegate(self._model, self))

        self.statusLabel.setText("")

    def getModel(self):
        return self._model

    def getColorModel(self):
        """ this is a shortcut, to make it easy to add/remove colored ranges """
        return self.getModel().getColorModel()

    def getBorderModel(self):
        """ this is a shortcut, to make it easy to add/remove bordered ranges """
        return self.getModel().getBorderModel()

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

        add_action(menu, "Color selection", self._handle_color_selection)

        # duplication here with vstructui
        color_menu = menu.addMenu("Color selection...")

        # need to escape the closure capture on the color loop variable below
        # hint from: http://stackoverflow.com/a/6035865/87207
        def make_color_selection_handler(color):
            return lambda: self._handle_color_selection(color=color)

        for color in QT_COLORS:
            add_action(color_menu, "{:s}".format(color.name),
                       make_color_selection_handler(color.qcolor), make_color_icon(color.qcolor))

        start = self._hsm.start
        end = self._hsm.end
        cm = self.getColorModel()
        if (start == end and cm.is_index_colored(start)) or cm.is_region_colored(start, end):
            def make_remove_color_handler(r):
                return lambda: self._handle_remove_color_range(r)

            remove_color_menu = menu.addMenu("Remove color...")
            for cr in cm.get_region_colors(start, end):
                pixmap = QPixmap(10, 10)
                pixmap.fill(cr.color)
                icon = QIcon(pixmap)
                add_action(remove_color_menu,
                       "Remove color [{:s}, {:s}], len: {:s}".format(h(cr.begin), h(cr.end), h(cr.end - cr.begin)),
                       make_remove_color_handler(cr), make_color_icon(cr.color))

        menu.addSeparator()  # -----------------------------------------------------------------

        add_action(menu, "Copy selection (binary)", self._handle_copy_binary)
        copy_menu = menu.addMenu("Copy...")
        add_action(copy_menu, "Copy selection (binary)", self._handle_copy_binary)
        add_action(copy_menu, "Copy selection (text)", self._handle_copy_text)
        add_action(copy_menu, "Copy selection (hex)", self._handle_copy_hex)
        add_action(copy_menu, "Copy selection (base64)", self._handle_copy_base64)

        menu.addSeparator()  # -----------------------------------------------------------------

        add_action(menu, "Add origin", lambda: self._handle_add_origin(index))
        return menu

    def _handle_context_menu_requested(self, qpoint):
        self.get_context_menu(qpoint).exec_(self.view.mapToGlobal(qpoint))

    def _handle_color_selection(self, color=None):
        # qt seems to set non-existant keyword args to False, so we manually reset to None
        if not color:
            color = None

        s = self._hsm.start
        e = self._hsm.end + 1
        range = self.getColorModel().color_region(s, e, color=color)
        self._hsm.bselect(-1, -1)
        # seems to be a bit of duplication here and in the ColorModel?
        self._colored_regions.addi(s, e, range)

    def _handle_remove_color_range(self, range):
        self.getColorModel().clear_range(range)

    @property
    def _selected_data(self):
        start = self._hsm.start
        end = self._hsm.end
        return self._meminfo[start:end]

    def _handle_copy_binary(self):
        mime = QMimeData()
        # mime type suggested here: http://stackoverflow.com/a/6783972/87207
        mime.setData("application/octet-stream", self._selected_data)
        QApplication.clipboard().setMimeData(mime)

    def _handle_copy_text(self):
        mime = QMimeData()
        mime.setText(self._selected_data)
        QApplication.clipboard().setMimeData(mime)

    def _handle_copy_hex(self):
        mime = QMimeData()
        mime.setText(binascii.b2a_hex(self._selected_data))
        QApplication.clipboard().setMimeData(mime)

    def _handle_copy_base64(self):
        mime = QMimeData()
        mime.setText(base64.b64encode(self._selected_data))
        QApplication.clipboard().setMimeData(mime)

    def add_origin(self, origin):
        self._origins.append(origin)
        self.originsChanged.emit()

    def remove_origin(self, origin):
        self._origins.remove(origin)
        self.originsChanged.emit()

    def _handle_add_origin(self, qindex):
        index = self.getModel().qindex2index(qindex)
        name, ok = QInputDialog.getText(self, "Add origin...", "Origin name:")
        if ok and name:
            self.add_origin(Origin(index, name))
