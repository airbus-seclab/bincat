from collections import namedtuple
from collections import defaultdict

import funcy
from intervaltree import IntervalTree
from PyQt5.QtCore import QObject
from PyQt5.QtCore import pyqtSignal

from .mutablenamedtuple import mutablenamedtuple
from .colortheme import SolarizedColorTheme


def row_start_index(index):
    """ get index of the start of the 0x10 byte row containing the given index """
    return index - (index % 0x10)


def row_end_index(index):
    """ get index of the end of the 0x10 byte row containing the given index """
    return index - (index % 0x10) + 0xF


def row_number(index):
    """ get row number of the 0x10 byte row containing the given index """
    return index // 0x10


def column_number(index):
    return index % 0x10


ColoredRange = namedtuple("ColorRange", ["begin", "end", "color"])


class ColorModel(QObject):
    rangeChanged = pyqtSignal([ColoredRange])

    def __init__(self, parent, color_theme=SolarizedColorTheme):
        super(ColorModel, self).__init__(parent)
        self._db = IntervalTree()
        self._theme = color_theme

    def color_region(self, begin, end, color=None):
        if color is None:
            color = self._theme.get_accent(len(self._db))
        r = ColoredRange(begin, end, color)
        self.color_range(r)
        return r

    def clear_region(self, begin, end):
        span = end - begin
        to_remove = []
        for r in self._db[begin:end]:
            if r.end - r.begin == span:
                to_remove.append(r)
        for r in to_remove:
            self.clear_range(r.data)

    def color_range(self, range_):
        self._db.addi(range_.begin, range_.end, range_)
        self.rangeChanged.emit(range_)

    def clear_range(self, range_):
        self._db.removei(range_.begin, range_.end, range_)
        self.rangeChanged.emit(range_)

    def get_color(self, index):
        # ranges is a (potentially empty) list of intervaltree.Interval instances
        # we sort them here from shorted length to longest, because we want
        #    the most specific color
        ranges = sorted(self._db[index], key=lambda r: r.end - r.begin)
        if len(ranges) > 0:
            return ranges[0].data.color
        return None

    def get_region_colors(self, begin, end):
        if begin == end:
            results = self._db[begin]
        else:
            results = self._db[begin:end]
        return funcy.pluck_attr("data", results)

    def is_index_colored(self, index):
        return len(self._db[index]) > 0

    def is_region_colored(self, begin, end):
        return len(self._db[begin:end]) > 0


ROLE_BORDER = 0xF
BorderTheme = namedtuple("BorderTheme", ["color"])
BorderData = namedtuple("BorderData", ["top", "bottom", "left", "right", "theme"])
BorderedRange = namedtuple("BorderedRange", ["begin", "end", "theme", "cells"])


CellT = mutablenamedtuple("CellT", ["top", "bottom", "left", "right"])
def Cell(top=False, bottom=False, left=False, right=False):
    return CellT(top, bottom, left, right)


def compute_region_border(start, end):
    """
    given the buffer start and end indices of a range, compute the border edges
      that should be drawn to enclose the range.

    this function currently assumes 0x10 length rows.
    the result is a dictionary from buffer index to Cell instance.
    the Cell instance has boolean properties "top", "bottom", "left", and "right"
      that describe if a border should be drawn on that side of the cell view.
    :rtype: Mapping[int, CellT]
    """
    cells = defaultdict(Cell)

    start_row = row_number(start)
    end_row = row_number(end)
    if end % 0x10 == 0:
        end_row -= 1

    ## topmost cells
    if start_row == end_row:
        for i in range(start, end):
            cells[i].top = True
    else:
        for i in range(start, row_end_index(start) + 1):
            cells[i].top = True
    # cells on second row, top left
    if start_row != end_row:
        next_row_start = row_start_index(start) + 0x10
        for i in range(next_row_start, next_row_start + column_number(start)):
            cells[i].top = True

    ## bottommost cells
    if start_row == end_row:
        for i in range(start, end):
            cells[i].bottom = True
    else:
        for i in range(row_start_index(end), end):
            cells[i].bottom = True
    # cells on second-to-last row, bottom right
    if start_row != end_row:
        prev_row_end = row_end_index(end) - 0x10
        for i in range(prev_row_end - (0x10 - column_number(end) - 1), prev_row_end + 1):
            cells[i].bottom = True

    ## leftmost cells
    if start_row == end_row:
        cells[start].left = True
    else:
        second_row_start = row_start_index(start) + 0x10
        for i in range(second_row_start, row_start_index(end) + 0x10, 0x10):
            cells[i].left = True
    # cells in first row, top left
    if start_row != end_row:
        cells[start].left = True

    ## rightmost cells
    if start_row == end_row:
        cells[end - 1].right = True
    else:
        penultimate_row_end = row_end_index(end) - 0x10
        for i in range(row_end_index(start), penultimate_row_end + 0x10, 0x10):
            cells[i].right = True
    # cells in last row, bottom right
    if start_row != end_row:
        cells[end - 1].right = True

    # convert back to standard dict
    # trick from: http://stackoverflow.com/a/20428703/87207
    cells.default_factory = None
    return cells


class BorderModel(QObject):
    rangeChanged = pyqtSignal([BorderedRange])

    def __init__(self, parent, color_theme=SolarizedColorTheme):
        super(BorderModel, self).__init__(parent)

        # data structure description:
        # _db is an interval tree that indexes on the start and end of bordered ranges
        # the values are BorderedRange instances.
        # given an index, determining its border is):
        #   intervaltree lookup index in _db (which is O(log <num ranges>) )
        #   iterate containing ranges (worst case, O(<num ranges>), but typically small)
        #     hash lookup on index to fetch border state (which is O(1))
        self._db = IntervalTree()
        self._theme = color_theme

    def border_region(self, begin, end, color=None):
        if color is None:
            color = self._theme.get_accent(len(self._db))
        range = BorderedRange(begin, end, BorderTheme(color), compute_region_border(begin, end))
        # note we use (end + 1) to ensure the entire selection gets captured
        self._db.addi(range.begin, range.end + 1, range)
        self.rangeChanged.emit(range)

    def clear_region(self, begin, end):
        span = end - begin
        to_remove = []
        for r in self._db[begin:end]:
            if r.end - r.begin - 1 == span:
                to_remove.append(r)
        for r in to_remove:
            self._db.removei(r.begin, r.end, r.data)
            self.rangeChanged.emit(r.data)

    def get_border(self, index):
        # ranges is a (potentially empty) list of intervaltree.Interval instances
        # we sort them here from shorted length to longest, because we want
        #    the most specific border
        ranges = sorted(self._db[index], key=lambda r: r.end - r.begin)
        if len(ranges) > 0:
            range = ranges[0].data
            cell = range.cells.get(index, None)
            if cell is None:
                return None
            ret = BorderData(cell.top, cell.bottom, cell.left, cell.right, range.theme)
            return ret
        return None

    def is_index_bordered(self, index):
        return len(self._db[index]) > 0

    def is_region_bordered(self, begin, end):
        span = end - begin
        for range in self._db[begin:end]:
            if range.end - range.begin == span:
                return True
        return False
