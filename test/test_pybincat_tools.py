#!/usr/bin/env python3
"""
Tests tools
"""

import pytest
from pybincat.tools.parsers import parse_val


@pytest.mark.parametrize(("test", "expval", "exptop", "expbot"), [
    ("0b111101101", 0b111101101, 0, 0),
    ("1231532", 1231532, 0, 0),
    ("0x5f5c2", 0x5f5c2, 0, 0),
    ("0x5f5?2", 0x5f502, 0xf0, 0),
    ("0xa__52", 0xa0052, 0, 0xff00),
    ("0xa__52", 0xa0052, 0, 0xff00),
    ("1544552", 1544552, 0, 0),
    ("0x4f2eb,_=0x12,?=0xe00", 0x4f2eb, 0xe00, 0x12),
    ("0x12_3?,?=0b110000,_=0b11000000000000", 0x12030, 0x3f, 0x3f00),
    ("?=0b11,0x1234,?=0xf0,_=0xf00", 0x1234, 0xf3, 0xf00),
    ("?=0b1100 , 1234,  ?=0xf0  ,_=0xa00", 1234, 0xfc, 0xa00),
    ("0b________", 0, 0, 0xff),
])
def test_parse_val(test, expval, exptop, expbot):
    val, top, bot = parse_val(test)
    assert val == expval
    assert top == exptop
    assert bot == expbot


@pytest.mark.parametrize("test", [
    "012_45", "42?", "0x123,?=0xf, 0x45",
    "123,_=0xff,?=0xff0",
])
def test_parse_val_exc(test):
    with pytest.raises(Exception):
        parse_val(test)
