
import pytest
import hashlib
import itertools


def armv8_bitmasks():
    res = []
    size = 2
    while size <= 64:
        for length in range(1, size):
            result = 0xffffffffffffffff >> (64 - length)
            e = size
            while e < 64:
                result |= result << e
                e *= 2
            for rotation in range(0, size):
                result = (result >> 63) | (result << 1)
                result &= 0xFFFFFFFFFFFFFFFF
                res.append(result)
        size *= 2
    return res


class TestValues_Meta(type):
    def __repr__(self):
        return self._name

class TestValues(object, metaclass=TestValues_Meta):
    _name = "NA"
    hash_single = False
    loop_cnt = [1, 15, 100]
    op3 = [ 0, 1, 4, 7 ]
    op5 = [ 0, 1, 8, 30, 31 ]
    op6 = [ 0, 1, 0x3F ]
    op6_32 = [ 0, 1, 31 ]
    op8 =  [ 1, 0xff ]
    op12_s = [-0x800, 0, 1, 0x7ff ]
    op16 = [ 1, 0xffff ]
    op16_s = [ 1, 0x7fff, -0x8000 ]
    op32 = [ 1, 0xffffffff]
    op64 = [ 1, 0xffffffffffffffff]
    op12 = [ 1, 0x800, 0xFFF]
    op32h = [ 0, 0xffff ]
    op32l = [ 0, 1, 0xffff ]
    someval8 = [ 0x2e, 0xa5 ]
    someval16 = [ 0x4b2e, 0xc68b ]
    someval32 = [ 0x5ed39a5f, 0xd2a173f6 ]
    someval64 = [ 0x27f4a35c5ed39a5f, 0xd2ac53201ca173f6 ]
    shift = [ 1, 32]
    armv7shift = [0, 31]
    armv8shift = [0, 16, 32, 48]
    armv7op = [1, 0xff]
    x86carryop = [ "stc", "clc"]
    armv8bitmasks = armv8_bitmasks()[0:10]
    armv8off = [-512, -8, 0, 8, 504]
    op5_couple = [(x,y) for x,y in itertools.product(op5,op5) if x+y <= 31 and y > 0]

class Large(TestValues):
    _name = "large"
    op8 = [ 0, 1, 2, 7, 8, 0xf, 0x10, 0x7f, 0x80, 0x81, 0xff]
    op12_s = op8 + [-0x800, -0x100, -0xff, -1,  0x7ff ]
    op16 = op8 +  [0x1234, 0x7fff, 0x8000, 0x8001, 0xfa72, 0xffff]
    op16_s = op8 + [ 0x1234, 0x7fff, -0x8000 -0x7fff, -1]
    op32 = op16 +  [0x12345678, 0x1812fada, 0x12a4b4cd,
                    0x7fffffff, 0x80000000, 0x80000001, 0xffffffff ]
    op64 = op32 +  [ 0x123456789, 0x100000000000,  0x65a227c6f24c562a,
                     0x7fffffffffffffff, 0x8000000000000000, 0x80000000000000001,
                     0xa812f8c42dec45ab, 0xffff123456789abc,  0xffffffffffffffff ]
    op32h = [ 0, 0x1234, 0x7fff, 0x8000, 0xffff ]
    shift = [0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 24, 31,
               32, 33, 48, 63, 64, 65, 127, 128, 129, 255 ]
    x86carryop = [ "stc", "clc" ]
    armv7shift = [0, 1, 7, 8, 0xf, 31]
    armv7op = [(x<<y) for x in [1, 0x7f , 0x80, 0xff] for y in range(0,28,4)]
    armv8bitmasks = armv8_bitmasks()[0:150]

class Medium(TestValues):
    _name = "medium"
    op8 =  [ 0, 1, 0x7f, 0x80, 0xff ]
    op16 = [ 0, 1, 0xff, 0x7fff, 0x8000, 0xffff ]
    op16_s = [ -0x8000, -0x7fff, -0xff, -1, 0, 1, 0xff, 0x7fff]
    op32 = [ 0, 1, 0x7fffffff, 0x80000000, 0xffffffff]
    op64 = op32 + [ 0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff]
    op32h = [ 0, 0x7fff, 0x8000, 0xffff ]
    shift = [ 0, 1, 7, 8, 0xf, 0x7f, 0x80, 0x81, 0xff]
    x86carryop = [ "stc", "clc" ]
    armv7shift = [0, 1, 0xf, 31]
    armv7op = [1, 0x7f , 0x80, 0xff, 0x7f00, 0x8000, 0x7f000000, 0xff000000, 0x8000000]
    armv8bitmasks = armv8_bitmasks()[0:20]

class Small(TestValues):
    _name = "small"
    x86carryop = [ "stc" ]
    op3 = [ 0, 7 ]

class Smoke(Large):
    """
    Fast(er?) test set for CI
    """
    hash_single = True
    _name = "smoke"


COVERAGES = [Large, Medium, Small, Smoke]


def pytest_addoption(parser):
    parser.addoption("--coverage", choices=[x._name for x in COVERAGES],
                     default="medium", help="test more or less values")


def pytest_generate_tests(metafunc):
    func_name = metafunc.function.__name__
    coverage = {x._name: x for x in COVERAGES}[metafunc.config.option.coverage]
    for fn in metafunc.fixturenames:
        fnstr = fn.rstrip("_")  # alias foo_, foo__, etc. to foo
        if hasattr(coverage, fnstr):
            params = getattr(coverage, fnstr)
            if coverage.hash_single:
                hashint = int(hashlib.sha1((func_name + fnstr).encode("utf8")).hexdigest(), 16)
                paramidx = hashint % len(params)
                params = [params[paramidx]]
            metafunc.parametrize(fn, params)
