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


def memoize(f):
    """ Memoization decorator for a function taking a single argument """
    class memodict(dict):
        def __missing__(self, key):
            ret = self[key] = f(key)
            return ret
    return memodict().__getitem__


@memoize
def parse_val(s):
    if s[0] not in '0123456789_?' or '_bincat_tmp' in s:
        # it's a register
        return s, 0, 0
    tbvals = dict.fromkeys(["?", "_"], 0)
    val = None
    bdict = {"0x": (16, "f"),
             "0o": (8, "7"),
             "0b": (2, "1")}
    for p in s.split(","):
        if "=" in p:
            lv, rv = p.split("=", 1)
            lv = lv.strip()
            rv = rv.strip()
            base, digit = bdict.get(rv[:2], (10, "9"))
            tbvals[lv] |= int(rv, base)
        else:
            p = p.strip()

            base, digit = bdict.get(p[:2], (10, "9"))
            if base in [2, 4, 8, 16, 32, 64]:
                vv = int(p.replace("_", "0").replace("?", "0"), base)
                vtop = int(p.replace("_", "0").replace("?", digit), base)
                vbot = int(p.replace("?", "0").replace("_", digit), base)
            else:
                if "?" in p or "_" in p:
                    raise Exception("Cannot put '?' or '_' in base %i" % base)
                vv = int(p, base)
                vtop = vbot = vv
            if val is not None:
                raise Exception("Cannot put several values in the same line")
            val = vv
            tbvals["?"] |= vtop ^ vv
            tbvals["_"] |= vbot ^ vv
    top = tbvals["?"]
    bot = tbvals["_"]
    if top & bot:
        raise Exception(
            "bits %#x are set both at top(?) and bottom(_)" % top & bot)
    return val, tbvals["?"], tbvals["_"]


def val2str(val, vtop, vbot, length, base=None, merged=False):
    if base == 16 or not base:
        if length == 0 or length is None:
            fstring = '{0:X}'
        else:
            if length % 4 == 0:
                length = length / 4
            else:
                length = (length / 4)+1
            fstring = ('{0:0>%dX}' % length)
    elif base == 2:
        fstring = ('0b{0:0>%db}' % length)
    else:
        raise ValueError("Invalid base")

    if type(val) == str:
        s = val
    else:
        s = fstring.format(val)
    if vtop:
        s_top = fstring.format(vtop)
        if merged:
            s = "".join(v if t == '0' else '?' for v, t in zip(s, s_top))
        else:
            s += ",?=" + s_top
    if vbot:
        s_bot = fstring.format(vbot)
        if merged:
            s = "".join(v if t == '0' else '_' for v, t in zip(s, s_bot))
        else:
            s += ",_=" + s_bot
    return s
