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
import logging
import idaapi
from idabincat.analyzer_conf import ConfigHelpers

dump_log = logging.getLogger('bincat.plugin.dump_binary')
dump_log.setLevel(logging.INFO)


# Dumps a remapped binary (as seen in IDA to disk)
# returns a list of sections
# [(name, va, vasize, raw_addr, raw_size)]
def dump_binary(path):
    max_addr = 0
    # Check if we have a buggy IDA or not
    try:
        idaapi.get_many_bytes_ex(0, 1)
    except TypeError:
        buggy = True
    else:
        buggy = False
    if buggy:
        f = idaapi.qfile_t()
        try:
            f.open(path, 'wb+')
        except TypeError:
            # Another ugly hack for IDA 6/7 compat (unicode strings)
            f.open(str(path), 'wb+')
        segments = [idaapi.getnseg(x) for x in range(idaapi.get_segm_qty())]

        # no need for IDA 7 compat, it's not buggy
        max_addr = segments[-1].endEA

        if max_addr > 200*1024*1024:
            if idaapi.ask_yn(
                    idaapi.ASKBTN_NO, "Dump file is over 200MB,"
                    " do you want to dump it anyway ?") != idaapi.ASKBTN_YES:
                return None

        idaapi.base2file(f.get_fp(), 0, 0, max_addr)
        f.close()
        return [("dump", 0, max_addr, 0, max_addr)]

    else:
        sections = []
        current_offset = 0
        with open(path, 'wb+') as f:
            # over all segments
            for n in range(idaapi.get_segm_qty()):
                seg = idaapi.getnseg(n)
                if hasattr(seg, "start_ea"):
                    start_ea = seg.start_ea
                else:
                    start_ea = seg.startEA
                if hasattr(seg, "end_ea"):
                    end_ea = seg.end_ea
                else:
                    end_ea = seg.endEA
                size = end_ea - start_ea
                # Only works with fixed IDAPython.
                f.write(idaapi.get_many_bytes_ex(start_ea, size)[0])
                sections.append(
                    (idaapi.get_segm_name(seg), start_ea, size,
                     current_offset, size))
                current_offset += size
        dump_log.debug(repr(sections))
        return sections


if __name__ == '__main__':
    fname = ConfigHelpers.askfile("*.*", "Save to binary")
    dump_binary(fname)
