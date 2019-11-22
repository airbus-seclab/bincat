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
    sections = []
    current_offset = 0
    with open(path, 'wb+') as f:
        # over all segments
        for n in range(idaapi.get_segm_qty()):
            seg = idaapi.getnseg(n)
            start_ea = seg.start_ea
            end_ea = seg.end_ea
            size = end_ea - start_ea
            # IDA7.4 FIXME
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
