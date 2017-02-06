import idc
import idautils
import idaapi

fname = idaapi.askfile_c(1, "*.*", "Save to binary")

max_addr = 0
f = open(fname, 'wb+')
# over all segments
for s in idautils.Segments():
    start = idc.GetSegmentAttr(s, idc.SEGATTR_START)
    end = idc.GetSegmentAttr(s, idc.SEGATTR_END)
    # print "Start: %x, end: %x, size: %x" % (start, end, end-start)
    max_addr = max(max_addr, end)
    f.seek(start, 0)
    # Only works with fixed IDAPython.
    f.write(idaapi.get_many_bytes_ex(start, end-start)[0])
f.close()

print "section[dump] = 0, 0x%x, 0, 0x%x" % (max_addr, max_addr)
