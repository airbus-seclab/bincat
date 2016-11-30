from idaapi import *

imports = []

# get import type and add used types in local types
# to ensure "correct" export
def imp_cb(ea, name, ord):
    # Get type
    imp_t = tinfo_t()
    if get_tinfo2(ea, imp_t):
        # Iterate over ret type and args
        for i in range(-1, imp_t.get_nargs()):
            arg_t = imp_t.get_nth_arg(i)
            # cvar.idati is the "local types"
            import_type(cvar.idati, -1, str(arg_t), 0)
        imports.append(print_type(ea, True))
    return True

nimps = idaapi.get_import_module_qty()
for i in xrange(0, nimps):
    idaapi.enum_import_names(i, imp_cb)

# Types we have already inspected
seen = set()

# List of structures, to patch .h later
structs = set()

### Recursively parse type tinfo;
### adding unknown members to the local types as necessary
def recurse_type(tinfo):
    print "recurse_type : "+str(tinfo)
    if str(tinfo) in seen:
        return
    else:
        seen.add(str(tinfo))
        import_type(cvar.idati, -1, str(tinfo), 0)
        print "import : "+str(tinfo)

    # Struct or union ? Walk members
    if tinfo.is_udt():
        # Hack to avoid problems with:
        # typedef struct _TOTO TOTO
        # IDA considers both _TOTO and TOTO as structs
        # this hack seems to fix it
        print "---\t %s %s" % (tinfo.get_final_type_name(), str(tinfo))
        if tinfo.get_final_type_name() == str(tinfo):
            print "adding to structs"
            structs.add(str(tinfo))

        u = udt_member_t()
        # Members
        for idx in range(0, tinfo.get_udt_nmembers()):
            u.offset = idx
            tinfo.find_udt_member(STRMEM_INDEX, u)
            recurse_type(u.type) # Recurse base type
            # AND also without pointer
            # to handle both shitty cases like : 
            #   - PVOID (pointer but not to struct)
            #   - COMPLEX_STRUCT *
            if u.type.is_ptr_or_array():
                no_ptr = u.type
                no_ptr.remove_ptr_or_array()
                recurse_type(no_ptr)
    return


# Fix local types by recursively making sure all types are defined
local_type = tinfo_t()
for ordinal in range(1, get_ordinal_qty(cvar.idati)):
    local_type.get_numbered_type(cvar.idati, ordinal)
    recurse_type(local_type)

# Sink to get .h in a string
class str_sink(ida_typeinf.text_sink_t):
    def __init__(self):
        ida_typeinf.text_sink_t.__init__(self)
        self.text = ""

    def _print(self, defstr):
        self.text += defstr
        return 0

    def res(self):
        return self.text

sink = str_sink()
ida_typeinf.print_decls(sink, ida_typeinf.cvar.idati, [],  PDF_INCL_DEPS|PDF_DEF_FWD|PDF_DEF_BASE)

# Generate fixed .h
res = sink.res()
for s in structs:
    if "struct " not in s:
        search = r"(^\s*(?:typedef )?)\b%s\b"%s
        print search
        res = re.sub(re.compile(search, re.MULTILINE), r"\1struct %s" % s, res)

res += "\n\n"+"\n".join(imports)
c=open("/tmp/aa.h", "wt+")
c.write(res)
c.close()
