from idaapi import *
import idaapi

# helper do import a type by name into local types
def import_name(type_name):
    # print "import_name : "+type_name
    import_type(cvar.idati, -1, type_name, 0)

imports = []

# get import type and add used types in local types
# to ensure "correct" export
def imp_cb(ea, name, ord_nb):
    # Get type
    imp_t = tinfo_t()
    if get_tinfo2(ea, imp_t):
        if not imp_t.is_func():
            imports.append(print_type(ea, True) + ";")
        else:
            # Iterate over ret type and args
            for i in range(-1, imp_t.get_nargs()):
                arg_t = imp_t.get_nth_arg(i)
                if arg_t.is_ptr_or_array():
                    no_ptr = arg_t
                    no_ptr.remove_ptr_or_array()
                    import_name(str(no_ptr))

                import_name(str(arg_t))
            imports.append(print_type(ea, True) + " {}")
    return True

nimps = idaapi.get_import_module_qty()
for ordinal in xrange(0, nimps):
    idaapi.enum_import_names(ordinal, imp_cb)


# Types we have already inspected
seen = set()

# List of structures, to patch .h later
structs = set()


### parse type tinfo;
### adding unknown members to the local types as necessary
### return True if new types were added
def analyze_type(tinfo):
    #print "analyze_type : "+str(tinfo)
    has_new_type = False
    if str(tinfo) in seen:
        return False
    else:
        seen.add(str(tinfo))
        import_name(str(tinfo))
        has_new_type = True

    # Struct or union ? Walk members
    if tinfo.is_udt():
        # Hack to avoid problems with:
        # typedef struct _TOTO TOTO
        # IDA considers both _TOTO and TOTO as structs
        # this hack seems to fix it (maybe we could use
        # get_next_type_name)
        # print "---\t %s %s" % (tinfo.get_final_type_name(), str(tinfo))
        if tinfo.get_final_type_name() == str(tinfo):
            # print "adding to structs"
            structs.add(str(tinfo))

        u = udt_member_t()
        # struct members
        for idx in range(0, tinfo.get_udt_nmembers()):
            u.offset = idx
            tinfo.find_udt_member(STRMEM_INDEX, u)

            # print "member :"+str(u.type)
            has_new_type = analyze_type(u.type) or has_new_type # Recurse base type
            # AND also without pointer
            # to handle both shitty cases like :
            #   - PVOID (pointer but not to struct)
            #   - COMPLEX_STRUCT *
            if u.type.is_ptr_or_array():
                no_ptr = u.type
                no_ptr.remove_ptr_or_array()
                has_new_type = analyze_type(no_ptr) or has_new_type

    # Some types are "proxies" like typedef
    # but IDA doesn't seem to be offer a way to
    # differenciate them easily
    next_t = tinfo.get_next_type_name()
    if next_t is not None and next_t not in seen:
        # print "import next: "+next_t
        import_name(next_t)
        has_new_type = True

    return has_new_type

def add_types():
    local_type = tinfo_t()
    count = 0
    for ordinal in range(1, get_ordinal_qty(cvar.idati)):
        local_type.get_numbered_type(cvar.idati, ordinal)
        if analyze_type(local_type):
            count +=1
    return count


# Fix local types by iterating until all types are defined
while add_types() > 0:
    pass

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
        res = re.sub(re.compile(search, re.MULTILINE), r"\1struct %s" % s, res)

res += "\n\n"+"\n".join(imports)

fname = askfile_c(1, "*.h", "Save to header")
c = open(fname, "wt+")
c.write(res)
c.close()
