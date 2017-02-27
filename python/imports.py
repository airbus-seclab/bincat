import re
from idaapi import *
import idaapi


class NpkGen(object):

    def generate_npk(self):
        self.imports = []
        #: Types we have already inspected
        self.seen = set()
        #: List of structures, to patch .h later
        self.structs = set()

        # 1. get data from IDA, generate .c file
        nimps = idaapi.get_import_module_qty()
        for ordinal in range(0, nimps):
            idaapi.enum_import_names(ordinal, self.imp_cb)

        # Fix local types by iterating until all types are defined
        while self.add_types() > 0:
            pass

        sink = str_sink()
        idaapi.ida_typeinf.print_decls(
            sink, idaapi.ida_typeinf.cvar.idati, [],
            idaapi.PDF_INCL_DEPS | idaapi.PDF_DEF_FWD | idaapi.PDF_DEF_BASE)

        # Generate fixed .h
        res = sink.res()
        for s in self.structs:
            if "struct " not in s:
                search = r"(^\s*(?:typedef )?)\b%s\b" % s
                res = re.sub(
                    search, r"\1struct %s" % s, res, flags=re.MULTILINE)

        res += "\n\n"+"\n".join(self.imports)

        fname = idaapi.askfile_c(1, "*.h", "Save to header")
        c = open(fname, "wt+")
        c.write(res)
        c.close()

        # 2. use gcc to preprocess this file
        # 3. use c2newspeak to generate .npk

    # --- internal helpers

    def import_name(self, type_name):
        """
        helper do import a type by name into local types
        """
        # print "import_name : "+type_name
        idaapi.import_type(idaapi.cvar.idati, -1, type_name, 0)

    def imp_cb(self, ea, name, ord_nb):
        """
        get import type and add used types in local types to ensure "correct"
        export
        """
        # Get type
        imp_t = idaapi.tinfo_t()
        if idaapi.get_tinfo2(ea, imp_t):
            if not imp_t.is_func():
                self.imports.append(idaapi.print_type(ea, True) + ";")
            else:
                # Iterate over ret type and args
                for i in range(-1, imp_t.get_nargs()):
                    arg_t = imp_t.get_nth_arg(i)
                    if arg_t.is_ptr_or_array():
                        no_ptr = arg_t
                        no_ptr.remove_ptr_or_array()
                        self.import_name(str(no_ptr))

                    self.import_name(str(arg_t))
                self.imports.append(idaapi.print_type(ea, True) + " {}")
        return True

    def analyze_type(self, tinfo):
        """
        parse type tinfo;
        adding unknown members to the local types as necessary
        return True if new types were added
        """
        # print "analyze_type : "+str(tinfo)
        has_new_type = False
        if str(tinfo) in self.seen:
            return False
        else:
            self.seen.add(str(tinfo))
            self.import_name(str(tinfo))
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
                self.structs.add(str(tinfo))

            u = idaapi.udt_member_t()
            # struct members
            for idx in range(0, tinfo.get_udt_nmembers()):
                u.offset = idx
                tinfo.find_udt_member(idaapi.STRMEM_INDEX, u)

                # print "member :"+str(u.type)
                # Recurse base type
                has_new_type = self.analyze_type(u.type) or has_new_type
                # AND also without pointer
                # to handle both shitty cases like :
                #   - PVOID (pointer but not to struct)
                #   - COMPLEX_STRUCT *
                if u.type.is_ptr_or_array():
                    no_ptr = u.type
                    no_ptr.remove_ptr_or_array()
                    has_new_type = self.analyze_type(no_ptr) or has_new_type

        # Some types are "proxies" like typedef
        # but IDA doesn't seem to be offer a way to
        # differenciate them easily
        next_t = tinfo.get_next_type_name()
        if next_t is not None and next_t not in self.seen:
            # print "import next: "+next_t
            self.import_name(next_t)
            has_new_type = True

        return has_new_type

    def add_types(self):
        local_type = idaapi.tinfo_t()
        count = 0
        for ordinal in range(1, idaapi.get_ordinal_qty(idaapi.cvar.idati)):
            local_type.get_numbered_type(idaapi.cvar.idati, ordinal)
            if self.analyze_type(local_type):
                count += 1
        return count


class str_sink(idaapi.ida_typeinf.text_sink_t):
    """
    Sink to get .h in a string
    """
    def __init__(self):
        idaapi.ida_typeinf.text_sink_t.__init__(self)
        self.text = ""

    def _print(self, defstr):
        self.text += defstr
        return 0

    def res(self):
        return self.text


if __name__ == '__main__':
    NpkGen().generate_npk()
