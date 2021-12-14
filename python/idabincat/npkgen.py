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
# This file can be also used as an IDA script.
import re
import tempfile
import os.path
import logging
import subprocess
try:
    import idaapi
    from ida_typeinf import PRTYPE_1LINE
except ImportError:
    # imported outside ida - for instance, from wsgi.py
    pass

npk_log = logging.getLogger('bincat.plugin.npkgen')
npk_log.setLevel(logging.INFO)


class NpkGenException(Exception):
    pass


class NpkGen(object):

    def get_header_data(self):

        self.imports = []
        #: Types we have already inspected
        self.seen = set()
        #: List of structures, to patch .h later
        self.structs = set()
        # add missing #defines

        self.imports.append("#define __cdecl")

        nimps = idaapi.get_import_module_qty()
        for ordinal in range(0, nimps):
            idaapi.enum_import_names(ordinal, self.imp_cb)

        # Fix local types by iterating until all types are defined
        while self.add_types() > 0:
            pass

        class str_sink(idaapi.text_sink_t):
            """
            Sink to get .h in a string
            """
            def __init__(self):
                idaapi.text_sink_t.__init__(self)
                self.text = ""

            def _print(self, defstr):
                self.text += defstr
                return 0

            def res(self):
                return self.text
        sink = str_sink()
        idaapi.print_decls(
            sink, idaapi.cvar.idati, [],
            idaapi.PDF_INCL_DEPS | idaapi.PDF_DEF_FWD | idaapi.PDF_DEF_BASE)

        # Generate fixed .h
        res = sink.res()
        for s in self.structs:
            if "struct " not in s:
                search = r"(^\s*(?:typedef )?)\s*%s\s" % re.escape(s)
                res = re.sub(search, r"\1struct %s " % s, res, flags=re.MULTILINE)
        res += "\n\n"+"\n".join(self.imports)
        res = re.sub(r"__attribute__.*? ", " ", res)
        res = re.sub("__fastcall", "", res)

        res = res.replace("$", "D_")
        res = res.replace("::", "__")

        return res

    def generate_tnpk(self, imports_data="", destfname=None):
        # required: c2newspeak requires a file, checks its extension
        dirname = tempfile.mkdtemp('bincat-generate-header')
        npk_log.info("Generating TNPK file in %s", dirname)
        cwd = os.getcwd()
        os.chdir(dirname)

        # 1. get imports_data
        if not imports_data:
            # not provided, fetch from IDA
            imports_data = self.get_header_data()

        ig_name = os.path.join(dirname, "ida-generated.h")
        c = open(ig_name, "w+")
        c.write(imports_data)
        c.close()
        npk_log.info("Calling 'gcc -P -E %s'", ig_name)
        # 2. use gcc to preprocess this file
        try:
            out = subprocess.check_output(
                ["gcc", "-P", "-E", ig_name], stderr=subprocess.STDOUT)
        except OSError as e:
            error_msg = ("Error encountered while running gcc. "
                         "Is it installed in PATH?")
            # Display traceback only if not "no such file"
            if e.errno != 2:
                npk_log.error(error_msg, exc_info=True)
            else:
                npk_log.error(error_msg, exc_info=False)
            raise NpkGenException(error_msg) from e
        except Exception as e:
            error_msg = "Error encountered while running gcc."
            npk_log.error(error_msg, exc_info=True)
            raise NpkGenException(error_msg) from e
        pp_name = os.path.join(dirname, "pre-processed.c")
        npk_log.info("Parsing '%s'" % pp_name)
        with open(pp_name, "wb") as f:
            f.write(out)
        # 3. use c2newspeak to generate .no
        if destfname is None:
            destfname = os.path.join(dirname, "pre-processed.no")
        try:
            out = subprocess.check_output(
                ["c2newspeak", "--typed-npk", "-o", destfname,
                 "pre-processed.c"], stderr=subprocess.STDOUT)
            if out:
                npk_log.debug(out)
        except OSError as e:
            error_msg = ("Error encountered while running c2newspeak. "
                         "Is it installed in PATH?")
            npk_log.error(error_msg, exc_info=True)
            raise NpkGenException(error_msg) from e
        except subprocess.CalledProcessError as e:
            error_msg = ""
            if e.output:
                error_msg += "\n--- start of c2newspeak output ---\n"
                error_msg += str(e.output)
                error_msg += "\n--- end of c2newspeak output ---"
            # Don't show exception if c2newspeak returns 1 (parse error)
            if e.returncode != 1:
                npk_log.error("Error encountered while running c2newspeak.\n"+error_msg, exc_info=True)
            else:
                npk_log.info("Parse error in c2newspeak:\n"+error_msg)
            raise NpkGenException(error_msg) from e
        # output is in destfname
        os.chdir(cwd)
        npk_log.debug("TNPK file has been successfully generated.")
        return destfname

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
        if idaapi.get_tinfo(imp_t, ea):
            if not imp_t.is_func():
                self.imports.append(idaapi.print_type(ea, PRTYPE_1LINE) + ";")
            else:
                # Iterate over ret type and args
                for i in range(-1, imp_t.get_nargs()):
                    arg_t = imp_t.get_nth_arg(i)
                    if arg_t.is_ptr_or_array():
                        no_ptr = arg_t
                        no_ptr.remove_ptr_or_array()
                        self.import_name(str(no_ptr))

                    self.import_name(str(arg_t))
                self.imports.append(idaapi.print_type(ea, PRTYPE_1LINE) + " {}")
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
                tinfo.find_udt_member(u, idaapi.STRMEM_INDEX)

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


if __name__ == '__main__':
    NpkGen().generate_tnpk()
