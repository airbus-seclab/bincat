GITVERSION:=$(shell git describe --dirty)

LIBDIR=$(DESTDIR)/$(PREFIX)/lib/
BINDIR=$(DESTDIR)/$(PREFIX)/bin/

CPPO_VER=-V OCAML:$(shell ocamlc -vnum)
CPPO="cppo $(CPPO_VER)"
CAMLLIBDIR:=$(shell ocamlc -where)


ML=\
utils/exceptions.ml\
utils/misc.ml\
data-struct/register.ml\
utils/mapOpt.ml\
utils/setExt.ml\
utils/bits.ml\
data-struct/taint.ml\
utils/config.ml\
data-struct/data.ml\
utils/log.ml\
frontend/init_check.ml\
data-struct/types.ml\
data-struct/asm.ml\
utils/dump.ml\
data-struct/mapped_mem.ml\
loaders/manual.ml\
loaders/raw.ml\
loaders/elf_core.ml\
loaders/elf.ml\
disassembly/decodeutils.ml\
fixpoint/stubs.ml\
fixpoint/rules.ml\
disassembly/x86Imports.ml\
disassembly/armv7Imports.ml\
disassembly/armv8aImports.ml\
frontend/lexer.ml\
frontend/parser.ml\
domains/env.ml\
domains/typenv.ml\
domains/bit.ml\
domains/unrel.ml\
domains/vector.ml\
domains/pointer.ml\
domains/reduced_bit_tainting.ml\
domains/reduced_unrel_typenv.ml\
disassembly/cfa.ml\
disassembly/x86.ml\
disassembly/armv7.ml\
disassembly/armv8A.ml\
fixpoint/interpreter.ml\
bincat_ver.ml \
main.ml

MLI=\
data-struct/register.mli\
utils/mapOpt.mli\
utils/setExt.mli\
data-struct/data.mli\
loaders/loader.mli\
domains/domain.mli\
disassembly/cfa.mli\
disassembly/decoder.mli\
fixpoint/stubs.mli


DEPS-armv8A := armv8A_ppx
OPTS-armv8A := -ppx ./armv8A_ppx

# Suppress "this open statement shadows the value ..."
# as it is legitimately done
OPTS-elf_core := -w -44


CMX = $(ML:.ml=.cmx)

DIROPT = -I `ocamlfind query newspeak` -I fixpoint -I `ocamlfind query ocamlgraph` -I `ocamlfind query zarith` -I data-struct -I domains -I utils -I disassembly -I frontend -I loaders

#  W58: no cmx file was found in path for module Z
#  not really a problem.
CAMLOPTIONS = -g -w Ael -warn-error +a-3-7-50-42-44-58 -w -58 $(DIROPT)

CAMLC   =ocamlc $(DIROPT)
CAMLOPT =ocamlopt
CAMLLEX =ocamllex
MENHIR  =menhir --explain
CAMLDEP =ocamldep $(DIROPT)
CAMLDOC =ocamldoc $(DIROPT)

EXEOPT=bincat
EXEBYTE=bincat.byte

ifeq ($(BYTECODE), 1)
CAMLCOMPIL = $(CAMLC) $(CAMLOPTIONS)
OBJ = $(ML:.ml=.cmo)
LIBX:=unix.cma graph.cma zarith.cma newspeak.cma bigarray.cma newspeak.cma
EXENAME=$(EXEBYTE)
BINCATOBJ = bincat.cmo
CAMLDEPOPT = 
else
CAMLCOMPIL = $(CAMLOPT) $(CAMLOPTIONS)
OBJ = $(ML:.ml=.cmx)
LIBX:=unix.cmxa graph.cmxa nums.cmxa str.cmxa zarith.cmxa newspeak.cmxa bigarray.cmxa newspeak.cmxa
EXENAME=$(EXEOPT)
BINCATOBJ = bincat.cmx
CAMLDEPOPT = -native
endif


ifeq ($(OS),Windows_NT)
    detected_OS := Windows
else
    detected_OS := $(shell uname)
endif

ifeq ($(detected_OS), Windows)
    shared=-ccopt -dynamiclib
    ldconfig=true
    LIBNAME=libbincat.dll
endif
ifeq ($(detected_OS), Darwin)
    LIBNAME=libbincat.so
    SHARED=-ccopt -dynamiclib
    LDCONFIG=true
endif
ifeq ($(detected_OS), Linux)
    LIBNAME=libbincat.so
    SHARED=-output-obj -runtime-variant _pic
    LDCONFIG=ldconfig
endif

CFLAGS=-ccopt -L$(CAMLLIBDIR) -ccopt -L`ocamlfind query newspeak` -ccopt -lasmrun

ifeq ($(STATIC), 1)
all: $(LIBNAME) static
else
all: $(LIBNAME) $(EXENAME)
endif

armv8A_ppx: disassembly/armv8A_ppx.ml
	$(CAMLOPT) -pp $(CPPO) -warn-error -33-9-17 -I `ocamlfind query ppx_tools` -I `ocamlfind query compiler-libs` -o armv8A_ppx  str.cmxa ocamlcommon.cmxa ppx_tools.cmxa $+

$(LIBNAME): $(OBJ) 
	rm -f $(BINCATOBJ)
	$(CAMLCOMPIL) $(SHARED) $(CFLAGS) -o $(LIBNAME) $(LIBX) $(OCAMLOPT) $+

$(EXENAME): $(OBJ) $(BINCATOBJ)
	$(CAMLCOMPIL)  $(CFLAGS) -o $@ $(LIBX) $(OCAMLOPT) $+

# Build $(EXENAME) statically
static: CFLAGS+=-ccopt -static
static: $(EXENAME)
	strip $(EXENAME)

bincat_ver.ml: update_gitver
	[ -f $@ ] || touch $@
	grep -q $(GITVERSION) bincat_ver.ml || sed s/XXX/$(GITVERSION)/ bincat_ver.ml.tmpl > $@


.SECONDEXPANSION:

%.cmx: %.ml %.mli $$(DEPS-$$(*F))
	$(CAMLCOMPIL) -c $(LIBX) $(OPTS-$(*F)) $*.ml

%.cmi: %.mli $$(DEPS-$$(*F))
	$(CAMLCOMPIL) -c $(OPTS-$(*F)) $*.mli

%.cmx: %.ml $$(DEPS-$$(*F))
	$(CAMLCOMPIL) -c $(LIBX) $(OPTS-$(*F)) $*.ml

%.cmo: %.ml $$(DEPS-$$(*F))
	$(CAMLCOMPIL) -c $(LIBX) $(OPTS-$(*F)) $*.ml

%.ml: %.mll
	$(CAMLLEX) $*.mll

%.ml %.mli: %.mly
	$(MENHIR) $*.mly

clean:
	-rm -f .depend
	-rm -f `find . -name "*.cm[ixo]"`
	-rm -f `find . -name  "*.o"`
	-rm -f `find . -name "*~"`
	-rm -f ocamldoc.sty ocamldoc.out
	-rm -f disassembly/*.so
	-rm -f $(LIBNAME) $(EXEBYTE) $(EXEOPT)
	-rm -f armv8A_ppx
	-rm -f frontend/lexer.ml frontend/lexer.mli frontend/parser.ml frontend/parser.mli frontend/*.conflicts frontend/*.automaton
	# Files moved in revision 2097c09e19f8
	-rm -f parser.ml parser.mli lexer.ml

install: $(LIBNAME) $(EXENAME)
	install $(LIBNAME) $(LIBDIR)
	install $(EXENAME) $(BINDIR)
	$(LDCONFIG) $(LIBDIR)

.depend: $(ML) $(MLI)
	rm -f .depend
	-$(CAMLDEP) -slash $(CAMLDEPOPT) $+ > .depend

doc: $(ML) $(MLI)
	@mkdir -p $(DOCPATH)/html
	@mkdir -p $(DOCPATH)/latex
	@$(CAMLDOC) -html $^ -d $(DOCPATH)/html $(DIROPT) 
	@$(CAMLDOC) -latex $^ -d $(DOCPATH)/latex $(DIROPT)

.PHONY: depend all clean install update_gitver

include .depend
