GITVERSION:=$(shell git describe --dirty)

LIBDIR=$(DESTDIR)/$(PREFIX)/lib/
BINDIR=$(DESTDIR)/$(PREFIX)/bin/

CAMLC   ?=ocamlc
CAMLOPT ?=ocamlopt
CAMLLEX ?=ocamllex
MENHIR  =menhir --explain
CAMLDEP ?=ocamldep
CAMLDOC ?=ocamldoc
CAMLFIND ?=ocamlfind

CPPO_VER=-V OCAML:$(shell $(CAMLC) -vnum)
CPPO="cppo $(CPPO_VER)"
CAMLLIBDIR:=$(shell $(CAMLC) -where)


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
  loaders/elf_coredump.ml\
  disassembly/decodeutils.ml\
  fixpoint/stubs.ml\
  fixpoint/rules.ml\
  disassembly/x86Imports.ml\
  disassembly/x64Imports.ml\
  disassembly/armv7Imports.ml\
  disassembly/armv8aImports.ml\
  disassembly/powerpcImports.ml\
  disassembly/riscVImports.ml\
  frontend/lexer.ml\
  frontend/parser.ml\
  domains/env.ml\
  domains/typenv.ml\
  domains/bit.ml\
  domains/unrel.ml\
  domains/vector.ml\
  domains/pointer.ml\
  domains/unrels.ml\
  domains/reduced_bit_tainting.ml\
  domains/abstract_heap.ml\
  domains/reduced_unrel_typenv_heap.ml\
  disassembly/cfa.ml\
  disassembly/core_x86.ml\
  disassembly/armv7.ml\
  disassembly/armv8A.ml\
  disassembly/powerpc.ml\
  disassembly/risc_v.ml\
  fixpoint/forward.ml\
  fixpoint/backward.ml\
  fixpoint/interpreter.ml\
  bincat_ver.ml\
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



DEPS-armv8A := armv8A_ppx
OPTS-armv8A :=  -ppx ./armv8A_ppx -warn-error -26-27
OPTS-elf_core := -w -44
OPTS-elf := -w -44
DEPS-config := npk/c2newspeak/typedC.cmi
OPTS-config := -I npk/c2newspeak
DEPS-types := npk/c2newspeak/typedC.cmi
OPTS-types := -I npk/c2newspeak
DEPS-rules := npk/c2newspeak/typedC.cmi
OPTS-rules := -I npk/c2newspeak
DEPS-parser := npk/c2newspeak/typedC.cmi
OPTS-parser := -I npk/c2newspeak
DEPS-core_x86 := npk/c2newspeak/typedC.cmi npk/newspeak/newspeak.cmi
OPTS-core_x86 := -I npk/c2newspeak -I npk/newspeak
DEPS-reduced_unrel_typenv_heap := npk/c2newspeak/typedC.cmi npk/newspeak/newspeak.cmi
OPTS-reduced_unrel_typenv_heap := -I npk/c2newspeak -I npk/newspeak


EXTLIB := str unix graph zarith bigarray
PACKAGES := ocamlgraph zarith

EXTLIBINCL := $(foreach P,$(PACKAGES), -I $(shell $(CAMLFIND) query $(P)))
LIBINCL = $(EXTLIBINCL) -I data-struct -I domains -I utils -I disassembly -I frontend -I loaders -I fixpoint

#  W58: no cmx file was found in path for module Z
#  -> not really a problem.
#  W42: use of XXX relies on type-directed disambiguation
#  -> not really a pb

CAMLOPTIONS = -g -w A-e-l -warn-error +a-3-7-50-42-44-58 -w -42 -w -58 -w -67 -w -70

EXEOPT=bincat
EXEBYTE=bincat.byte

ifeq ($(BYTECODE), 1)
    CAMLCOMPIL = $(CAMLC)
    OBJ = $(ML:.ml=.cmo)
    NPKLIB:=npk/newspeak.cma
    EXTLIB:=$(EXTLIB:=.cma)
    EXENAME=$(EXEBYTE)
    BINCATOBJ = bincat.cmo
    CAMLDEPOPT = 
else
    CAMLCOMPIL = $(CAMLOPT)
    OBJ = $(ML:.ml=.cmx)
    NPKLIB:=npk/newspeak.cmxa
    EXTLIB:=$(EXTLIB:=.cmxa)
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

CFLAGS=-ccopt -lasmrun

ifeq ($(STATIC), 1)
all: $(LIBNAME) static
else
all: $(LIBNAME) $(EXENAME)
endif

armv8A_ppx: disassembly/armv8A_ppx.ml
	$(CAMLOPT) -pp $(CPPO) -warn-error -33-9-17 -I `$(CAMLFIND) query ppx_tools` -I +compiler-libs -o armv8A_ppx  str.cmxa ocamlcommon.cmxa ppx_tools.cmxa $+

$(LIBNAME): $(NPKLIB) $(OBJ)
	rm -f $(BINCATOBJ)
	$(CAMLCOMPIL) $(SHARED) $(CFLAGS) $(EXTLIBINCL) $(EXTLIB) $+ -o $@

$(EXENAME): $(NPKLIB) $(OBJ) $(BINCATOBJ)
	$(CAMLCOMPIL) $(CFLAGS) $(EXTLIBINCL) $(EXTLIB) $+ -o $@

# Build $(EXENAME) statically
static: CFLAGS+=-ccopt -static
static: $(EXENAME)
	strip $(EXENAME)

bincat_ver.ml: update_gitver
	[ -f $@ ] || touch $@
	grep -q $(GITVERSION) bincat_ver.ml || sed s/XXX/$(GITVERSION)/ bincat_ver.ml.tmpl > $@


# dependencies on newspeak
$(NPKLIB):
	$(MAKE) -C npk/ BYTECODE=$(BYTECODE)

npk/c2newspeak/typedC.cmi:
	$(MAKE) -C npk/ BYTECODE=$(BYTECODE)

npk/newspeak/newspeak.cmi:
	$(MAKE) -C npk/ BYTECODE=$(BYTECODE)



.SECONDEXPANSION:

%.cmi: %.mli $$(DEPS-$$(*F))
	$(CAMLCOMPIL) $(CAMLOPTIONS) $(LIBINCL) $(OPTS-$(*F)) -c $*.mli

%.cmx: %.ml $$(DEPS-$$(*F))
	$(CAMLOPT) -pp $(CPPO) $(CAMLOPTIONS) $(LIBINCL) $(OPTS-$(*F)) -c $*.ml

%.cmo: %.ml $$(DEPS-$$(*F))
	$(CAMLC) $(CAMLOPTIONS) $(LIBINCL) $(OPTS-$(*F)) -c $*.ml

%.ml: %.mll
	$(CAMLLEX) $*.mll

%.ml %.mli: %.mly
	$(MENHIR) $*.mly

clean:
	-$(MAKE) -C npk clean
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
	$(MAKE) -C npk/ install
	install $(LIBNAME) $(LIBDIR)
	install $(EXENAME) $(BINDIR)
	$(LDCONFIG) $(LIBDIR)

.depend: $(ML) $(MLI)
	rm -f .depend
	-$(CAMLDEP) -pp $(CPPO) $(LIBINCL) -slash $(CAMLDEPOPT) $+ > .depend

doc: $(ML) $(MLI)
	@mkdir -p $(DOCPATH)/html
	@mkdir -p $(DOCPATH)/latex
	@$(CAMLDOC) -html $^ -d $(DOCPATH)/html $(DIROPT) 
	@$(CAMLDOC) -latex $^ -d $(DOCPATH)/latex $(DIROPT)

.PHONY: depend all clean install update_gitver

include .depend
