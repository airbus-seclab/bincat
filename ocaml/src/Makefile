GITVERSION:=$(shell git describe)

ML=\
data-struct/register.ml\
utils/mapOpt.ml\
utils/bits.ml\
utils/config.ml\
utils/exceptions.ml\
data-struct/data.ml\
utils/log.ml\
data-struct/types.ml\
data-struct/asm.ml\
data-struct/imports.ml\
frontend/lexer.ml\
frontend/parser.ml\
data-struct/code.ml\
domains/symbexp.ml\
domains/env.ml\
domains/typenv.ml\
domains/bit.ml\
domains/tainting.ml\
domains/unrel.ml\
domains/vector.ml\
domains/pointer.ml\
domains/reduced_bit_tainting.ml\
domains/reduced_unrel_typenv.ml\
disassembly/cfa.ml\
disassembly/decoder.ml\
fixpoint/stubs.ml\
fixpoint/interpreter.ml\
bincat_ver.ml \
main.ml

MLI=\
data-struct/register.mli\
utils/mapOpt.mli\
data-struct/data.mli\
domains/domain.mli\
fixpoint/stubs.mli\

LIBDIR=$(DESTDIR)/$(PREFIX)/lib/
BINDIR=$(DESTDIR)/$(PREFIX)/bin/

CAMLLIBDIR:=$(shell ocamlc -where)

CMX = $(ML:.ml=.cmx)
CMI = $(MLI:.mli=.cmi)

DIROPT = -I `ocamlfind query newspeak` -I fixpoint -I `ocamlfind query ocamlgraph` -I `ocamlfind query zarith` -I domains -I data-struct -I utils -I disassembly -I frontend


CAMLC   =ocamlc $(DIROPT)
CAMLOPT =ocamlopt -g -w Ael -warn-error +a-7-3-52-50-42 $(DIROPT)
CAMLLEX =ocamllex
MENHIR  =menhir --explain
CAMLDEP =ocamldep $(DIROPT)
CAMLDOC =ocamldoc $(DIROPT)

LIBX=unix.cmxa graph.cmxa nums.cmxa str.cmxa zarith.cmxa newspeak.cmxa bigarray.cmxa typedC.cmx

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
all: $(LIBNAME) bincat_native

$(LIBNAME): $(CMX) 
	rm -f bincat_native.cmx
	$(CAMLOPT) $(SHARED) $(CFLAGS) -o $(LIBNAME) $(LIBX) $(OCAMLOPT) $+

bincat_native: $(CMX) bincat_native.cmx
	$(CAMLOPT)  $(CFLAGS) -o bincat_native $(LIBX) $(OCAMLOPT) $+

bincat_ver.ml: update_gitver
	[ -f $@ ] || touch $@
	grep -q $(GITVERSION) bincat_ver.ml || sed s/XXX/$(GITVERSION)/ bincat_ver.ml.tmpl > $@

%.cmx: %.ml %.mli
	$(CAMLOPT) -c $(LIBX) $*.ml

%.cmi: %.mli
	$(CAMLOPT) -c $*.mli

%.cmx: %.ml
	$(CAMLOPT) -c $(LIBX) $*.ml

%.ml: %.mll
	$(CAMLLEX) $*.mll

%.ml %.mli: %.mly
	$(MENHIR) $*.mly


clean:
	-rm -f .depend
	-rm -f `find . -name "*.cm[ix]"`
	-rm -f `find . -name  "*.o"`
	-rm -f `find . -name "*~"`
	-rm -f ocamldoc.sty ocamldoc.out
	-rm -f disassembly/*.so
	-rm -f $(LIBNAME)
	-rm -f frontend/lexer.ml frontend/lexer.mli frontend/parser.ml frontend/parser.mli frontend/*.conflicts frontend/*.automaton
	# Files moved in revision 2097c09e19f8
	-rm -f parser.ml parser.mli lexer.ml

install: $(LIBNAME) bincat_native
	install $(LIBNAME) $(LIBDIR)
	install bincat_native $(BINDIR)
	$(LDCONFIG) $(LIBDIR)

.depend: $(ML) $(MLI)
	rm -f .depend
	-$(CAMLDEP) -slash -native $+ > .depend

doc: $(ML) $(MLI)
	@mkdir -p $(DOCPATH)/html
	@mkdir -p $(DOCPATH)/latex
	@$(CAMLDOC) -html $^ -d $(DOCPATH)/html $(DIROPT) 
	@$(CAMLDOC) -latex $^ -d $(DOCPATH)/latex $(DIROPT)

.PHONY: depend all clean install update_gitver

include .depend
