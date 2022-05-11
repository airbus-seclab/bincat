SHELL=/bin/bash
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
  version.ml\
  utils/standardApplication.ml\
  utils/listUtils.ml\
  utils/strSet.ml\
  newspeak/conf.ml\
  newspeak/temps.ml\
  newspeak/newspeak.ml\
  newspeak/npkcontext.ml\
  newspeak/lowspeak.ml\
  newspeak/npkil.ml\
  newspeak/abilexer.ml\
  newspeak/npk2lpk.ml\
  newspeak/linker.ml\
  newspeak/cir.ml\
  newspeak/cir2npkil.ml\
  newspeak/abiparser.ml\
  newspeak/x2newspeak.ml\
  c2newspeak/typedC.ml\
  c2newspeak/gnuc.ml\
  c2newspeak/bareSyntax.ml\
  c2newspeak/csyntax.ml\
  c2newspeak/gotoElimination.ml\
  c2newspeak/typedC2Cir.ml\
  c2newspeak/synthack.ml\
  c2newspeak/bare2C.ml\
  c2newspeak/csyntax2TypedC.ml\
  c2newspeak/preprocess.ml\
  c2newspeak/npkParser.ml\
  c2newspeak/pp_parser.ml\
  c2newspeak/pp_lexer.ml\
  c2newspeak/npkLexer.ml\
  c2newspeak/compiler.ml\
  c2newspeak/pp_syntax.ml\
  c2newspeak/params.ml

MLI=\
  utils/standardApplication.mli\
  utils/strSet.mli\
  utils/listUtils.mli\
  c2newspeak/npkParser.mli\
  c2newspeak/synthack.mli\
  c2newspeak/bare2C.mli\
  c2newspeak/csyntax.mli\
  c2newspeak/params.mli\
  c2newspeak/bareSyntax.mli\
  c2newspeak/pp_parser.mli\
  c2newspeak/compiler.mli\
  c2newspeak/gnuc.mli\
  c2newspeak/typedC.mli\
  c2newspeak/gotoElimination.mli\
  c2newspeak/csyntax2TypedC.mli\
  c2newspeak/typedC2Cir.mli\
  c2newspeak/pp_syntax.mli\
  newspeak/npkcontext.mli\
  newspeak/cir2npkil.mli\
  newspeak/temps.mli\
  newspeak/newspeak.mli\
  newspeak/conf.mli\
  newspeak/lowspeak.mli\
  newspeak/x2newspeak.mli\
  newspeak/npkil.mli\
  newspeak/linker.mli\
  newspeak/npk2lpk.mli\
  newspeak/cir.mli\
  newspeak/abiparser.mli\
  version.mli

OPTS-newspeak := -w -7
OPTS-lowspeak := -w -7
OPTS-npk2lpk := -w -7

EXTLIB := str unix graph zarith bigarray
PACKAGES := ocamlgraph zarith

EXTLIBINCL := $(foreach P,$(PACKAGES), -I $(shell $(CAMLFIND) query $(P)))
LIBINCL = $(EXTLIBINCL) -I utils -I newspeak -I c2newspeak


CAMLOPTIONS = -g -w A-e-l -warn-error +a-3-7-50-42-44-58-26 -w -70



ifeq ($(BYTECODE), 1)
    CAMLCOMPIL = $(CAMLC)
    OBJ = $(ML:.ml=.cmo)
    EXTLIB:=$(EXTLIB:=.cma)
    EXENAME=c2newspeak.byte
    LIBNAME=newspeak.cma
    CAMLDEPOPT =
    C2NPKOBJ=c2newspeak/c2newspeak.cmo
else
    CAMLCOMPIL = $(CAMLOPT)
    OBJ = $(ML:.ml=.cmx)
    EXTLIB:=$(EXTLIB:=.cmxa)
    EXENAME=c2newspeak.opt
    LIBNAME=newspeak.cmxa
    CAMLDEPOPT = -native
    C2NPKOBJ=c2newspeak/c2newspeak.cmx
endif


CFLAGS=

ifeq ($(STATIC), 1)
all: $(LIBNAME) static
else
all: $(LIBNAME) $(EXENAME)
endif


$(LIBNAME): $(OBJ)
	$(CAMLCOMPIL) $(CFLAGS) $(EXTLIBINCL) $+ -a -o $@

$(EXENAME): $(LIBNAME) $(C2NPKOBJ)
	$(CAMLCOMPIL) $(CFLAGS) $(EXTLIBINCL) $(EXTLIB) $+ -o $@

# Build $(EXENAME) statically
static: CFLAGS+=-ccopt -static
static: $(EXENAME)
	strip $(EXENAME)

.SECONDEXPANSION:

%.cmi: %.mli $$(DEPS-$$(*F))
	$(CAMLCOMPIL) $(CAMLOPTIONS) $(LIBINCL) $(OPTS-$(*F)) -c $*.mli

%.cmx: %.ml $$(DEPS-$$(*F))
	$(CAMLOPT) $(CAMLOPTIONS) $(LIBINCL) $(OPTS-$(*F)) -c $*.ml

%.cmo: %.ml $$(DEPS-$$(*F))
	$(CAMLC) $(CAMLOPTIONS) $(LIBINCL) $(OPTS-$(*F)) -c $*.ml


%.ml: %.mll
	$(CAMLLEX) $*.mll

%.ml %.mli: %.mly
	$(MENHIR) $*.mly


clean:
	rm -f .depend
	rm -f `find . -name "*.cm[ixo]"`
	rm -f `find . -name  "*.o"`
	rm -f `find . -name "*~"`
	rm -f ocamldoc.sty ocamldoc.out
	rm -f disassembly/*.so
	rm -f newspeak.{a,cma,cmxa} c2newspeak.{opt,byte}
	rm -f armv8A_ppx
	rm -f c2newspeak/{pp_,abi}{lexer,parser}.{ml,mli,output,conflicts}
	rm -f c2newspeak/npk{Lexer,Parser}.{ml,mli,output,conflicts}
	rm -f newspeak/{,abi}{lexer,parser}.{ml,mli,output,conflicts}



install: $(EXENAME)
	install $(EXENAME) $(BINDIR)/c2newspeak

.depend: $(ML) $(MLI)
	rm -f .depend
	-$(CAMLDEP) $(LIBINCL) -slash $(CAMLDEPOPT) $+ > .depend

.PHONY: depend all clean install

include .depend
