ML=\
data-struct/register.ml\
utils/mapOpt.ml\
utils/bits.ml\
utils/config.ml\
utils/exceptions.ml\
utils/log.ml\
data-struct/data.ml\
frontend/lexer.ml\
frontend/parser.ml\
data-struct/asm.ml\
data-struct/code.ml\
domains/value.ml\
domains/tainting.ml\
domains/unrel.ml\
domains/vector.ml\
domains/pointer.ml\
domains/reduced_value_tainting.ml\
disassembly/cfa.ml\
disassembly/decoder.ml\
fixpoint/interpreter.ml\
main.ml

MLI=\
data-struct/register.mli\
utils/mapOpt.mli\
data-struct/data.mli\
domains/domain.mli\

LIBNAME=libbincat.so

LIBDIR ?= /usr/local/lib

CMX = $(ML:.ml=.cmx)
CMI = $(MLI:.mli=.cmi)

DIROPT = -I fixpoint -I +ocamlgraph -I `ocamlfind query zarith` -I domains -I data-struct -I utils -I disassembly -I frontend


CAMLC   =ocamlc $(DIROPT)
CAMLOPT =ocamlopt -w Ael -warn-error +a-7-50 $(DIROPT) 
CAMLLEX =ocamllex
MENHIR  =menhir --explain
CAMLDEP =ocamldep $(DIROPT)
CAMLDOC =ocamldoc $(DIROPT)

LIBX=unix.cmxa graph.cmxa nums.cmxa zarith.cmxa
CFLAGS=-ccopt -dynamiclib -ccopt -L/usr/local/lib/ocaml -ccopt -lasmrun
all: $(LIBNAME)

$(LIBNAME): $(CMX) 
	$(CAMLOPT) $(CFLAGS) -o $(LIBNAME) $(LIBX) $(OCAMLOPT) $+


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

install: $(LIBNAME)
	install -b $(LIBNAME) $(LIBDIR)

.depend: $(ML) $(MLI)
	rm -f .depend
	-$(CAMLDEP) -native $+ > .depend

doc: $(ML) $(MLI)
	@mkdir -p $(DOCPATH)/html
	@mkdir -p $(DOCPATH)/latex
	@$(CAMLDOC) -html $^ -d $(DOCPATH)/html $(DIROPT) 
	@$(CAMLDOC) -latex $^ -d $(DOCPATH)/latex $(DIROPT)

.PHONY: depend all clean install

include .depend

