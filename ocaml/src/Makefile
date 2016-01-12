ML=\
data-struct/register.ml\
utils/mapOpt.ml\
utils/bits.ml\
utils/config.ml\
data-struct/data.ml\
lexer.ml\
parser.ml\
data-struct/asm.ml\
utils/utils.ml\
data-struct/code.ml\
fixpoint/alarm.ml\
domains/unrel.ml\
domains/ptr.ml\
domains/pair.ml\
domains/tainting.ml\
disassembly/cfa.ml\
disassembly/decoder.ml\
fixpoint/interpreter.ml\
main.ml

MLI=\
data-struct/register.mli\
utils/mapOpt.mli\
domains/domain.mli\
fixpoint/alarm.mli\

LIBNAME=libbincat.so

LIBDIR ?= /usr/local/lib

CMX = $(ML:.ml=.cmx)

DIROPT = -I fixpoint -I +ocamlgraph -I `ocamlfind query zarith` -I domains -I data-struct -I utils -I disassembly

CAMLC   =ocamlc $(DIROPT)
CAMLOPT =ocamlopt -w Ael -warn-error +a-7-50 $(DIROPT) 
CAMLLEX =ocamllex
MENHIR  =menhir --explain
CAMLDEP =ocamldep $(DIROPT)
CAMLDOC =ocamldoc $(DIROPT)

LIBX=graph.cmxa nums.cmxa zarith.cmxa

all: $(LIBNAME)

$(LIBNAME): $(CMX) 
	$(CAMLOPT) -output-obj -fPIC -o $(LIBNAME) $(LIBX) $+


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
	-rm -f lexer.ml lexer.mli parser.ml parser.mli *.conflicts *.automaton

install: $(LIBNAME)
	cp $(LIBNAME) $(LIBDIR)

.depend: $(ML) $(MLI)
	rm -f .depend
	-$(CAMLDEP) -native $+ > .depend

doc: 
	@mkdir -p $(DOCPATH)/html
	@mkdir -p $(DOCPATH)/latex
	@$(CAMLDOC) -html $^ -d $(DOCPATH)/html $(DIROPT) $(SRC)
	@$(CAMLDOC) -latex $^ -d $(DOCPATH)/latex

.PHONY: depend all clean install

include .depend

