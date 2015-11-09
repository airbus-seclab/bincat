SRC=data-struct/data.mli data-struct/register.mli data-struct/register.ml\
	utils/mapOpt.mli utils/mapOpt.ml\
	utils/context.mli utils/context.ml\
	data-struct/asm.mli data-struct/asm.ml\
	utils/utils.ml utils/utils.mli\
	data-struct/code.mli data-struct/code.ml\
	domains/domain.mli\
	fixpoint/alarm.mli fixpoint/alarm.ml\
	domains/unrel.mli domains/unrel.ml domains/ptr.mli domains/ptr.ml\
	disassembly/abi.mli disassembly/abi.ml\
	domains/pair.mli domains/pair.ml\
	domains/tainting.mli domains/tainting.ml\
	disassembly/cfa.mli disassembly/cfa.ml\
	disassembly/decoder.mli disassembly/decoder.ml\
	fixpoint/fixpoint.mli fixpoint/fixpoint.ml\
	parser.mly lexer.mll\
	main.mli main.ml

LIBNAME=libbincat.so

LIBDIR ?= /usr/local/lib



SRC1 = $(SRC:.mly=.ml)
SRC2 = $(SRC1:.mll=.ml)
OBJS1 = $(SRC2:.ml=.cmx)
OBJS=$(filter-out %.mli, $(OBJS1))


DIROPT = -I fixpoint -I +ocamlgraph -I domains -I data-struct -I utils -I disassembly

CAMLC   =ocamlc $(DIROPT)
CAMLOPT =ocamlopt -w Ael -warn-error +a-7-50 $(DIROPT) 
CAMLLEX =ocamllex
MENHIR=menhir
CAMLDEP =ocamldep $(DIROPT)
CAMLDOC =ocamldoc $(DIROPT)

LIBX=graph.cmxa nums.cmxa

all: $(LIBNAME)

$(LIBNAME): $(OBJS1) 
	$(CAMLOPT) -output-obj -fPIC -o $(LIBNAME) $(LIBX) $(OBJS)


.SUFFIXES:
.SUFFIXES: .ml .mli .cmo .cmi .cmx .mll .mly

.ml.cmo:
	$(CAMLC) -c $<

.mli.cmi:
	$(CAMLC) -c $<

.ml.o:
	$(CAMLOPT) -c $<

.ml.cmx:
	$(CAMLOPT) -c $<

.mll.cmx:
	$(CAMLLEX) $<
	$(CAMLOPT) -c $*.ml

.mly.cmx:
	$(MENHIR) --dump $<
	$(CAMLOPT) -c $*.mli
	$(CAMLOPT) -c $*.ml

.mly.cmi:
	$(MENHIR) --explain $<
	$(CAMLC) -c $*.mli

.mll.ml:
	$(CAMLLEX) $<

.mly.ml:
	$(MENHIR) --dump $<

clean:
	-rm -f .depend
	-rm -f *.cm[ix] *.o *~ ocamldoc.sty ocamldoc.out
	-rm -f domains/*.cm[ix] domains/*.o domains/*~
	-rm -f utils/*.cm[ix] utils/*.o utils/*~
	-rm -f fixpoint/*.cm[ix] fixpoint/*.o fixpoint/*~
	-rm -f data-struct/*.cm[ix] data-struct/*.o data-struct/*~
	-rm -f disassembly/*.cm[ix] disassembly/*.o disassembly/*~ disassembly/*.so
	-rm -f $(LIBNAME)
	-rm -f lexer.ml lexer.mli parser.ml parser.mli parser.conflicts parser.automaton

install: $(LIBNAME)
	cp $(LIBNAME) $(LIBDIR)

.depend: $(SRC)
	rm -f .depend
	$(CAMLDEP) $(SRC) > .depend

doc: 
	@mkdir -p $(DOCPATH)/html
	@mkdir -p $(DOCPATH)/latex
	@$(CAMLDOC) -html $^ -d $(DOCPATH)/html $(DIROPT) $(SRC)
	@$(CAMLDOC) -latex $^ -d $(DOCPATH)/latex

.PHONY: depend all clean install

include .depend

