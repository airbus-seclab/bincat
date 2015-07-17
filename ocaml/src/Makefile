SRC=data-struct/data.mli data-struct/register.mli data-struct/register.ml\
	utils/mapOpt.mli utils/mapOpt.ml\
	utils/context.mli utils/context.ml\
	data-struct/asm.mli data-struct/asm.ml\
	data-struct/code.mli data-struct/code.ml\
	domains/domain.mli\
	fixpoint/alarm.mli fixpoint/alarm.ml\
	domains/unrel.mli domains/unrel.ml domains/ptr.mli domains/ptr.ml\
	disassembly/decoder.mli disassembly/decoder.ml\
	disassembly/abi.mli disassembly/abi.ml\
	domains/pair.mli domains/pair.ml\
	data-struct/interval.mli data-struct/interval.ml\
	 utils/utils.ml utils/utils.mli\
	domains/tainting.mli domains/tainting.ml\
	fixpoint/state.mli fixpoint/state.ml\
	data-struct/cfa.mli data-struct/cfa.ml\
	 fixpoint/fixpoint.mli fixpoint/fixpoint.ml main.mli main.ml

LIBNAME=libBinCAT.so



SRC1 = $(SRC:.mly=.ml)
SRC2 = $(SRC1:.mll=.ml)
OBJS1 = $(SRC2:.ml=.cmx)
OBJS2 = $(filter-out %.mly, $(OBJS1))
OBJS=$(filter-out %.mli, $(OBJS1))


DIROPT = -I fixpoint -I +ocamlgraph -I domains -I data-struct -I utils -I disassembly

CAMLC   =ocamlc $(DIROPT)
CAMLOPT =ocamlopt -w Ael -warn-error +a-7 $(DIROPT) 
CAMLLEX =ocamllex
CAMLYACC=ocamlyacc
CAMLDEP =ocamldep $(DIROPT)
CAMLDOC =ocamldoc $(DIROPT)

LIBX=graph.cmxa nums.cmxa hmap.cmx hset.cmx hashcons.cmx exceptions.cmx mapOpt.cmx\
extendedIntMisc.cmx extendedBigInt.cmx listUtils.cmx natural.cmx range.cmx bounded_congruence.cmx dimension.cmx

all: $(LIBNAME)

$(LIBNAME): $(OBJS1)
	$(CAMLOPT) -fPIC -output-obj -o $(LIBNAME) $(LIBX) $(OBJS)


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
	$(CAMLYACC) $<
	$(CAMLOPT) -c $*.mli
	$(CAMLOPT) -c $*.ml

.mly.cmi:
	$(CAMLYACC) $<
	$(CAMLC) -c $*.mli

.mll.ml:
	$(CAMLLEX) $<

.mly.ml:
	$(CAMLYACC) $<

clean:
	-rm -f .depend
	-rm -f *.cm[ix] *.o *~ ocamldoc.sty ocamldoc.out
	-rm -f domains/*.cm[ix] domains/*.o domains/*~
	-rm -f utils/*.cm[ix] utils/*.o utils/*~
	-rm -f fixpoint/*.cm[ix] fixpoint/*.o fixpoint/*~
	-rm -f data-struct/*.cm[ix] data-struct/*.o data-struct/*~
	-rm -f disassembly/*.cm[ix] disassembly/*.o disassembly/*~ disassembly/*.so
	-rm -f $(LIBNAME)

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

