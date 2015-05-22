CMX = alarm.cmx register.cmx utils.cmx asm.cmx abi.cmx unrel.cmx tainting.cmx ptr.cmx pair.cmx state.cmx fixpoint.cmx main.cmx

LIBX=graph.cmxa nums.cmxa hmap.cmx hset.cmx hashcons.cmx exceptions.cmx mapOpt.cmx\
extendedIntMisc.cmx extendedBigInt.cmx listUtils.cmx natural.cmx range.cmx bounded_congruence.cmx dimension.cmx

all:
	ocamlfind ocamlopt -o test -package oUnit -I +ocamlgraph -I ../src/fixpoint -I ../src/disassembly -I ../src/utils -I ../src/data-struct -I ../src/domains -I ../src -I "`ocamlfind query hashcons`"  -I "`ocamlfind query aiDataStruct`" $(LIBX) $(CMX) test.ml
	./test
