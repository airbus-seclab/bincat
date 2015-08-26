CMX = alarm.cmx register.cmx utils.cmx asm.cmx abi.cmx unrel.cmx tainting.cmx ptr.cmx pair.cmx state.cmx fixpoint.cmx main.cmx

LIBX=oUnitadvanced.cmxa oUnit.cmxa graph.cmxa nums.cmxa hmap.cmx hset.cmx hashcons.cmx

all:
	ocamlfind ocamlopt -o test -package ounit -I +ocamlgraph -I ../src/fixpoint -I ../src/disassembly -I ../src/utils -I ../src/data-struct -I ../src/domains -I ../src $(LIBX) $(CMX) test.ml
	./test
