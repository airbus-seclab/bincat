CMX = alarm.cmx mapOpt.cmx register.cmx utils.cmx asm.cmx cfa.cmx decoder.cmx code.cmx abi.cmx unrel.cmx tainting.cmx ptr.cmx pair.cmx fixpoint.cmx main.cmx

LIBX=unix.cmxa graph.cmxa nums.cmxa

all:
	ocamlfind ocamlopt -o test -I +ocamlgraph -I ../src/fixpoint -I ../src/disassembly -I ../src/utils -I ../src/data-struct -I ../src/domains -I ../src $(LIBX) $(CMX) test.ml
	./test
