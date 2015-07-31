(******************************************************************************)
(* Functor generating the unrelational abstract domain of pointer             *)
(******************************************************************************)
module Make(Asm: Asm.T): (Unrel.T with module Asm = Asm)

	    
