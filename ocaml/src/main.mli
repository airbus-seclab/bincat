(** binding between C and ml *)
(** this module contains all exported symbols *)


(** [process_elf flat segments op_sz text o e] *)
val process_elf: bool -> int array -> int -> string -> string -> string -> unit
(** flat : true for a flat memory model ; 
segments in the array are supposed in that order cs, ds, ss, es, fs, gs ;
op_sz is the size in bits of the addresses and operands ;
text : code ; o : offset of the entry point wrt to the beginning of the text section ; e : entry point ;
o and e are supposed in hexadecimal with the format \x... *)


val process_pe: bool -> int array -> int -> int -> int -> string -> string -> string -> unit
(** addr : address size (16 or 32) ; op: operand size (16 or 32) ; stack: stack width (16 or 32) *)


(** fixpoint engine for a flat memory model *)
(** its signature is exposed for test purpose only *)
(* module FlatFixpoint: *)
(* sig *)
(*   (\* module Address: *\) *)
(*   (\* sig *\) *)
(*   (\*   type t *\) *)
(*   (\* end *\) *)
(*   (\* module Offset: *\) *)
(*   (\* sig *\) *)
(*   (\*   type t *\) *)
(*   (\* end *\) *)
(*   module Code: *)
(*   sig *)
(*     type t *)
(*   end *)
(*   module Cfa: *)
(*   sig *)
(*     type t *)
(*     module State: *)
(*     sig *)
(*       type t *)
(*       val equal: t -> t -> bool *)
(*     end *)
(*   end *)
(*     (\*val process_stmt: Cfa.t -> Cfa.State.t -> Address.t -> Offset.t -> Asm.t -> Cfa.State.t*\) *)
(* end *)
											  
