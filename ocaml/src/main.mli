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


(** the belowed signatures are given for test purpose only *)

 
module FlatFixpoint:
sig
  module Offset:
  sig
    type t
    val one: t
    val compare: t -> t -> int
  end
  module Address:
  sig
    type t
    val sub: t -> t -> Offset.t
    val to_string: t -> string
  end
  module Code:
  sig
    type t

    val make: code:string -> ep:string -> o:string -> addr_sz:int -> t
    (** code is the byte sequence of instructions to decode ; ep is the entry point ; o is the offset  *)
    (** of the entry point from the start of the provided byte sequence *)
    (** addr_sz is the size in bits of the addresses *)		

  end
 
  module Cfa:
  sig
     module State:
    sig
      type t
      val ip: t -> Address.t
    end
      
    type t
    val make: string -> t * State.t
    val print: t -> string -> unit
  end
  val process: Code.t -> Cfa.t -> Cfa.State.t -> Cfa.t * Cfa.State.t list
end
											  
