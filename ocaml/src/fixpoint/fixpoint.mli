
module Make: functor (Domain: Domain.T) ->
	     (** Fixpoint engine *)
sig		     
  module Dom:
  sig
    type t = Domain.t
    val equal: t -> t -> bool
  end
  module Offset:
  sig
    type t
    val one: t
    val compare: t -> t -> int
  end
  module Address:
  sig
    type t = Domain.Asm.Address.t
    val sub: t -> t -> Offset.t
    val to_string: t -> string
  end
    
  (** control flow automaton *)
  module Cfa:
  sig
    module State:
    sig
      type t
      val ip: t -> Domain.Asm.Address.t
      val abstract_value: t -> Domain.t 
    end

    (** abstract data type *)
    type t
	   
    (** the given string is the entry point *)
    val make: string -> t * State.t
			  
   
    (** graphviz printer *)
    (** the string parameter is the name of the dot file containing results *)
    val print: t -> string -> unit

    
  end

    (** abstract data type of the code section *)
    module Code:
    sig
      (** constructor *)
      type t
	     
    val make: code:string -> ep:string -> o:string -> addr_sz:int -> t
    (** code is the byte sequence of instructions to decode ; ep is the entry point ; o is the offset  *)
    (** of the entry point from the start of the provided byte sequence *)
								       (** addr_sz is the size in bits of the addresses *)

    (** string conversion *)
    val to_string: t -> string
    end

    type segments = {
	cs: Address.t;
	ds: Address.t;
	ss: Address.t;
	es: Address.t;
	fs: Address.t;
	gs: Address.t
      }
		      
  (** computes the fixpoint of the reachable CFA from the given intial one and the provided code *)
    (** the given state is the initial state of the computation *)
  val process: Code.t ->  Cfa.t -> Cfa.State.t -> segments -> Cfa.t

 
 
end

