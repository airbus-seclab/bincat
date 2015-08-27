
module Make: functor (Domain: Domain.T) ->
	     (** Fixpoint engine *)
sig

  (** control flow automaton *)
  module Cfa:
  sig
    module State:
    sig
      (** data type for the decoding context *)
	  type ctx_t = {
	      addr_sz: int; (** size in bits of the addresses *)
	      op_sz  : int; (** size in bits of operands *)
	    }
	   
	  (** abstract data type of a state *)
	  type t = {
	      id: int; 	     (** unique identificator of the state *)
	      ip: Domain.Asm.Address.t ;  (** instruction pointer *)
	      mutable v: Domain.t; 		  (** abstract value *)
	      mutable ctx: ctx_t ; 		  (** context of decoding *)
	      mutable stmts: Domain.Asm.stmt list; (** list of statements thas has lead to this state *)
	      internal     : bool 	     (** whenever this node has been added for technical reasons and not because it is a real basic blocks *)
	    }

    end

    (** abstract data type *)
    type t
	   
    (** the given string is the entry point *)
    val make: string -> t * State.t
			  
   
    (** graphviz printer *)
    val print: t -> unit

    
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
      
  (** computes the fixpoint of the reachable CFA from the given intial one and the provided code *)
    (** the given state is the initial state of the computation *)
  val process: Code.t ->  Cfa.t -> Cfa.State.t -> Cfa.t * (Cfa.State.t list)

 
 
end

