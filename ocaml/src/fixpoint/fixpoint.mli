
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
	      mutable v: Domain.t option; 		  (** abstract value ; None means "not set yet" *)
	      mutable ctx: ctx_t ; 		  (** context of decoding *)
	      mutable stmts: Domain.Asm.stmt list; (** list of statements thas has lead to this state *)
	      internal     : bool 	     (** whenever this node has been added for technical reasons and not because it is a real basic blocks *)
	    }


    end
    
    type t
    val create: unit -> t
			  
    (** dummy state *)
    (** the given string is the entry point *)
    val dummy_state: string -> State.t
				 

    
  end

    (** abstract data type of the code section *)
    module Code:
    sig
      type t
      (** constructor *)
      val make: string -> string -> string -> int -> t
      (** The first string is the entry point ; the second string is the offset (raises an exception if it is negative) *)
    (** of the entry point from the start of the provided byte sequence (third string) supposed to start at 0 index *)
    (** the integer is the size in bits of the addresses *)
							  
    end
      
  (** computes the fixpoint of the reachable CFA from the given intial one and the provided code *)
  (** the given state is the initial state of the computation *)
  val process: Code.t ->  Cfa.t -> Cfa.State.t -> Cfa.t

 
end

