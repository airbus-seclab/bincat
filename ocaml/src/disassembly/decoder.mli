module Make(Domain: Domain.T):
sig
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

	  (** state comparison: returns 0 whenever they are the physically the same (do not compare the content) *)
	  val compare: t -> t -> int
	  (** otherwise return a negative integer if the first state has been created before the second one; *)
	  (** a positive integer if it has been created later *)
    end
    (** Abstract data type of edge labels of the CFA *)
      module Label:
	sig
	  (** None means no label ; true is used for a if-branch link between states ; false for a else-branch link between states *)
	  type t = bool option 
	end
      (** *)    
      type t
      val create: unit -> t

			    
      (** dummy state *)
      val dummy_state: string -> State.t
      (** the given string is the entry point *)
				   
    (** [add_state g pred ip s stmts ctx i] creates a new state in _g_ with
    - ip as instruction pointer;
    - stmts as list of statements;
    - v as abstract value (if already in the CFG ; then previous value is joined with s)
    - pred as ancestor;
    - ctx as decoding context
    - i is the boolean true for internal states ; false otherwise *)
    val add_state: t -> State.t -> Domain.Asm.Address.t -> Domain.t option -> Domain.Asm.stmt list -> State.ctx_t -> bool -> State.t * bool

    (** [add_edge g src dst l] adds in _g_ an edge _src_ -> _dst_ with label _l_ *)
    val add_edge: t -> State.t -> State.t -> Label.t -> unit

    val succs: t -> State.t -> State.t list
    val pred: t -> State.t -> State.t list
    val remove: t -> State.t -> unit
    end
  
  type segments = {
      cs: Domain.Asm.Segment.t;
      ds: Domain.Asm.Segment.t;
      ss: Domain.Asm.Segment.t;
      es: Domain.Asm.Segment.t;
      fs: Domain.Asm.Segment.t;
      gs: Domain.Asm.Segment.t;
    }
  val parse: string -> Cfa.t -> Cfa.State.t -> Domain.Asm.Address.t -> segments -> Cfa.State.t list * int
end

