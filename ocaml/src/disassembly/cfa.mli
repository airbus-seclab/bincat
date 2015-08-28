(******************************************************************************)
(* Functor generating the control flow automaton                              *)
(******************************************************************************)
module Make(Domain: Domain.T):
sig
(** Abstract data type of nodes of the CFA *)
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
      (** the string is the value of the instruction pointer *)
  val make: string -> t * State.t

  (** cfa pretty printer *)
  (** the string parameter is the file name *)
  val print: t -> string -> unit
			       
  (** set the v field of given state by the given domain *)
  val update_state: State.t -> Domain.t -> bool
					     
  (** strong update if the state was not initalized ; a weak update otherwise *)
  (** if the result is contained in the first case then false is returned ; otherwise true is returned *)
							      
  (** updates the context and statement fields of the given state *)
  val update_stmts: State.t -> Domain.Asm.stmt list -> int -> int -> unit
  (** the first integer is the new operand size ; the second integer is the new address size. Both in bits *)

  (** [add_edge g src dst l] adds in _g_ an edge _src_ -> _dst_ with label _l_ *)
  val add_edge: t -> State.t -> State.t -> Label.t -> unit

(** [add_state g pred ip s stmts ctx i] creates a new state in _g_ with
    - ip as instruction pointer;
    - stmts as list of statements;
    - v as abstract value (if already in the CFA ; then previous value is joined with s)
    - pred as ancestor;
    - ctx as decoding context
    - i is the boolean true for internal states ; false otherwise *)
  val add_state: t -> State.t -> Domain.Asm.Address.t -> Domain.t -> Domain.Asm.stmt list -> State.ctx_t -> bool -> State.t * bool

  val succs: t -> State.t -> State.t list
  val pred: t -> State.t -> State.t list
 
  val remove: t -> State.t -> unit


  end
