(** Abstract state module *)

(** signature of the abstract store (addresses, assembly language, etc.) *)
module type Store =
  sig
    type address
    type exp
    type asm
  end
    
module Make:
functor (Store: Store) ->
sig
  (** abstract state data type *)
  type t

  (** [contains s1 s2] returns true whenever _s1_ contains _s2_ *)
  val contains: t -> t -> bool

  (** creates an initial state with top value *)        
  val make: unit -> t

  (** returns Top *)
  val forget: t -> t

  (** returns true whenever its argument is top *)    
  val is_top: t -> bool

  (** function transfert of the assignment *)    
  val set: Store.address -> Store.lval -> Store.exp -> t -> t

  (** widening *)
  val widen: t -> t -> t

  (** restricts the given abstract state to values that satisfy then given expression *)
  val guard: t -> Store.exp -> t

  (** returns the list of addresses corresponding to the given expression *)
  val exp_to_addresses: t -> exp -> Store.address list

end

 
