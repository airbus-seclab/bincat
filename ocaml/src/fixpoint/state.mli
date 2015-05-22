(** Signature of an abstract state *)
module type T = sig
 type t
  (** abstract state data type *)
 type address
 type lval
 type exp

  val contains: t -> t -> bool
  (** [contains s1 s2] returns true whenever _s1_ contains _s2_ *)
    
  val make: unit -> t
  (** creates an initial state with top value *)    

  val forget: t -> t
  (** returns Top *)
    
  val is_top: t -> bool
(** returns true whenever its argument is top *)
    
  val set: address -> lval -> exp -> t -> t
(** function transfert of the assignment *)

  val widen: t -> t -> t
  (** widening *)

  val guard: t -> exp -> t
(** restricts the given abstract state to values that satisfy then given expression *)

  val exp_to_addresses: t -> exp -> address list
(** returns the list of addresses corresponding to the given expression *)
end

module Make(Data: Data.T)(Asm: Asm.T with type address = Data.Address.t and type word = Data.Word.t):
  (T with type address = Data.Address.t and type lval = Asm.lval and type exp = Asm.exp)
 
