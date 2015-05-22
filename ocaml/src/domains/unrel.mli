(** Functor to generate unrelational abstract domains *)
class type ['addr, 'v] ctx_t =
object
  method get_val_from_register: Register.t -> 'v
  method get_val_from_memory  : 'addr -> 'v
end

module type T =
    functor (D: Data.T) -> 
      functor (Asm: Asm.T with type word = D.Word.t and type address = D.Address.t) -> sig
	type t
	val name	    : string
	val top 	    : t
	val contains 	    : t -> t -> bool
	val equal    	    : t -> t -> bool
	val to_string	    : t -> string
	val eval_exp	    : Asm.exp -> (Asm.memory, D.Address.Set.t) Domain.context -> (D.Address.t, t) ctx_t -> t
	val mem_to_addresses: Asm.memory -> int -> (D.Address.t, t) ctx_t -> D.Address.Set.t option (** None is Top *)
(** never call the method ctx_t.to_addresses in this function *)
	val exp_to_addresses: Asm.exp -> (D.Address.t, t) ctx_t -> D.Address.Set.t option 
(* TODO merge this function with mem_to_addresses *)
	val taint_register  : Register.t -> t option 
	val taint_memory    : D.Address.t -> t option
	val join	    : t -> t -> t
	val combine	    : t -> t -> int -> int -> t (** [combine v1 v2 l u] computes v1[l, u] <- v2 *)
	val widen	    : t -> t -> t
      end
	
module Make(Do: T): Domain.T
