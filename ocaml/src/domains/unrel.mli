(******************************************************************************)
(* Functor generating unrelational abstract domains                           *)
(* basically it is a map from Registers to abstract values                    *)
(******************************************************************************)

(** context *)
class type ['addr, 'v] ctx_t =
  object

    (** returns the abstract value associated to the given register *)
    method get_val_from_register: Register.t -> 'v

    (** returns the abstract value associated to the given address *)
    method get_val_from_memory  : 'addr -> 'v
end


    
(** Unrelational domain signature *)
module type T = sig

    (** the assembly intermediate language *)
    module Asm: Asm.T

    (** abstract data type *)
    type t
	   
    (** name of the abstract domain *)
    val name: string
		
    (** top abstract value *)
    val top: t

    (** equality comparion : returns true whenever the two arguments are logically equal *)
    val equal: t -> t -> bool

    (** order comparison : returns true whenever the first argument is greater than the second one *)
    val contains: t -> t -> bool

    (** string conversion *)
    val to_string: t -> string
			  
    (** returns the evaluation of the given expression as an abstract value *)			    
    val eval_exp: Asm.exp -> (Asm.exp, Asm.Address.Set.t) Domain.context -> (Asm.Address.t, t) ctx_t -> t
												  
    (** returns the set of addresses associated to the memory expression of size _n_ where _n_ is the integer parameter *)
    val mem_to_addresses: Asm.exp -> int -> (Asm.Address.t, t) ctx_t -> Asm.Address.Set.t option
    (** None is Top *)										  
    (** never call the method ctx_t.to_addresses in this function *)
										    
    (** returns the set of addresses associated to the given expression *)											  
    val exp_to_addresses: Asm.exp -> (Asm.Address.t, t) ctx_t -> Asm.Address.Set.t option 
									     
    (** taint the given register into the given abstract value *)
    val taint_register: Register.t -> t option
    (** None means that this functionality is not handled *)
					
    (** taint the given address into the given abstract value *)
    val taint_memory: Asm.Address.t -> t option
    (** None means that this functionality is not handled *)
				       
    (** join two abstract values *)
    val join: t -> t -> t
			  
    (** [combine v1 v2 l u] computes v1[l, u] <- v2 *)
    val combine: t -> t -> int -> int -> t 
					   
    (** widens two abstract values *)
    val widen: t -> t -> t
  end
		  
module Make(V: T): Domain.T
