(*********************************************************************************)
(* Functor generating unrelational abstract domains                              *)
(* basically it is a map from Registers and Memory Addrresses to abstract values *)
(*********************************************************************************)

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
		
    (** non initialized abstract value *)
    (** the integer is the size in bits of this value *)
    val bot: int -> t

    (** set comparison : returns true whenever the first argument is included in the second one *)
    val subset: t -> t -> bool

    (** string conversion *)
    val to_string: t -> string

    (** value generation from configuration *)
    (** the integer paramater is the size in bits of the returned value *)
    val of_config: Config.cvalue -> int -> t

    (** returns the evaluation of the given expression as an abstract value *)			    
    val eval_exp: Asm.exp -> (Asm.exp, Asm.Address.Set.t) Domain.context -> (Asm.Address.t, t) ctx_t -> t
												  
    (** returns the set of addresses associated to the memory expression of size _n_ where _n_ is the integer parameter *)
    val mem_to_addresses: Asm.exp -> int -> (Asm.Address.t, t) ctx_t -> Asm.Address.Set.t
    (** may raise an Exception if this set of addresses is too large *)	
    (** never call the method ctx_t.to_addresses in this function *)
										    
    (** returns the set of addresses associated to the given expression *)										 
    val exp_to_addresses: Asm.exp -> (Asm.Address.t, t) ctx_t -> Asm.Address.Set.t
    (** may raise an Exception if this set of addresses is too large *)
										   
    (** returns the tainted value corresponding to the given configuration *)
    val taint_from_config: Config.tvalue -> t option
    (** None means that this functionality is not handled *)
					
  
				       
    (** join two abstract values *)
    val join: t -> t -> t
			  
    (** [combine v1 v2 l u] computes v1[l, u] <- v2 *)
    val combine: t -> t -> int -> int -> t 

  end
		  
module Make(V: T): (Domain.T with module Asm = V.Asm)
