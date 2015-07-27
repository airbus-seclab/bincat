(** Signature of abstract domains *)

(** a context is a kind of oracle for a domain to get useful information (from other domains, etc.) *) 
class type ['mem, 'addr] context =
  object

    (** [mem_to_addresses a n] returns either *)
    (** Top or the concrete address starting at the abstract address _a_ of _n_ bit width *) 
  method mem_to_addresses: 'mem -> int -> 'addr option 
  (** never call this method from T.exp_to_addresses (stack overflow) *)
end

module type T = 
    sig
      module Asm: Asm.T
		
      (** type of abstract values *)
      type t 
      
      (** name of the abstract domain. For printing purpose only *)      
      val name: string 

      (** returns true whenever the first argument contains the second one *)	
      val contains: t -> t -> bool
      (** false otherwise *)
				
      (** remove the given register from the given abstract value *)	
      val remove_register: Register.t -> t -> t

      (** string conversion *)
      val to_string: t -> string list

      (** assignment into the given register of the given expression *)
      val set_register: Asm.reg -> Asm.exp -> (Asm.exp, Asm.Address.Set.t) context -> t -> t
      
      (** returns the set of addresses corresponding to the given expression of size in bits given by the parameter ;
	  None is for Top *)	
      val mem_to_addresses: Asm.exp -> int -> t -> Asm.Address.Set.t option
      
      (** returns the set of addresses corresponding to the given expression ; None is Top *)	
      val exp_to_addresses: t -> Asm.exp -> Asm.Address.Set.t option

      (** assignment into memory *) 
      val set_memory: Asm.exp -> int -> Asm.exp -> (Asm.exp, Asm.Address.Set.t) context -> t -> t
      (**[set_memory e1 n e2 ctx m] returns the abstract value _m_ where the dimension _e1_ of size _n_ bits has been set to _e2_ *)

      (** [taint_register r m] *) 
      val taint_register: Register.t -> t -> t
      (** returns _m_ where the register _r_ has been tainted *)
      (** the identity is a sound return value *)
					       
      (** [taint_memory a m] *) 
      val taint_memory: Asm.Address.t -> t -> t
      (** returns _m_ where the address _a_ has been tainted *)
      (** the identity is a sound return value *)
					      
      (** creates an initial value *)	
      val make: unit -> t

      (** forgets all computed information in s *)
      val forget: t -> t
      (**  only dimensions are preserved *)	

      (** widens the two abstract values *)
      val widen: t -> t -> t
    end
      
