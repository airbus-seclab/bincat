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

      (** equality *)
      val equal: t -> t -> bool
		       
      (** remove the given register from the given abstract value *)	
      val remove_register: Register.t -> t -> t

      (** string conversion *)
      val to_string: t -> string list

      (** assignment into the given register of the given expression *)
      val set_register: Asm.reg -> Asm.exp -> (Asm.exp, Asm.Address.Set.t) context -> t -> t
      
      (** returns the set of addresses corresponding to the given expression of size in bits given by the parameter *)
      val mem_to_addresses: Asm.exp -> int -> t -> Asm.Address.Set.t
      (** may raise an exception if the set of addresses is too large *)
								     
      (** returns the set of addresses corresponding to the given expression *)	
      val exp_to_addresses: t -> Asm.exp -> Asm.Address.Set.t
      (** may raise an exception if the set of addresses is too large *)

      (** assignment into memory *) 
      val set_memory: Asm.exp -> int -> Asm.exp -> (Asm.exp, Asm.Address.Set.t) context -> t -> t
      (**[set_memory e1 n e2 ctx m] returns the abstract value _m_ where the dimension _e1_ of size _n_ bits has been set to _e2_ *)

      (** [taint_register r t m] *) 
      val taint_register: Register.t -> Config.value -> t -> t
      (** returns _m_ where the register _r_ has been tainted by value _t_ *)
      (** the identity is a sound return value *)
      (** may raise an exception if the value size exceeds the register capacity *)

      (** [set_register_from_config r c m] *)
      val set_register_from_config: Register.t -> Config.value -> t -> t
      (** returns _m_ where the register _r_ has been set to value _c_ *)
      (** the identity is a sound return value *)
      (** may raise an exception if the size of _c_ exceeds the register capacity *)
									   
      (** [taint_memory a t m] *) 
      val taint_memory: Asm.Address.t -> Config.value -> t -> t
      (** returns _m_ where the address _a_ has been tainted by value _t_ *)
      (** the identity is a sound return value *)

      (** [set_memory_from_config a c m] *)
      val set_memory_from_config: Asm.Address.t -> Config.value -> t -> t
      (** returns _m_ where the memory address _a_ has been set to value _c_ *)
      (** the identity is a sound return value *)		      
      (** top value *)	
      val top: t
			
      (** returns true whenever the given value is top *)
      val is_top: t -> bool

      (** forgets all computed information in s *)
      val forget: t -> t
      (**  only dimensions are preserved *)	

      (** joins the two abstract values *)
      val join: t -> t -> t

      (** create an abstract value from the registers in Register.tbl ; all dimensions are set to top *)
      val from_registers: unit -> t
    end
      
