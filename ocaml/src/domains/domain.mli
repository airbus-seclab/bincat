(** Signature of abstract domains *)

module type T = 
    sig
		
      (** type of abstract values *)
      type t 
      
      (** returns the initial value *)
      val init: unit -> t

      (** bottom value *)
      val bot: t

      (** returns true whenever the concretization of the first argument is included in the concretization of the second argument *)
      (** false otherwise *)
      val subset: t -> t -> bool
 	       
      (** remove the given register from the given abstract value *)	
      val remove_register: Register.t -> t -> t

      (** undefine the value of the register *)
      val undefine: Register.t -> t -> t
				       
      (** add the given register to the given abstract value *)
      val add_register: Register.t -> t -> t
					     
      (** string conversion *)
      val to_string: t -> string list

      (** int conversion of the given register *)
      (** may raise an exception if this kind of operation is not a singleton or is undefined for the given domain *)
      val value_of_register: t -> Register.t -> Z.t

      (** int conversion of the given expression *)
      (** may raise an exception if this kind of operation is not a singleton or is undefined for the given domain *)
      val value_of_exp: t -> Asm.exp -> Z.t
						 
      (** assignment into the given left value of the given expression *)
      val set: Asm.lval -> Asm.exp -> t -> t
									  
      (** joins the two abstract values *)
      val join: t -> t -> t

      (** meets the two abstract values *)
      val meet: t -> t -> t
			    
      (** [taint_register_from_config r c m] update the abstract value _m_ with the given tainting configuration _c_ for register _r_ *)
      (** the size of the configuration is the same as the one of the register *)
      val taint_register_from_config: Register.t -> Config.tvalue -> t -> t

      (** [taint_register_from_config a c m] update the abstract value _m_ with the given tainting configuration _c_ for the memory location _a_ *)
      (** the size of the configuration is the same as the one of a memory word *)
      val taint_memory_from_config: Data.Address.t -> Config.tvalue -> t -> t

      (** [set_memory_from_config a c m] update the abstract value _m_ with the value configuration for the memory location _a_ *)
      (** the size of the configuration is the same as the one of a memory word *)
      val set_memory_from_config: Data.Address.t -> Data.Address.region -> Config.cvalue -> t -> t

      (** [set_register_from_config r c m] update the abstract value _m_ with the value configuration for register _r_ *)
      (** the size of the configuration is the same as the one of the register *)
      val set_register_from_config: Register.t -> Data.Address.region -> Config.cvalue -> t -> t

      (** [compare v e1 c e2] restrict the given abstract value d to abstract value that satisfy the binary comparison (e1 c e2) *)
      (** may raise exception Exceptions.EmptyEnv *)
      val compare: t -> Asm.exp -> Asm.cmp -> Asm.exp -> t

      (** returns a set of addresses corresponding to the given expression *)
      (** may raise an exeption if that set is too large *)
      val mem_to_addresses: t -> Asm.exp -> Data.Address.Set.t

    end
      
