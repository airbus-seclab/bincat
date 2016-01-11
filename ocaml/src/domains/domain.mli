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
		
      (** type of abstract values *)
      type t 
      
      (** name of the abstract domain. For printing purpose only *)      
      val name: string 

      (** returns the initial value *)
      val init: unit -> t
			  
      (** comparison *)
      (** returns true whenever the concretization of the first argument is included in the concretization of the second argument *)
      (** false otherwise *)
      val subset: t -> t -> bool
 	       
      (** remove the given register from the given abstract value *)	
      val remove_register: Register.t -> t -> t

      (** string conversion *)
      val to_string: t -> string list

      (** assignment into the given register of the given expression *)
      val set_register: Asm.reg -> Asm.exp -> int -> (Asm.exp, Data.Address.Set.t) context -> t -> t

      (** assignment into memory *) 
      val set_memory: Asm.exp -> Asm.exp -> int -> (Asm.exp, Data.Address.Set.t) context -> t -> t
      (**[set_memory e1 n e2 ctx m] returns the abstract value _m_ where the dimension _e1_ of size _n_ bits has been set to _e2_ *)
      
      (** returns the set of addresses corresponding to the given expression of size in bits given by the parameter *)
      val mem_to_addresses: Asm.exp -> int -> t -> Data.Address.Set.t
      (** may raise an exception if the set of addresses is too large *)
								     
      (** returns the set of addresses corresponding to the given expression *)	
      val exp_to_addresses: Asm.exp -> int -> t -> Data.Address.Set.t
      (** may raise an exception if the set of addresses is too large *)
									  
      (** joins the two abstract values *)
      val join: t -> t -> t

      (** [taint_register_from_config r c m] update the abstract value _m_ with the given tainting configuration _c_ for register _r_ *)
      val taint_register_from_config: Register.t -> Config.tvalue -> t -> t

      (** [taint_register_from_config a c m] update the abstract value _m_ with the given tainting configuration _c_ for the memory location _a_ *)
      val taint_memory_from_config: Data.Address.t -> Config.tvalue -> t -> t

      (** [set_memory_from_config a c m]* update the abstract value _m_ with the value configuration for the memory location _a_ *)
      val set_memory_from_config: Data.Address.t -> Config.cvalue -> t -> t

      (** [set_register_from_config r c m] update the abstract value _m_ with the value configuration for register _r_ *)
      val set_register_from_config: Register.t -> Config.cvalue -> t -> t

      (** transfer function when the given function is entered *)
      val enter_fun: t -> Asm.fct -> t

      (** transfer function when the current function is returned *)
      val leave_fun: t -> t
    end
      
