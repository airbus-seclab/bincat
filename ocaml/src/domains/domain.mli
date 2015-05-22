(** Signature of abstract domains *)
class type ['mem, 'addr] context =
object
  method mem_to_addresses: 'mem -> int -> 'addr option (** None is for Top *)
  (* never call this method from T.exp_to_addresses (stack overflow) *)
end

module type T = 
  functor (D: Data.T) -> 
    functor (Asm: Asm.T with type address = D.Address.t and type word = D.Word.t) ->
    sig
      type t 
      (** type of non bottom abstract values *)
      
      val name	      : string 
      (** name of the absract domain. For printing purpose *)
	
      val contains	      : t -> t -> bool
      (** returns true whenever the first argument contains the second one *)
	
      val remove_register : Register.t -> t -> t
      (** remove the given var from the given abstract value *)
	
      val to_string	      : t -> string list
	
      val set_register    : Asm.reg -> Asm.exp -> (Asm.memory, D.Address.Set.t) context -> t -> t
      (** assignment into register *)
	
      val mem_to_addresses: Asm.memory -> int -> t -> D.Address.Set.t option
      (** returns the set of addresses corresponding to the given memory expression of size in bits given by the parameter ;
	  None is for Top *)
	
      val exp_to_addresses: t -> Asm.exp -> D.Address.Set.t option
(** returns the set of addresses corresponding to the given expression ; None is Top *)

      val set_memory      : Asm.memory -> int -> Asm.exp -> (Asm.memory, D.Address.Set.t) context -> t -> t
      (** assignment into memory ; first argument is the destination ; *)
      (** second one is the content to store *)
	
      val taint_register  : Register.t -> t -> t
      (** identity is sound *)
	
      val taint_memory      : D.Address.t -> t -> t
      (** identity is sound *)
	
      val make : unit -> t
      (** initial value *)
	
      val forget : t -> t
    (** forgets all computed information in s ; only dimensions are preserved *)

      val widen: t -> t -> t
    end
      
