(** Code functor *)

module Make:
  functor (D: Data.T) ->
  sig
    (** code data type *)
    type t
	   
    (** constructor *) 
    val make: code:string -> ep:string -> o:string -> addr_sz:int -> t
    (** code is the byte sequence of instructions to decode ; ep is the entry point ; o is the offset  *)
    (** of the entry point from the start of the provided byte sequence *)
    (** addr_sz is the size in bits of the addresses *)
				     
    (** returns the sub sequence starting at the given address *)
    (** may raise an exception if the given address is out of range *)
    val sub: t -> D.Address.t -> string
				   

    (** string conversion *)
    val to_string: t -> string
  end
