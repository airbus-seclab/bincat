(** Code functor *)

module Make:
  functor (D: Data.T) ->
  sig
    (** code data type *)
    type t
	   
    (** constructor *) 
    val make: string -> string -> string -> int -> t
    (** The first string is the entry point ; the second string is the offset (raises an exception if it is negative) *)
    (** of the entry point from the start of the provided byte sequence (third string) supposed to start at 0 index *)
    (** the integer is the size in bits of the addresses *)
				     
    (** returns the sub sequence starting at the given address *)
    val sub: t -> D.Address.t -> string
    (** may raise an exception if the given address is out of range *)
  end
