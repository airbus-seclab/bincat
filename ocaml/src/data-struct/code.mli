(** Code functor *)

module Make :
  functor (D: Data.T) ->
  sig
    (** code data type *)
    type t
	   
    (** constructor *) 
    val make: D.Address.t -> int -> string -> t
    (** The provided address is the entry point ; the integer is the offset (raises an exception if it is negative) *)
    (** of the entry point from the start of the provided byte sequence supposed to start at 0 index *)
				     
    (** returns the sub sequence starting at the given address *)
    val sub: t -> D.Address.t -> string
    (** may raise an exception if the given address is out of range *)
  end
