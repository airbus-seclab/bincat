(** data type for the code *)
module type T =
  sig
    type t
    type address
	   
    (** constructor *) 
    val make: address -> int -> string -> t
    (** The provided address is the entry point ; the integer is the offset (raises an exception if it is negative) *)
    (** of the entry point from the start of the provided byte sequence supposed to start at 0 index *)
				     
    (** returns the sub sequence starting at the given address *)
    val sub: t -> address -> string
    (** may raise an exception if the given address is out of range *)
end

module Make: functor (D: Data.T) -> (T with type address = D.Address.t)
