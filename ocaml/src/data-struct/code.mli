(** data type for the code *)
module type T =
  sig
    type t
    type address
	   
    (** Constructor *) 
    val make: address -> string -> t
    (** The provided address represents the address of the first element in the byte sequence *)
				     
    (** returns the sub sequence starting at the given address *)
    val sub: string -> address -> string
    (** may raise an exception if the given address is out of range *)
end

module Make: functor (D: Data.T) -> (T with type address = D.Address.t)
