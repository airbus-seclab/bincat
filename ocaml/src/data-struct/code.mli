(** Abstract Data Type for the code *)

module Make:
  functor (D: Data.T) ->
  sig
    (** code data type *)
    type t
	   
    (** constructor *) 
    val make: code:string -> ep:D.Address.t -> o:D.Offset.t -> t
    (** code is the byte sequence of instructions to decode ; ep is the address of the entry point in the code; o is an offset between the begining of the code and the entry point *)
									      
				     
    (** returns the sub sequence starting at the given address *)
    (** may raise an exception if the given address is out of range *)
    val sub: t -> D.Address.t -> string
				   

    (** string conversion *)
    val to_string: t -> string
  end
