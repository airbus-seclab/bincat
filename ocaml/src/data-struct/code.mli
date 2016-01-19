(** Abstract Data Type for the code *)
    type t
	   
    (** constructor *) 
    val make: code:string -> ep:Z.t -> t
    (** code is the byte sequence of instructions to decode *)
    (** ep is the entry point in that sequence *)
									      
				     
    (** returns the sub sequence starting at the given address *)
    (** may raise an exception if the given address is out of range *)
    val sub: t -> Data.Address.t -> string
				   

    (** string conversion *)
    val to_string: t -> string
