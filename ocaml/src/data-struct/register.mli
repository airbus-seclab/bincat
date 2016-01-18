(** Module for registers *)

(** type of a register *)
type t

(** returns the set of current used registers *)
val used: unit -> t list
	   
(** creates a register from the given string and size *)
val make: name:string -> ?is_sp:bool -> size:int -> t
(** may raise Invalid_argument if a register with that name already exists 
or is a reserved name f *)
(** the boolean parameter is true whenever the register is the stack pointer. False otherwise *)

(** returns a fresh register name *)
val fresh_name: unit -> string

(** remove the given register from the set of used registers *)
val remove: t -> unit

(** returns the name of the given register *)
val name: t -> string

(** equality *)
val equal: t -> t -> bool

(** comparison *)
val compare: t -> t -> int
			 
(** returns the size in bits of the register *)
val size: t -> int

(** returns the register corresponding to the given name *)
val of_name: string -> t

(** returns true whenever the given register is the stack pointer *)
(** false otherwise *)
val is_stack_pointer: t -> bool
