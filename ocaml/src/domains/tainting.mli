(** Abstract domain computing a tainting analysis *)
module M: Domain.T
	    
(** function calling the lexer/parser for the tainting rules included in the file whose name is given as parameter *)
val parse: string -> unit
