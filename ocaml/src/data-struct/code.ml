(**************************************************************************************************************************)
(* Code module *)
(**************************************************************************************************************************)
module Make (D: Data.T) =
  struct
    type t = {
	e: D.Address.t; (** entry point *)
	o: int; 	(** offset of the start of the string from the entry point *)
	c: string; 	(** the byte sequence containing the code *)	       
      }
	       
    type address   = D.Address.t
    let make e o c =
      if o >= 0 then
	{e = e ; o = o ; c = c}
      else
	raise Utils.Illegal_address
	      
    let sub v a =
      try
	let o   = Int64.to_int (D.Address.sub a v.e) in
	let len = (String.length v.c) - o            in
	String.sub v.c o len 
      with _ -> raise Utils.Illegal_address
  end
