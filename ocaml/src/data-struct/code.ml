(**************************************************************************************************************************)
(* Code module *)
(**************************************************************************************************************************)
module Make (D: Data.T) =
  struct
    type t = {
	e: D.Address.t; (** entry point *)
	o: Int64.t; 	(** offset of the start of the string from the entry point *)
	c: string; 	(** the byte sequence containing the code *)	       
      }
	       
    let make ~code ~ep ~o ~addr_sz =
      try
	let o' = Int64.of_string o in
	if Int64.compare o' Int64.zero  >= 0 then
	  {e = D.Address.of_string ep addr_sz; o = o' ; c = code}
	else
	  raise Utils.Illegal_address
      with _ -> raise Utils.Illegal_address
		      
    let sub v a =
      try
	let o   = Int64.to_int (D.Address.sub a v.e) in
	let len = (String.length v.c) - o            in
	String.sub v.c o len 
      with _ -> raise Utils.Illegal_address
  end
