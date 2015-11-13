(**************************************************************************************************************************)
(* Code module *)
(**************************************************************************************************************************)
module Make (D: Data.T) =
  struct
    type t = {
	e: D.Address.t; (** entry point *)
	o: D.Offset.t; 	(** offset of the start of the string from the entry point *)
	c: string; 	(** the byte sequence containing the code *)	       
      }
			   
    let make ~code ~ep ~a ~addr_sz =
      let e = D.Address.of_string ep addr_sz in
      try
	{
	  e = e;
	  o = D.Address.sub (D.Address.of_string a addr_sz) e;
	  c = code;
	}
      with _ -> raise Utils.Illegal_address
		      
    let sub v a =
      try
	let o   = D.Offset.to_int (D.Address.sub a v.e) in
	let len = (String.length v.c) - o               in
	String.sub v.c o len 
      with _ -> raise Utils.Illegal_address

    let to_string c =
      let s = ref "" in
      for i = ((String.length c.c) -1) downto 0 do
	s := (Printf.sprintf "\\x%X" (Char.code (String.get c.c i))) ^ !s
      done;
      "entry point:\t" ^ (D.Address.to_string c.e) ^ "\ntext:\t        " ^ !s
  end
