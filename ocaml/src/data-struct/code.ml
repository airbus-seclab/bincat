(**************************************************************************************************************************)
(* Code module *)
(**************************************************************************************************************************)
type t = {
    e: Data.Address.t; (** entry point *)
    c: string; 	       (** the byte sequence containing the code *)	       
  }
			   
let make ~code ~ep =
  {
    e = ep;
    c = code;
  }
    
    
let sub v a =
  try
    let o   = Data.Address.to_int a   in
    let len = (String.length v.c) - o in
    String.sub v.c o len 
  with _ ->  raise Utils.Illegal_address
		   
let to_string c =
  let s = ref "" in
  for i = ((String.length c.c) -1) downto 0 do
    s := (Printf.sprintf "\\x%X" (Char.code (String.get c.c i))) ^ !s
  done;
  Printf.sprintf "entry point:\t %s\ntext:\t        %s" (Data.Address.to_string c.e) !s
