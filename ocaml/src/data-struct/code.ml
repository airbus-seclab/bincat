(**************************************************************************************************************************)
(* Code module *)
(**************************************************************************************************************************)
type t = {
    rva: Z.t;   (** virtual address of the beginning of the code *)
    e: Z.t;    (** entry point, i.e. offset from the rva *)
    c: string; (** the byte sequence containing the code *)	       
  }
			   
let make ~code ~rva ~ep =
  {
    rva = rva;
    e 	= ep;
    c 	= code;
  }
    
    
let sub v a =
  try
    let o   = Z.to_int (Z.sub (Data.Address.to_int a) v.rva) in
    let len = (String.length v.c) - o         		     in
    String.sub v.c o len 
  with _ ->  Log.error (Printf.sprintf "Illegal address of code %s" (Data.Address.to_string a))
		   
let to_string c =
  let s = ref "" in
  for i = ((String.length c.c) -1) downto 0 do
    s := (Printf.sprintf "\\x%X" (Char.code (String.get c.c i))) ^ !s
  done;
  Printf.sprintf "entry point:\t %s\ntext:\t        %s" (Data.Word.to_string (Data.Word.of_int c.e !Config.address_sz)) !s
