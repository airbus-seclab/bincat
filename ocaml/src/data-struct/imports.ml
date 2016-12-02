module Make(D: Domain.T) =
struct
  type fun_type = {
        name: string;
        libname: string;
        prologue: Asm.stmt list;
        stub: Asm.stmt list;
        epilogue: Asm.stmt list
  }

  let tbl: (Data.Address.t, fun_type) Hashtbl.t = Hashtbl.create 5

  exception Found of (Data.Address.t * fun_type)
  let search_by_name (fun_name: string): (Data.Address.t * fun_type) =
    try
      Hashtbl.iter (fun a fundec ->
	if String.compare fundec.name fun_name = 0 then
	  raise (Found (a, fundec))
	else ()
      ) tbl;
      raise Not_found
    with Found pair -> pair 

end
