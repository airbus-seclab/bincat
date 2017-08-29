(*
    This file is part of BinCAT.
    Copyright 2014-2017 - Airbus Group

    BinCAT is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or (at your
    option) any later version.

    BinCAT is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with BinCAT.  If not, see <http://www.gnu.org/licenses/>.
*)

(* TODO: move parts depending on x86 architecture (eax for instance in result) into a subdirectory x86 *)
module Make(D: Domain.T) =
struct
  type fun_type = {
        name: string;
        libname: string;
        prologue: Asm.stmt list;
        stub: Asm.stmt list;
        epilogue: Asm.stmt list;
        ret_addr: Asm.exp
  }

  let tbl: (Data.Address.t, fun_type) Hashtbl.t = Hashtbl.create 5

  let available_stubs: (string, unit) Hashtbl.t = Hashtbl.create 5

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

  open Asm

  (* x86 depend *)

  let reg r = V (T (Register.of_name r))

  let cdecl_calling_convention = {
    return = reg "eax" ;
    callee_cleanup = (fun _x -> [ ]) ;
    arguments = function
    | n ->
       Lval (M (BinOp (Add,
                      Lval (reg "esp"),
                      Const (Data.Word.of_int (Z.of_int ((n+1) * !Config.stack_width / 8)) !Config.stack_width)),
               !Config.stack_width))
  }

  let stdcall_calling_convention = { cdecl_calling_convention with
      callee_cleanup = (fun nargs -> [
        Set (reg "esp", BinOp(Add, Lval (reg "esp"),
                              Const (Data.Word.of_int (Z.of_int (nargs * !Config.stack_width/8)) !Config.stack_width))) ])
  }

  let stdcall_stubs: (string, stmt list) Hashtbl.t = Hashtbl.create 5;;
  let cdecl_stubs: (string, stmt list) Hashtbl.t = Hashtbl.create 5;;


  let funs = [
    "memcpy" ;
    "puts";
    "sprintf";
    "printf" ;
    "__printf_chk" ;
    "__sprintf_chk" ;
    "strlen" ;
  ]

  let init_cdecl () =
    List.iter (fun name ->
      Hashtbl.add cdecl_stubs name [ Directive (Stub (name, cdecl_calling_convention)) ];
      Hashtbl.replace available_stubs name ()
    ) funs

  let init_stdcall () =
    List.iter (fun name ->
      Hashtbl.add stdcall_stubs name [ Directive (Stub (name, stdcall_calling_convention)) ];
      Hashtbl.replace available_stubs name ()
    ) funs

  let init () =
    init_stdcall ();
    init_cdecl ()

  let string_from_fundec fundec =
    Printf.sprintf "%s (lib=%s) prologue=%s stub=%s epilogue=%s"
      fundec.name
      fundec.libname
      (string_of_stmts fundec.prologue true)
      (string_of_stmts fundec.stub true)
      (string_of_stmts fundec.epilogue true)

  let string_from_fundecs fundecs =
    let fundecs_str = List.map string_from_fundec fundecs
    in Printf.sprintf "[ %s ]" (String.concat ",\n" fundecs_str)

end
