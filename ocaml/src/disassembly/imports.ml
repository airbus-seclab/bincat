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

  open Asm

  (* x86 depend *)
      
  let esp () = Register.of_name "esp"
 
  (* x86 dependent *)
  let arg n =
    let esp = Register.of_name "esp" in
    Lval (M (BinOp (Add, Lval (V (T (esp))), Const (Data.Word.of_int (Z.of_int n) !Config.stack_width)), !Config.stack_width))

  (* x86 dependent *)
  let sprintf_stdcall () =
    let buf = arg 4 in
    let format = arg 8 in
    let va_arg = BinOp (Add, Lval (V (T (esp ()))), Const (Data.Word.of_int (Z.of_int 12) !Config.stack_width)) in
    let res = Register.of_name "eax" in
    [ Directive (Stub ("sprintf",  [Lval (V (T res)) ; buf ; format ; va_arg])) ]

  let sprintf_cdecl = sprintf_stdcall

    let printf_stdcall () =
    let format = arg 4 in
    let va_arg = BinOp (Add, Lval (V (T (esp()))), Const (Data.Word.of_int (Z.of_int 8) !Config.stack_width)) in
    let res = Register.of_name "eax" in
    [ Directive (Stub ("printf",  [Lval (V (T res)) ; format ; va_arg])) ]

  let printf_cdecl = printf_stdcall

  let puts_stdcall () =
    let str = arg 4 in
    let res = Register.of_name "eax" in
    [ Directive (Stub ("puts",  [Lval (V (T res)) ; str])) ]

  let puts_cdecl = puts_stdcall
    
  let strlen_stdcall () =
    let buf = arg 4 in
    let res = Register.of_name "eax" in
    [ Directive (Stub ("strlen",  [Lval (V (T res)) ; buf])) ]

  let strlen_cdecl = strlen_stdcall

  let memcpy_stdcall () =
    let dst = arg 4 in
    let src = arg 8 in
    let sz = arg 12 in
    let res = Register.of_name "eax" in
    [ Directive (Stub ("memcpy",  [Lval (V (T res)) ; dst ; src ; sz])) ]

  let memcpy_cdecl = memcpy_stdcall

  (* QEMU stb of printf *)
  let printf_chk_stdcall () =
    let format = arg 8 in
    let va_arg = BinOp (Add, Lval (V (T (esp()))), Const (Data.Word.of_int (Z.of_int 12) !Config.stack_width)) in
   
    let res = Register.of_name "eax" in
    [ Directive (Stub ("printf",  [Lval (V (T res)) ; format ; va_arg])) ]
      
  let printf_chk_cdecl = printf_chk_stdcall 
    
  let stdcall_stubs: (string, stmt list) Hashtbl.t = Hashtbl.create 5;;
  let cdecl_stubs: (string, stmt list) Hashtbl.t = Hashtbl.create 5;;

  let init_stdcall () =
    let funs =
      [("memcpy", memcpy_stdcall) ; ("sprintf", sprintf_stdcall) ; ("printf", printf_stdcall);
       ("puts", puts_stdcall);
       ("__printf_chk", printf_chk_stdcall) ; ("strlen", strlen_stdcall)
      ]
    in
    List.iter (fun (name, body) -> Hashtbl.add stdcall_stubs name (body())) funs
  
  
  let init_cdecl () =
	let funs =
	  [("memcpy", memcpy_cdecl) ; ("sprintf", sprintf_cdecl) ; ("printf", printf_cdecl);
	   ("puts", puts_cdecl);
       ("__printf_chk", printf_chk_cdecl) ; ("strlen", strlen_cdecl)
      ]
    in
    List.iter (fun (name, body) -> Hashtbl.add cdecl_stubs name (body())) funs
  	 
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
