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

module Make(D: Domain.T) =
struct
  type fun_type = {
        name: string;
        libname: string;
        prologue: Asm.stmt list;
        stub: Asm.stmt list;
        epilogue: Asm.stmt list;
        ret_addr: Asm.exp;
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

  let reg r = V (T (Register.of_name r))

  let const x sz = Const (Data.Word.of_int (Z.of_int x) sz)

  let aapcs_calling_convention = {
    return = reg "x0" ;
    callee_cleanup = (fun _x -> []) ;
    arguments = function
      | 0 -> Lval (reg "x0")
      | 1 -> Lval (reg "x1")
      | 2 -> Lval (reg "x2")
      | 3 -> Lval (reg "x3")
      | 4 -> Lval (M (Lval (reg "sp"), 64))
      | n -> Lval (M ((BinOp (Add, Lval (reg "sp"), const ((n-5)*8) 64)), 64)) ;
  }

  let aapcs_stubs: (string, stmt list) Hashtbl.t = Hashtbl.create 5;;

  let init_aapcs () =
    let funs =
      [ "memcpy" ;
        "puts";
        "sprintf";
        "printf" ;
        "__printf_chk" ;
        "__sprintf_chk" ;
        "strlen" ]
    in
    List.iter (fun name ->
      Hashtbl.add aapcs_stubs name [ Directive (Stub (name, aapcs_calling_convention)) ];
      Hashtbl.replace available_stubs name ()
    ) funs

  let init () =
    init_aapcs ()

end

