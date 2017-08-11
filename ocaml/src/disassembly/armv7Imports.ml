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

  let reg r = Lval (V (T (Register.of_name r)))

  (* strlen *)
  let strlen_aapcs () =
    let buf = Lval (V (T (Register.of_name "r0"))) in
    let res = reg "r0" in
    [ Directive (Stub ("strlen",  [res ; buf])) ]

  (* memcpy *)
  let memcpy_aapcs () =
    let dst = reg "r0" in
    let src = reg "r1" in
    let sz = reg "r2" in
    let res = reg "r0" in
    [ Directive (Stub ("memcpy",  [res ; dst ; src ; sz])) ]



  let aapcs_stubs: (string, stmt list) Hashtbl.t = Hashtbl.create 5;;

  let init_aapcs () =
    let funs =
      [ ("memcpy", memcpy_aapcs) ;
        (*("sprintf", sprintf_stdcall) ;
        ("printf", printf_stdcall) ;
        ("puts", puts_stdcall) ;
        ("__printf_chk", printf_chk_stdcall) ; *)
        ("strlen", strlen_aapcs) ]
    in
    List.iter (fun (name, body) -> 
      Hashtbl.add aapcs_stubs name (body());
      Hashtbl.replace available_stubs name ()
    ) funs


  let init () =
    init_aapcs ()

end

