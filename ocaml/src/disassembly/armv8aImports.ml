(*
    This file is part of BinCAT.
    Copyright 2014-2018 - Airbus

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

module L = Log.Make(struct let name = "armv8AImports" end)
         
module Make(D: Domain.T)(Stubs: Stubs.T with type domain_t := D.t) =
struct

  open Asm

  let reg r = V (T (Register.of_name r))

  let const x sz = Const (Data.Word.of_int (Z.of_int x) sz)

  let tbl: (Data.Address.t, import_desc_t * Asm.calling_convention_t) Hashtbl.t = Hashtbl.create 5

  let aapcs_calling_convention = {
    return = reg "x0" ;
    callee_cleanup = (fun _x -> []) ;
    arguments = function
    | 0 -> reg "x0"
    | 1 -> reg "x1"
    | 2 -> reg "x2"
    | 3 -> reg "x3"
    | 4 -> reg "x4"
    | 5 -> reg "x5"
    | 6 -> reg "x6"
    | 7 -> reg "x7"
    | 8 -> M (Lval (reg "sp"), 32)
    | n -> M ((BinOp (Add, Lval (reg "sp"), const ((n-5)*4) 32)), 32) ;
  }

  let get_local_callconv cc =
    match cc with
    | Config.AAPCS -> aapcs_calling_convention
    | c -> L.abort (fun p -> p "Calling convention [%s] not supported for ARM v8A architecture"
                               (Config.call_conv_to_string c))
    
  let get_callconv () = get_local_callconv !Config.call_conv
                    
  let typing_rule_stmts_from_name name =
    try
      let _rule = Hashtbl.find Config.typing_rules name in
      [], []
    with
    | _ -> [], []

  let stub_stmts_from_name name callconv =
    let stub_call =
      if  Hashtbl.mem Stubs.stubs name then
        [ Directive (Stub (name, callconv)) ]
      else
        [ Directive (Forget (reg "x0")) ] in
    stub_call @ [
        Directive (Forget (reg "x1")) ;
        Directive (Forget (reg "x2")) ;
        Directive (Forget (reg "x3")) ;
        Directive (Forget (reg "x4")) ;
        Directive (Forget (reg "x5")) ;
        Directive (Forget (reg "x6")) ;
        Directive (Forget (reg "x7")) ;
      ]

  let init_imports () =
    let default_cc = get_callconv () in
    Hashtbl.iter (fun adrs (libname,fname) ->
        let tainting_pro,tainting_epi, cc = Rules.tainting_rule_stmts libname fname (fun cc -> get_local_callconv cc) in
        let cc' =
          match cc with
          | Some cc -> cc
          | None -> default_cc
        in
        let typing_pro,typing_epi = Rules.typing_rule_stmts fname cc' in
        let stub_stmts = stub_stmts_from_name fname cc' in
        let fundesc:Asm.import_desc_t = {
        name = fname ;
        libname = libname ;
        prologue = typing_pro @ tainting_pro ;
        stub = stub_stmts ;
        epilogue = typing_epi @ tainting_epi ;
        ret_addr = Lval(reg "x30") ;
      } in
      Hashtbl.replace tbl (Data.Address.global_of_int adrs) (fundesc, cc')
    ) Config.import_tbl


  let skip fdesc a =
      match fdesc with
      | Some (fdesc', cc) ->
         if Hashtbl.mem Config.funSkipTbl (Config.Fun_name fdesc'.Asm.name) then
           let stmts = [Directive (Skip (Asm.Fun_name fdesc'.Asm.name, cc))]  in
           { fdesc' with stub = stmts }
         else
           fdesc'
        
      | None ->
         let ia = Data.Address.to_int a in
         if Hashtbl.mem Config.funSkipTbl (Config.Fun_addr ia) then
           {
          name = "";
          libname = "";
          prologue = [];
          stub = [];
          epilogue = [] ;
          ret_addr =Lval(reg "x30");
           }
         else
           raise Not_found

  let init () =
    Stubs.init ();
    init_imports ()


end
