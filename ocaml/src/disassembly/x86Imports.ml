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

module L = Log.Make(struct let name = "x86Imports" end)

module Make(D: Domain.T)(Stubs: Stubs.T with type domain_t := D.t) =
struct

  open Asm

  let reg r = V (T (Register.of_name r))

  let const x sz = Const (Data.Word.of_int (Z.of_int x) sz)

  let tbl: (Data.Address.t, Asm.import_desc_t) Hashtbl.t = Hashtbl.create 5

  let cdecl_calling_convention = {
    return = reg "eax" ;
    callee_cleanup = (fun _x -> [ ]) ;
    arguments = function
    | n -> Lval (M (BinOp (Add,
                           Lval (reg "esp"),
                           Const (Data.Word.of_int (Z.of_int ((n+1) * !Config.stack_width / 8))
                                    !Config.stack_width)),
                    !Config.stack_width))
  }

  let stdcall_calling_convention = {
    cdecl_calling_convention with
      callee_cleanup = (fun nargs -> [
        Set (reg "esp", BinOp(Add, Lval (reg "esp"),
                              Const (Data.Word.of_int (Z.of_int (nargs * !Config.stack_width/8))
                                       !Config.stack_width))) ])
  }

  let typing_rule_stmts_from_name name =
    try
      let _rule = Hashtbl.find Config.typing_rules name in
      [], []
    with
    | _ -> [], []

  let tainting_stmts_from_name libname name =
    try
      let _callconv,ret,args = Hashtbl.find Config.tainting_rules (libname,name) in
      let taint_arg taint =
        match taint with
        | Config.No_taint -> []
        | Config.Buf_taint -> [ Directive (Taint (None, M (Lval (reg "eax"), 
                                                           !Config.operand_sz))) ]
        | Config.Addr_taint -> [ Directive (Taint (None, (reg "eax"))) ]
      in
      let taint_ret_stmts =
        match ret with
        | None -> []
        | Some t -> taint_arg t
      in
      let _taint_args_stmts =
        List.fold_left (fun l arg -> (taint_arg arg)@l) [] args
      in
      [], taint_ret_stmts @ taint_ret_stmts
    with
    | _ -> [], []

  let stub_stmts_from_name name =
    let cc = 
      match !Config.call_conv with
      | Config.CDECL -> cdecl_calling_convention
      | Config.STDCALL -> stdcall_calling_convention
      | Config.FASTCALL -> L.abort (fun p -> p "Fast call not implemented yet")
      | c -> L.abort (fun p -> p "Calling convention [%s] not supported fot x86 architecture"
        (Config.call_conv_to_string c)) in

    if  Hashtbl.mem Stubs.stubs name then
      [ Directive (Stub (name, cc)) ]
    else
      [ Directive (Forget (reg "eax")) ]



  let init_imports () =
    Hashtbl.iter (fun adrs (libname,fname) ->
      let typing_pro,typing_epi = typing_rule_stmts_from_name fname in
      let tainting_pro,tainting_epi = tainting_stmts_from_name libname fname  in
      let stub_stmts = stub_stmts_from_name fname in
      let fundesc:Asm.import_desc_t = {
        name = fname ;
        libname = libname ;
        prologue = typing_pro @ tainting_pro ;
        stub = stub_stmts ;
        epilogue = typing_epi @ tainting_epi @ [ 
                       Set(reg "esp", BinOp(Add, Lval (reg "esp"), const 4 32))
                     ];
        ret_addr = Lval(M (Lval (reg "esp"),!Config.stack_width)) ;
      } in
      Hashtbl.replace tbl (Data.Address.global_of_int adrs) fundesc
    ) Config.import_tbl


  let init () =
    Stubs.init ();
    init_imports ()

end
