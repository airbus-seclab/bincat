(*
    This file is part of BinCAT.
    Copyright 2014-2021 - Airbus

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

  let tbl: (Data.Address.t, Asm.import_desc_t * Asm.calling_convention_t) Hashtbl.t = Hashtbl.create 5

  let cdecl_calling_convention () = {
    return = reg "eax" ;
    callee_cleanup = (fun _x -> []) ;
    arguments = function
    | n -> M (BinOp (Add,
                     Lval (reg "esp"),
                     Const (Data.Word.of_int (Z.of_int ((n+1) * !Config.stack_width / 8))
                                             !Config.stack_width)),
              !Config.stack_width)
    }

  let stdcall_calling_convention () =
    let cdecl = cdecl_calling_convention () in
    {
    cdecl with
      callee_cleanup = (fun nargs -> [
        Set (reg "esp", BinOp(Add, Lval (reg "esp"),
                              Const (Data.Word.of_int (Z.of_int (nargs * !Config.stack_width/8))
                                       !Config.stack_width))) ])
  }

  let get_local_callconv cc =
    match cc with
    | Config.CDECL -> cdecl_calling_convention ()
    | Config.STDCALL -> stdcall_calling_convention ()
    | Config.FASTCALL -> L.abort (fun p -> p "Fast call not implemented yet")
    | c -> L.abort (fun p -> p "Calling convention [%s] not supported for x86 architecture"
                               (Config.call_conv_to_string c))

  let get_callconv () = get_local_callconv !Config.call_conv

  let set_first_arg e =
    let r = reg "esp" in
    [
      Set (r, BinOp(Sub, Lval r, Const (Data.Word.of_int (Z.of_int (!Config.stack_width/8)) !Config.stack_width))) ;
      Set (M(Lval r, !Config.stack_width), e)
    ]
    
  let unset_first_arg () =
    match !Config.call_conv with
    | Config.CDECL ->
       let r = reg "esp" in
       [
         Set (r, BinOp(Add, Lval r, Const (Data.Word.of_int (Z.of_int (!Config.stack_width/8)) !Config.stack_width)))
       ]
    | Config.STDCALL -> [] (* done by the callee *)
    | cc -> L.abort (fun p -> p "Unset_first_arg: unsupported pour that calling convetion (%s)" (Config.call_conv_to_string cc))
          
  let stub_stmts_from_name name callconv =
    if  Hashtbl.mem Stubs.stubs name then
      [ Directive (Stub (name, callconv)) ]
    else
      [ Directive (Forget (reg "eax")) ]


  let stack_width () = !Config.stack_width/8

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
        stub = stub_stmts @ [ Set(reg "esp", BinOp(Add, Lval (reg "esp"), const (stack_width()) 32)) ] ;
        epilogue = typing_epi @ tainting_epi ;
        ret_addr = Lval(M (BinOp(Sub, Lval (reg "esp"), const (stack_width()) 32),!Config.stack_width)) ;
      } in
      Hashtbl.replace tbl (Data.Address.global_of_int adrs) (fundesc, cc')
    ) Config.import_tbl


  let skip fdesc a =
      match fdesc with
      | Some (fdesc', cc) ->
         if Hashtbl.mem Config.funSkipTbl (Config.Fun_name fdesc'.Asm.name) then
           let stmts = [Directive (Skip (Asm.Fun_name fdesc'.Asm.name, cc)) ; Set(reg "esp", BinOp(Add, Lval (reg "esp"), const (stack_width()) 32)) ]  in
           { fdesc' with stub = stmts }
         else
           fdesc'
      | None ->
         let ia = Data.Address.to_int a in
         if Hashtbl.mem Config.funSkipTbl (Config.Fun_addr ia) then
           let arg_nb, _ = Hashtbl.find Config.funSkipTbl (Config.Fun_addr ia) in
           {
              name = "";
              libname = "";
              prologue = [];
              stub = [Directive (Skip (Asm.Fun_addr a, get_callconv())) ; Set(reg "esp", BinOp(Add, Lval (reg "esp"), const (stack_width()) 32)) ];
              epilogue = [];
              (* the return address expression is evaluated *after* cleaning up the stack (in stdcall),
               * so we need to look it up at the correct place, depending on the number of args *)
              ret_addr = if !Config.call_conv == Config.STDCALL then
                            Lval(M (BinOp(Sub, Lval (reg "esp"), const (((Z.to_int arg_nb)+1) * stack_width()) 32),!Config.stack_width))
                        else
                          Lval(M (BinOp(Sub, Lval (reg "esp"), const (stack_width()) 32),!Config.stack_width));
           }
          else
            raise Not_found

  let init () =
    Stubs.init ();
    init_imports ()

end
