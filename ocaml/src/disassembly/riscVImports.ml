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


module L = Log.Make(struct let name = "riscVImports" end)
module Make(D: Domain.T)(Stubs: Stubs.T with type domain_t := D.t) =
  struct

    open Asm
    let reg r = V (T (Register.of_name r))
    let const x sz = Const (Data.Word.of_int (Z.of_int x) sz)

    let tbl: (Data.Address.t, Asm.import_desc_t * Asm.calling_convention_t) Hashtbl.t = Hashtbl.create 5
    (* https://github.com/riscv/riscv-elf-psabi-doc/ *)
    (* https://github.com/riscv/riscv-elf-psabi-doc/blob/master/riscv-elf.md *)
    let integer_calling_convention = {
        return = reg "x1";
        callee_cleanup = (fun _ -> []);
        arguments =
          function
          | 0 -> reg "x10"
          | 1 -> reg "x11"
          | 2 -> reg "x12"
          | 3 -> reg "x13"
          | 4 -> reg "x14"
          | 5 -> reg "x15"
          | 6 -> reg "x16"
          | 7 -> reg "x17"
          | n ->
             let sz = !Config.operand_sz in
             M (BinOp (Add, Lval (reg "x2"), const ((n-7)*sz) sz), sz)
      }
                                
    let get_local_callconv cc =
      match cc with
      | Config.RISCVI -> integer_calling_convention
      | c -> L.abort (fun p -> p "Calling convention [%s] not supported for RISC V architecture"
                                    (Config.call_conv_to_string c))
              
    let get_callconv () = get_local_callconv !Config.call_conv

    let stub_stmts_from_name name callconv =
    if  Hashtbl.mem Stubs.stubs name then
      [ Directive (Stub (name, callconv)) ]
    else
      [ Directive (Forget (reg "x2")) ]
      
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

    let init () =
      Stubs.init();
      init_imports ()

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
          ret_addr =Lval(reg "x1");
           }
         else
           raise Not_found

  end
