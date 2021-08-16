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

(* From: PowerPC Processor ABI Supplement 
   Section "Function Calling Sequence"

Register Name Usage
r0      Volatile register which may be modified during function linkage
r1      Stack frame pointer, always valid
r2      System-reserved register
r3-r4   Volatile registers used for parameter passing and return values
r5-r10  Volatile registers used for parameter passing
r11-r12 Volatile registers which may be modified during function linkage
r13     Small data area pointer register
r14-r30 Registers used for local variables
r31     Used for local variables or "environment pointers"
f0      Volatile register
f1      Volatile register used for parameter passing and return values
f2-f8   Volatile registers used for parameter passing

Registers r1, r14 through r31, and f14 through f31 are nonvolatile;
that is, they "belong" to the calling function. A called function
shall save these registers’ values before it changes them, restoring
their values before it returns. Registers r0, r3 through r12, f0
through f13, and the special purpose registers CTR and XER are
volatile; that is, they are not preserved across function
calls. Furthermore, the values in registers r0, r11, and r12 may be
altered by cross-module calls, so a function cannot depend on the
values in these registers having the same values that were placed in
them by the caller.

Register r2 is reserved for system use and should not be changed by
application code.

Register r13 is the small data area pointer. Process startup code for
executables that reference data in the small data area with 16-bit
offset addressing relative to r13 must load the base of the small data
area (the value of the loader-defined symbol _SDA_BASE_) into
r13. Shared objects shall not alter the value in r13. See Small Data
Area in Chapter 4 for more details.

 *)



module L = Log.Make(struct let name = "powerpcImports" end)

module Make(D: Domain.T)(Stubs: Stubs.T with type domain_t := D.t) =
struct
  open Asm

  let reg r = V (T (Register.of_name r))
  let preg r x y = V (P ((Register.of_name r), x, y))

  let const x sz = Const (Data.Word.of_int (Z.of_int x) sz)

  let tbl: (Data.Address.t, import_desc_t * Asm.calling_convention_t) Hashtbl.t = Hashtbl.create 5

  let svr_calling_convention = {
    return = reg "r3" ;
    callee_cleanup = (fun _x -> []) ;
    arguments = function
    | 0 -> reg "r3"
    | 1 -> reg "r4"
    | 2 -> reg "r5"
    | 3 -> reg "r6"
    | 4 -> reg "r7"
    | 5 -> reg "r8"
    | 6 -> reg "r9"
    | 7 -> reg "r10"
    | 8 -> M (Lval (reg "r1"), 32)
    | n -> M ((BinOp (Add, Lval (reg "r1"), const ((n-8)*4) 32)), 32) ;
  }

  let get_local_callconv cc =
    match cc with
    | Config.SVR -> svr_calling_convention
    | c -> L.abort (fun p -> p "Calling convention [%s] not supported for PowerPC architecture"
                               (Config.call_conv_to_string c))

  let get_callconv () = get_local_callconv !Config.call_conv

  let typing_rule_stmts_from_name name =
    try
      let _rule = Hashtbl.find Config.typing_rules name in
      [], []
    with
    | _ -> [], []

  let stub_stmts_from_name name callconv=
    if  Hashtbl.mem Stubs.stubs name then
      [
        Directive (Stub (name, callconv)) ;
        Directive (Forget (reg "r4")) ;
        Directive (Forget (reg "r5")) ;
        Directive (Forget (reg "r6")) ;
        Directive (Forget (reg "r7")) ;
        Directive (Forget (reg "r8")) ;
        Directive (Forget (reg "r9")) ;
        Directive (Forget (reg "r10")) ;
        Directive (Forget (reg "r11")) ;
        Directive (Forget (reg "r12")) ;
      ]
    else
      [
        Directive (Forget (reg "r3")) ;
        Directive (Forget (reg "r4")) ;
        Directive (Forget (reg "r5")) ;
        Directive (Forget (reg "r6")) ;
        Directive (Forget (reg "r7")) ;
        Directive (Forget (reg "r8")) ;
        Directive (Forget (reg "r9")) ;
        Directive (Forget (reg "r10")) ;
        Directive (Forget (reg "r11")) ;
        Directive (Forget (reg "r12")) ;
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
            ret_addr = Lval(reg "lr") ;
          } in
        Hashtbl.replace tbl (Data.Address.global_of_int adrs) (fundesc, cc')
      ) Config.import_tbl



  (** check if fdesc (import description) or a (address) should be skipped
   *  raise Not_found if not
   *  else
   *    return either a 
   *      - *patched* fdesc (stub replaced with 'Skip')
   *      - new minimal fdesc to Skip
   * *)
  let skip fdesc a =
      match fdesc with
      | Some (fdesc', cc) ->
         if Hashtbl.mem Config.funSkipTbl (Config.Fun_name fdesc'.Asm.name) then
           let stmts = [Directive (Skip (Asm.Fun_name fdesc'.Asm.name, cc))]  in
           (* replace stub statements *)
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
          epilogue = [Directive (Skip (Asm.Fun_addr a, get_callconv())) ;] ;
          ret_addr =BinOp(And, Lval(reg "lr"), const 0xfffffffe 32) ;
           }
         else
           raise Not_found

  let init () =
    Stubs.init ();
    init_imports ()


end
