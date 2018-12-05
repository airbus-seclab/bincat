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

(***************************************************************************************)
(* x86 decoder *)
(***************************************************************************************)


module Make(Domain: Domain.T)(Stubs: Stubs.T with type domain_t := Domain.t) =
struct

  open Asm
  open Data
  open Decodeutils
  include Core_x86
  (************************************************************************)
  (* Creation of the registers *)
  (************************************************************************)


  let eax = Register.make ~name:"eax" ~size:32;;
  let ecx = Register.make ~name:"ecx" ~size:32;;
  let edx = Register.make ~name:"edx" ~size:32;;
  let ebx = Register.make ~name:"ebx" ~size:32;;
  let esp = Register.make_sp ~name:"esp" ~size:32;;
  let ebp = Register.make ~name:"ebp" ~size:32;;
  let esi = Register.make ~name:"esi" ~size:32;;
  let edi = Register.make ~name:"edi" ~size:32;;

  Hashtbl.add register_tbl 0 eax;;
  Hashtbl.add register_tbl 1 ecx;;
  Hashtbl.add register_tbl 2 edx;;
  Hashtbl.add register_tbl 3 ebx;;
  Hashtbl.add register_tbl 4 esp;;
  Hashtbl.add register_tbl 5 ebp;;
  Hashtbl.add register_tbl 6 esi;;
  Hashtbl.add register_tbl 7 edi;;

    module Arch =
    struct
      module Domain = Domain
      module Stubs = Stubs
      module Imports = X86Imports.Make(Domain)(Stubs)
      let ebx = ebx
      let ebp = ebp
      let esi = esi
      let edi = edi
      let edx = edx
      let eax = eax
      let ecx = ecx
      let esp = esp
      let decode_from_0x40_to_0x4F c sz =
        let stmts =
          match c with
          | c when '\x40' <= c && c <= '\x47' -> (* INC *) let r = find_reg ((Char.code c) - 0x40) sz in core_inc_dec (V r) Add sz
          | _ -> (* DEC *) let r = find_reg ((Char.code c) - 0x48) sz in core_inc_dec (V r) Sub sz
        in
        S stmts
        
      let get_rex _c = None
      let default_segmentation = false
      let get_base_address segments rip c =
          if !Config.mode = Config.Protected then
              let dt = if c.ti = GDT then segments.gdt else segments.ldt in
              try
                  let e = Hashtbl.find dt c.index in
                  if c.rpl <= e.dpl then
                      e.base
                  else
                      error rip "illegal requested privileged level"
              with Not_found ->
                  error rip (Printf.sprintf "illegal requested index %s in %s Description Table" (Word.to_string c.index) (if c.ti = GDT then "Global" else "Local"))
          else
              error rip "only protected mode supported"

      let add_segment segments operand_sz rip offset sreg =
          let seg_reg_val = Hashtbl.find segments.reg sreg in
          let base_val = get_base_address segments rip seg_reg_val        in
          if Z.compare base_val Z.zero = 0 then
              offset
          else
              BinOp(Add, offset, const_of_Z base_val operand_sz)
    end
    module Core = Make(Arch)
    include Core
              
end
(* end Decoder *)

