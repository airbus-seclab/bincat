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
(* x86-64 decoder *)
(***************************************************************************************)

module L = Log.Make(struct let name = "x86_64" end)
module Make(Domain: Domain.T)(Stubs: Stubs.T with type domain_t := Domain.t) =
struct

  (*  open Data *)
  include Core_x86
  open Asm
  (* open Decodeutils *)

  (************************************************************************)
  (* Creation of the registers *)
  (************************************************************************)

  (* general purpose registers *)
  let (register_tbl: (int, Register.t) Hashtbl.t) = Hashtbl.create 8;;

  let rax = Register.make ~name:"rax" ~size:64;;
  let rcx = Register.make ~name:"rcx" ~size:64;;
  let cl = P(rcx, 0, 7);;
  let rdx = Register.make ~name:"rdx" ~size:64;;
  let rbx = Register.make ~name:"rbx" ~size:64;;
  let rsp = Register.make_sp ~name:"rsp" ~size:64;;
  let rbp = Register.make ~name:"rbp" ~size:64;;
  let rsi = Register.make ~name:"rsi" ~size:64;;
  let rdi = Register.make ~name:"rdi" ~size:64;;
  let r8 = Register.make ~name:"r8" ~size:64;;
  let r9 = Register.make ~name:"r9" ~size:64;;
  let r10 = Register.make ~name:"r10" ~size:64;;
  let r11 = Register.make ~name:"r11" ~size:64;;
  let r12 = Register.make ~name:"r12" ~size:64;;
  let r13 = Register.make ~name:"r13" ~size:64;;
  let r14 = Register.make ~name:"r14" ~size:64;;
  let r15 = Register.make ~name:"r15" ~size:64;;

  List.iteri (fun i r -> Hashtbl.add register_tbl i r) [ rax ; rcx ; rdx ; rbx ; rsp ; rbp ; rsi ; rdi ; r8 ; r9 ; r10 ; r11 ; r12 ; r13 ; r14 ; r15 ]


  (* xmm registers *)
  let xmm0 = Register.make ~name:"xmm0" ~size:128;;
  let xmm1 = Register.make ~name:"xmm1" ~size:128;;
  let xmm2 = Register.make ~name:"xmm2" ~size:128;;
  let xmm3 = Register.make ~name:"xmm3" ~size:128;;
  let xmm4 = Register.make ~name:"xmm4" ~size:128;;
  let xmm5 = Register.make ~name:"xmm5" ~size:128;;
  let xmm6 = Register.make ~name:"xmm6" ~size:128;;
  let xmm7 = Register.make ~name:"xmm7" ~size:128;;
  let xmm8 = Register.make ~name:"xmm8" ~size:128;;
  let xmm9 = Register.make ~name:"xmm9" ~size:128;;
  let xmm10 = Register.make ~name:"xmm10" ~size:128;;
  let xmm11 = Register.make ~name:"xmm11" ~size:128;;
  let xmm12 = Register.make ~name:"xmm12" ~size:128;;
  let xmm13 = Register.make ~name:"xmm13" ~size:128;;
  let xmm14 = Register.make ~name:"xmm14" ~size:128;;
  let xmm15 = Register.make ~name:"xmm15" ~size:128;;

  let xmm_tbl = Hashtbl.create 7;;
  List.iteri (fun i r -> Hashtbl.add xmm_tbl i r) [ xmm0 ; xmm1 ; xmm2 ; xmm3 ; xmm4 ; xmm5 ; xmm6 ; xmm7 ; xmm8 ; xmm9 ; xmm10 ; xmm11 ; xmm12 ; xmm13 ; xmm14 ; xmm15 ];;

 

  (***********************************************************************)
  (* Creation of the flags for the mxcsr register *)
  (***********************************************************************)
  let mxcsr_fz = Register.make ~name:"mxcsr_fz" ~size:1;; (* bit 15: Flush to zero  *)
  let mxcsr_round = Register.make ~name:"mxcsr_round" ~size:2;; (* bit 13 and 14: rounding mode st:
                                                                   - bit 14:  round positive
                                                                   - bit 13 : round negative
                                                                   - bit 13 and 14 : round to zero or round to the nearest *)
  let mxcsr_pm = Register.make ~name:"mxcsr_pm" ~size:1;; (* bit 12: Precision mask *)
  let mxcsr_um = Register.make ~name:"mxcsr_um" ~size:1;; (* bit 11: Underflow mask *)
  let mxcsr_om = Register.make ~name:"mxcsr_om" ~size:1;; (* bit 10: Overflow mask *)
  let mxcsr_zm = Register.make ~name:"mxcsr_zm" ~size:1;; (* bit 9: Divide by zero mask *)
  let mxcsr_dm = Register.make ~name:"mxcsr_dm" ~size:1;; (* bit 8: Denormal mask *)
  let mxcsr_im = Register.make ~name:"mxcsr_im" ~size:1;; (* bit 7: Invalid operation mask *)
  let mxcsr_daz = Register.make ~name:"mxcsr_daz" ~size:1;; (* bit 6: Denormals are zero *)
  let mxcsr_pe = Register.make ~name:"mxcsr_pe" ~size:1;; (* bit 5: Precision flag *)
  let mxcsr_ue = Register.make ~name:"mxcsr_ue" ~size:1;; (* bit 4: Underflow flag *)
  let mxcsr_oe = Register.make ~name:"mxcsr_oe" ~size:1;; (* bit 3: Overflow flag *)
  let mxcsr_ze = Register.make ~name:"mxcsr_ze" ~size:1;; (* bit 2: Divide by zero flag *)
  let mxcsr_de = Register.make ~name:"mxcsr_de" ~size:1;; (* bit 1: Denormal flag *)
  let mxcsr_ie = Register.make ~name:"mxcsr_ie" ~size:1;; (* bit 0: Invalid operation flag *)

(** control flow automaton *)
  module Cfa = Cfa.Make(Domain)

  (** import table *)
  module Imports = X86Imports.Make(Domain)(Stubs)

  type ctx_t = unit

  let init () = Imports.init()
  let parse _text _g _is _v _a _ctx = None
end
