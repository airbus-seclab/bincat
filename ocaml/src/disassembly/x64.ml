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


module Make(Domain: Domain.T)(Stubs: Stubs.T with type domain_t := Domain.t) =
struct

  include Core_x86

  (* open Decodeutils *)

  (************************************************************************)
  (* Creation of the registers *)
  (************************************************************************)

  (* general purpose registers *)
  let (register_tbl: (int, Register.t) Hashtbl.t) = Hashtbl.create 8;;

  let rax = Register.make ~name:"rax" ~size:64;;
  let rcx = Register.make ~name:"rcx" ~size:64;;
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

  List.iteri (fun i r -> Hashtbl.add register_tbl i r) [ rax ; rcx ; rdx ; rbx ; rsp ; rbp ; rsi ; rdi ; r8 ; r9 ; r10 ; r11 ; r12 ; r13 ; r14 ; r15 ];;


  (* x64-only xmm registers *)
  let xmm8 = Register.make ~name:"xmm8" ~size:128;;
  let xmm9 = Register.make ~name:"xmm9" ~size:128;;
  let xmm10 = Register.make ~name:"xmm10" ~size:128;;
  let xmm11 = Register.make ~name:"xmm11" ~size:128;;
  let xmm12 = Register.make ~name:"xmm12" ~size:128;;
  let xmm13 = Register.make ~name:"xmm13" ~size:128;;
  let xmm14 = Register.make ~name:"xmm14" ~size:128;;
  let xmm15 = Register.make ~name:"xmm15" ~size:128;;

  List.iteri (fun i r -> Hashtbl.add xmm_tbl i r) [ xmm8 ; xmm9 ; xmm10 ; xmm11 ; xmm12 ; xmm13 ; xmm14 ; xmm15 ];;


  module Arch =
    struct
      module Domain = Domain
      module Stubs = Stubs
      let register_tbl = register_tbl
      let mutable_segments = false
      let ebx = rbx
      let ebp = rbp
      let esi = rsi
      let edi = rdi
      let edx = rdx
      let eax = rax
      let ecx = rcx
      let esp = rsp
    end
  module Core = Make (Arch)
  include Core

end
