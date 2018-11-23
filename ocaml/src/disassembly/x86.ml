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

  include Core_x86
  (************************************************************************)
  (* Creation of the registers *)
  (************************************************************************)

  (* general purpose registers *)
  let (register_tbl: (int, Register.t) Hashtbl.t) = Hashtbl.create 8;;

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
      let register_tbl = register_tbl
      let mutable_segments = false
      let ebx = ebx
      let ebp = ebp
      let esi = esi
      let edi = edi
      let edx = edx
      let eax = eax
      let ecx = ecx
      let esp = esp
    end
    module Core = Make(Arch)
    include Core
              
end
(* end Decoder *)

