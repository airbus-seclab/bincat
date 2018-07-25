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

(* abstract environment for non relational domains *)
module Key =
      struct
        type t =
          | Reg of Register.t
          | Mem_Itv of Data.Address.t * Data.Address.t (* interval of addresses, from init *)
          | Mem of Data.Address.t                      (* address to single byte *)

        let compare v1 v2 =
            match v1, v2 with
            | Reg r1, Reg r2 -> Register.compare r1 r2
            | Mem addr1, Mem addr2 ->
              Data.Address.compare addr1 addr2
            | Mem addr1, Mem_Itv (m2_low, m2_high) ->
              if addr1 < m2_low then -1
              else if m2_high < addr1 then 1
              else 0
            | Mem_Itv (m1_low, m1_high), Mem addr2 ->
              if m1_high < addr2 then -1
              else if addr2 < m1_low then 1
              else 0
            | Mem_Itv (m1_low, m1_high), Mem_Itv (m2_low, m2_high) ->
              if m1_high < m2_low then -1
              else if m2_high < m1_low then 1
              else 0
            | Reg _ , _    -> 1
            | _   , _    -> -1

        let to_string x =
          match x with
          | Reg r -> Printf.sprintf "reg[%s]"  (Register.name r)
          | Mem_Itv (low_a, high_a) -> Printf.sprintf "mem[%s*%s]" (Data.Address.to_string low_a) (Z.to_string (Z.add Z.one (Data.Address.sub high_a low_a)))
          | Mem addr -> Printf.sprintf "mem[%s*1]" (Data.Address.to_string addr)
      end

 (* For Ocaml non-gurus : creates a Map type which uses MapOpt with keys of type Key *)
module Map = MapOpt.Make(Key)
include Map


(* apply f v1 v2 for every pair (k, v1), (k, v2) in m1 and m2. If k is not a key of m2 then (k, v1) is added to the result *)
let join f m1 m2 =
  let m = empty in
  let m' = fold (fun k v m -> add k v m) m1 m in
  fold (fun k v m -> try let v' = find k m1 in replace k (f v v') m with Not_found -> add k v m) m2 m'
