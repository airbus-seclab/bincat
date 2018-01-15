(*
    This file is part of BinCAT.
    Copyright 2014-2018 - Airbus Group

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

type status =
  | A (* allocated *)
  | F (* freed *)
  | TOP (* unknown status *)

let string_of_status s =
  match s with
  | A -> "A"
  | F -> "F"
  | TOP -> "?"
     
let leq s1 s2 =
  match s1, s2 with
  | A, A
  | F, F
  | A, TOP
  | F, TOP -> true
  | _, _ -> false
     
module Key =
struct
  type t = Data.Address.heap_id_t
  let compare = compare
end
  
module Map = MapOpt.Make(Key) (* a key not in the map means its value is BOT *)
  
type t =
  | BOT
  | Val of status Map.t

let init () = Val (Map.empty)

let forget m =
  match m with
  | BOT -> BOT
  | Val m' -> Val (Map.map (fun _ -> TOP) m')

let is_bot m = m = BOT

let is_subset m1 m2 =
  match m1, m2 with
  | BOT, _ -> true
  | _, BOT -> false
  | Val m1', Val m2' ->
     try
       Map.iteri (fun k v1 ->
         try
           let v2 = Map.find k m2' in
           if not (leq v1 v2) then
             raise Exit
         with Not_found -> raise Exit) m1';
       true
     with Exit -> false

let to_string m =
  match m with
  | BOT -> ["_"]
  | Val m' ->
     Map.fold (
       fun addr_id status acc ->
         let status' = string_of_status status in
         let _, sz = Data.Address.get_heap_region addr_id in
     ("H["^(string_of_int addr_id)^":"^(Z.to_string sz)^"]="^status')::acc
     ) m' []

let is_allocated m addr =
  match m with
  | BOT -> false
  | Val m' ->
     try
       match addr with
       | Data.Address.Heap (id, _) ->
          let status = Map.find m' id in
          if status = A then true else false
       | _ -> true
     with _ -> false
