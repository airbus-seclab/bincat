(*
    This file is part of BinCAT.
    Copyright 2014-2020 - Airbus

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

(* data type tainting source *)
module Src =
  struct

    (* type of tainting sources *)
    type id_t = int

    (*current id for the generation of fresh taint sources *)
    let (current_id: id_t ref) = ref 0

    let new_src (): id_t =
      current_id := !current_id + 1;
      !current_id

    let clear () =
      current_id := 0

    (* a value may be surely Tainted or Maybe tainted *)
    type t =
      | Tainted of id_t (** surely tainted by the given source *)
      | Maybe of id_t (** maybe tainted by then given source *)


    (* comparison between tainting sources. Returns
    - 0 is equal
    - a negative number if the first source is less than the second one
    - a positive number otherwise *)
    let compare (src1: t) (src2: t): int =
      match src1, src2 with
      | Tainted id1, Tainted id2 -> id1 - id2
      | Tainted id1, Maybe id2 -> id1 - id2
      | Maybe id1, Maybe id2 -> id1 - id2
      | Maybe id1, Tainted id2 -> if id1 = id2 then 1 else id1 - id2

    let to_string src =
      match src with
      | Tainted id -> "t-"^(string_of_int id)
      | Maybe id -> "m-"^(string_of_int id)
  end

(* set of (possible) tainting sources *)
module SrcSet = SetExt.Make(Src)


(* a taint value can be
   - undefined (BOT)
   - untainted (U)
   - or a set (S) of (possible) tainting sources
   - or an unknown taint (TOP) *)
type t =
  | BOT
  | U
  | S of SrcSet.t
  | TOP

let total_order t1 t2 =
  (* BOT < TOP < U < S *)
  match t1, t2 with
  | BOT, BOT | TOP, TOP | U, U -> 0
  | S src1, S src2 ->
     let n1 = SrcSet.cardinal src1 in
     let n2 = SrcSet.cardinal src2 in
     let n = n1-n2 in
     if n <> 0 then n1
     else SrcSet.compare src1 src2   
  | BOT, _ -> -1
  | TOP, _ -> -1
  | U, _ -> -1
  | _, _ -> 1
          
let is_subset t1 t2 =
  match t1, t2 with
  | BOT, _
  | _, TOP
  | U, U -> true
  | S s1, S s2 when SrcSet.subset s1 s2 = true -> true
  | _, _ -> false

let clear = Src.clear

let new_src = Src.new_src

let singleton src = S (SrcSet.singleton src)

let join_predicate v1 v2 =
  match v1, v2 with
  | Src.Tainted id1, Src.Maybe id2 when id1 = id2 -> Some (Src.Maybe id1)
  | Src.Maybe id1, Src.Tainted id2 when id1 = id2 -> Some (Src.Maybe id1)
  | Src.Tainted id1, Src.Tainted id2 when id1 = id2 -> Some v1
  | Src.Maybe id1, Src.Maybe id2 when id1 = id2 -> Some v1
  | _, _ -> None

let join (t1: t) (t2: t): t =
  match t1, t2 with
  | BOT, t | t, BOT -> t
  | U, U -> U
  | _, U  | U, _ -> TOP
  | S src1, S src2 -> S (SrcSet.union_on_predicate join_predicate src1 src2)
  | TOP, _  | _, TOP -> TOP

let logor (t1: t) (t2: t): t =
  match t1, t2 with
  | BOT, t | t, BOT -> t
  | U, U -> U
  | t, U  | U, t -> t
  | S src1, S src2 -> S (SrcSet.union_on_predicate join_predicate src1 src2)
  | _, _ -> TOP

let inter_predicate v1 v2 =
  match v1, v2 with
  | Src.Tainted id1, Src.Maybe id2 when id1 = id2 -> Some (Src.Tainted id1)
  | Src.Maybe id1, Src.Tainted id2 when id1 = id2 -> Some (Src.Tainted id1)
  | Src.Tainted id1, Src.Tainted id2 when id1 = id2 -> Some v1
  | Src.Maybe id1, Src.Maybe id2 when id1 = id2 -> Some v1
  | _, _ -> None

let logand (t1: t) (t2: t): t =
  match t1, t2 with
  | BOT, t | t, BOT -> t
  | U, U -> U
  | _, U | U, _ -> U
  | S src1, S src2 ->
     let src' = SrcSet.inter_on_predicate inter_predicate src1 src2 in
     if SrcSet.is_empty src' then U
     else S src'
  | S src, TOP | TOP, S src -> S src
  | TOP, TOP -> TOP



let meet (t1: t) (t2: t): t =
  match t1, t2 with
  | BOT, _ | _, BOT -> BOT
  | S _, U | U, S _ -> BOT
  | U, U -> U
  | U, TOP | TOP, U -> U
  | S src1, S src2 -> S (SrcSet.inter_on_predicate inter_predicate src1 src2)
  | S src, TOP | TOP, S src -> S src
  | TOP, TOP -> TOP

let to_char (t: t): char =
  match t with
  | BOT -> '_'
  | TOP -> '?'
  | S srcs ->
     let elts = SrcSet.elements srcs in
     if List.for_all (fun src -> match src with | Src.Tainted _ -> true | Src.Maybe _ -> false) elts then
       '1'
     else '?'
  | U -> '0'

let equal (t1: t) (t2: t): bool =
  match t1, t2 with
  | U, U -> true
  | TOP, _ | _, TOP -> true
  | S src1, S src2 -> SrcSet.compare src1 src2 = 0
  | _, _ -> false

let binary (carry: t option) (t1: t) (t2: t): t =
  match t1, t2 with
  | BOT, _ | _, BOT -> BOT
  | TOP, _ | _, TOP -> TOP
  | t, U | U, t ->
     begin
       match carry with
       | None -> t
       | Some csrc -> join csrc t
     end

  | S src1, S src2 ->
     let src' = SrcSet.union src1 src2 in
     begin
       match carry with
       | None -> S src'
       | Some csrc -> join csrc (S src')
     end

let add = binary
let sub = binary
let xor = binary None
let neg v = v

(* finite lattice => widen = join *)
let widen = join

(* default tainting value is Untainted *)
let default = U

let untaint (_t: t): t = U
let taint (t: t): t = t

let min (t1: t) (t2: t): t =
  match t1, t2 with
  | BOT, t | t, BOT -> t
  | U, t  | t, U -> t
  | S src, TOP  | TOP, S src -> S src
  | S src1, S src2 -> if SrcSet.compare src1 src2 <= 0 then t1 else t2
  | TOP, TOP -> TOP

let is_tainted (t: t): bool =
  match t with
  | S _ | TOP -> true
  | U       -> false
  | BOT     -> false

let to_z (t: t): Z.t =
  match t with
  | U -> Z.zero
  | S srcs when SrcSet.cardinal srcs = 1 ->
     begin
       match SrcSet.choose srcs with
          | Src.Tainted _ -> Z.one
          | Src.Maybe _ -> raise (Exceptions.Too_many_concrete_elements "Taint.to_z")
     end
  | _ -> raise (Exceptions.Too_many_concrete_elements "Taint.to_z")

let to_string t =
  match t with
  | BOT -> "_"
  | U -> ""
  | TOP -> "?"
  | S srcs ->
     SrcSet.fold (fun src acc -> (Src.to_string src)^", "^acc) srcs ""

module Set = Set.Make (struct type aux_t = t type t = aux_t let compare = total_order end) 

let string_of_set s =
  let s' = Set.fold (fun s acc -> logor s acc) s U in
  to_string s'

