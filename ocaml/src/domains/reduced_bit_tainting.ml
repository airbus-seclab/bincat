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

(** reduced product between Value and Tainting *)
(** its signature is Vector.Value_domain *)

module L = Log.Make(struct let name = "reduced_bit_tainting" end)

module B = Bit
module T = Taint

type t = B.t * T.t

let top = B.TOP, T.TOP

let forget (_v, _t) = B.TOP, T.TOP

let is_top (v, _t) = v = B.TOP

let to_z (v, _t) = B.to_z v

let to_int (v, _t) = B.to_int v

let forget_taint_src (v, _t) tid = v, T.singleton (T.Src.Maybe tid)

let join (v1, t1) (v2, t2) = B.join v1 v2, T.join t1 t2

let taint_logor (v, t1) (_, t2) = v, T.logor t1 t2
  
let meet (v1, t1) (v2, t2) = B.meet v1 v2, T.meet t1 t2

let xor (v1, t1) (v2, t2) = B.xor v1 v2, T.logor t1 t2

let core_sub_add op (v1, t1) (v2, t2) =
  let res, carry = op v1 v2  in
  let res_taint  = T.logor t1 t2 in
  let res_carry =
    match carry, res_taint with
    | B.ZERO, _   -> None
    | B.ONE, t    -> Some (B.ONE, t)
    | B.TOP, T.U  -> Some (B.TOP, T.U)
    | B.TOP, _    -> Some (B.TOP, T.TOP)
  in
  (res, res_taint), res_carry

let add (v1, t1) (v2, t2) = core_sub_add B.add (v1, t1) (v2, t2)

let sub (v1, t1) (v2, t2) = core_sub_add B.sub (v1, t1) (v2, t2)

(* be careful: never reduce during widening *)
let widen (v1, t1) (v2, t2) = B.widen v1 v2, T.widen t1 t2

let to_char (v, _t) = B.to_char v

let to_string (v, _t) = B.to_string v

let string_of_taint (_v, t) = T.to_string t

let char_of_taint (_v, t) = T.to_char t

let untaint (v, t) = v, T.untaint t
let taint (v, t) = v, T.taint t
let update_taint t' (v, _) = v, t'
let set_bit (_, t) = B.ONE, t
let clear_bit (_, t) = B.ZERO, t
let update_bit v' (_, t) = v', t

let compare (v1, _t1) op (v2, _t2) = B.compare v1 op v2

let get_taint (_, t) = t

let one = B.ONE, T.U
let is_one (v, _t) = v = B.ONE

let zero = B.ZERO, T.U
let is_zero (v, _t) = v = B.ZERO

let is_subset (v1, t1) (v2, t2) = B.is_subset v1 v2 && T.is_subset t1 t2

let of_z z =
  if Z.compare z Z.zero = 0 then
    B.ZERO, T.U
  else
    if Z.compare z Z.one = 0 then
      B.ONE, T.U
    else
      B.TOP, T.U

let taint_of_z z (v, _t) tid =
  let t' =
  if Z.compare Z.zero z = 0 then T.U
  else
    if Z.compare Z.one z = 0 then T.singleton (T.Src.Tainted tid)
    else T.singleton (T.Src.Maybe tid)
  in
  v, t'

let taint_to_z (_, t) = T.to_z t

let equal (v1, _) (v2, _) = B.equal v1 v2

let geq (v1, _) (v2, _) = B.geq v1 v2

let lt (v1, _) (v2, _) = B.lt v1 v2

let lt_multibit_helper (v1, _) (v2, _) = B.lt_multibit_helper v1 v2

let lognot (v, t) = B.lognot v, t

let logor (v1, t1) (v2, t2) =
  match (v1, t1), (v2, t2) with
  | _, (B.ONE, T.U) -> B.ONE, T.U
  | (B.ONE, T.U), _ -> B.ONE, T.U
  | (v1, t1), (v2, t2) -> B.logor v1 v2, T.logor t1 t2

let logand (v1, t1) (v2, t2) =
  match (v1, t1), (v2, t2) with
  | _, (B.ZERO, T.U) -> B.ZERO, T.U
  | (B.ZERO, T.U), _ -> B.ZERO, T.U
  | (v1, t1), (v2, t2) -> B.logand v1 v2, T.logor t1 t2

let is_tainted (_v, t) = T.is_tainted t

let forget_taint (v, _) = v, Taint.TOP
