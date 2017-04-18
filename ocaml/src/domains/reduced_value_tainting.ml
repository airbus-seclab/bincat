(*
    This file is part of BinCAT.
    Copyright 2014-2017 - Airbus Group

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

module V = Value
module T = Tainting

type t = V.t * T.t

let top = V.TOP, T.TOP

let forget (_v, t) = V.TOP, t
  
let is_top (v, _t) = v = V.TOP

let to_z (v, _t) = V.to_z v

let to_int (v, _t) = V.to_int v

let forget_taint (v, _t) = v, T.TOP

let join (v1, t1) (v2, t2) = V.join v1 v2, T.join t1 t2

let meet (v1, t1) (v2, t2) = V.meet v1 v2, T.meet t1 t2

let xor (v1, t1) (v2, t2) = V.xor v1 v2, T.logor t1 t2

let core_sub_add op (v1, t1) (v2, t2) =
  let v', b = op v1 v2      in
  let t'    = T.logor t1 t2 in
  if b then
    (* overflow is propagated to tainting *)
    (v', t'), Some (V.ONE, t')
  else
    (v', t'), None

let add (v1, t1) (v2, t2) = core_sub_add V.add (v1, t1) (v2, t2)

let sub (v1, t1) (v2, t2) = core_sub_add V.sub (v1, t1) (v2, t2)

(* be careful: never reduce during widening *)
let widen (v1, t1) (v2, t2) = V.widen v1 v2, T.widen t1 t2

let to_char (v, _t) = V.to_char v

let to_string (v, _t) = V.to_string v 

let string_of_taint (_v, t) = T.to_string t

let char_of_taint (_v, t) = T.to_char t

let untaint (v, t) = v, T.untaint t
let taint (v, t) = v, T.taint t
let update_taint t' (v, _) = v, t'

let compare (v1, _t1) op (v2, _t2) = V.compare v1 op v2

let get_taint (_, t) = t

let one = V.ONE, T.U
let is_one (v, _t) = v = V.ONE

let zero = V.ZERO, T.U
let is_zero (v, _t) = v = V.ZERO

let subset (v1, _t1) (v2, _t2) = V.subset v1 v2

let of_z z =
  if Z.compare z Z.zero = 0 then
    V.ZERO, T.U
  else
    if Z.compare z Z.one = 0 then
      V.ONE, T.U
    else
      V.TOP, T.U

let taint_of_z z (v, _t) =
  let t' =
  if Z.compare Z.zero z = 0 then T.U
  else
    if Z.compare Z.one z = 0 then T.T
    else T.TOP
  in
  v, t'

let taint_to_z (_, t) = T.to_z t

let equal (v1, _) (v2, _) = V.equal v1 v2

let geq (v1, _) (v2, _) = V.geq v1 v2

let lt (v1, _) (v2, _) = V.lt v1 v2

let lognot (v, t) = V.lognot v, t

let logor (v1, t1) (v2, t2) = match (v1, t1), (v2, t2) with
  | _, (V.ONE, T.U) -> V.ONE, T.U
  | (V.ONE, T.U), _ -> V.ONE, T.U
  | (v1, t1), (v2, t2) -> V.logor v1 v2, T.logor t1 t2

let logand (v1, t1) (v2, t2) = match (v1, t1), (v2, t2) with
  | _, (V.ZERO, T.U) -> V.ZERO, T.U
  | (V.ZERO, T.U), _ -> V.ZERO, T.U
  | (v1, t1), (v2, t2) -> V.logand v1 v2, T.logor t1 t2

let is_tainted (_v, t) = T.is_tainted t
