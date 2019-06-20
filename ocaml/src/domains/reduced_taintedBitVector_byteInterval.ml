(*
    This file is part of BinCAT.
    Copyright 2014-2019 - Airbus

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

module L = Log.Make(struct let name = "reduced_taintedBitVector_byteInterval" end)
module V = Vector.Make(Reduced_bit_tainting)
module B = Byte_interval

type t = V.t * B.t

let top = V.top, B.top
        
let size (v, b) =
  let v_sz = V.size v in
  let b_sz = B.size b in
  if v_sz = b_sz then
    v_sz
  else
    raise (Exceptions.Error "incompatible size betwen bit vectors and Byte")

let forget (v, b) = V.forget v, B.forget b
let join (v1, b1) (v2, b2) = V.join v1 v2, B.join b1 b2
let widen (v1, b1) (v2, b2) = V.widen v1 v2, B.widen b1 b2
let taint (v, b) = V.taint v, b
let untaint (v, b) = V.untaint v, b
let taint_sources (v, _b) = V.taint_sources v
let to_z (v, b) =
  try
    V.to_z v
  with _ -> B.to_z b
