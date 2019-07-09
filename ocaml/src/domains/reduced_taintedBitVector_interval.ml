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
module I = IntervalDomain

type t = V.t * I.t

let top sz = V.top sz, I.top sz
        
let size (v, i) =
  let v_sz = V.size v in
  let i_sz = I.size i in
  if v_sz = i_sz then
    v_sz
  else
    raise (Exceptions.Error "incompatible size betwen bit vectors and Byte")

let forget (v, i) opt = V.forget v opt, I.forget i opt
let join (v1, i1) (v2, i2) = V.join v1 v2, I.join i1 i2
let widen (v1, i1) (v2, i2) = V.widen v1 v2, I.widen i1 i2
let taint (v, i) = V.taint v, i
let untaint (v, i) = V.untaint v, i
let taint_sources (v, _i) = V.taint_sources v
let of_word w = V.of_word w, I.of_word w
              
let to_char (v, i) =
  try
    V.to_char v
  with _ -> I.to_char i
          
let to_z (v, i) =
  try
    V.to_z v
  with _ -> I.to_z i

let get_minimal_taint (v, _i) = V.get_minimal_taint v

let meet (v1, i1) (v2, i2) = V.meet v1 v2, I.meet i1 i2

let is_subset (v1, i1) (v2, i2) = V.is_subset v1 v2 && I.is_subset i1 i2

let taint_of_config taints n (prev: t option): t * Taint.t =
  let vprev, i'=
    match prev with
    | Some (v', i') -> Some v', i'
    | None -> None, I.top n
  in
  let v', taint = V.taint_of_config taints n vprev in
  (v', i'), taint

let to_string (v, i) = (V.to_string v) ^ (I.to_string i)

let to_strings (v, i) =
  let v_str, taint_str = V.to_strings v in
  let i_str = I.to_string i in
  i_str^v_str, taint_str

let concat (v1, i1) (v2, i2) = V.concat v1 v2, I.concat i1 i2
let span_taint (v, i) t = V.span_taint v t, i
let unary op (v, i) = V.unary op v, I.unary op i 
let binary op (v1, i1) (v2, i2) = V.binary op v1 v2, I.binary op i1 i2
let compare (v1, i1) cmp (v2, i2) = V.compare v1 cmp v2 && I.compare i1 cmp i2

let to_addresses r (v, i) =
  let vaddresses = V.to_addresses r v in
  let iaddresses = I.to_addresses r i in
  Data.Address.Set.inter vaddresses iaddresses

let extract (v, i) low up = V.extract v low up, I.extract i low up
let combine (v1, i1) (v2, i2) low up = V.combine v1 v2 low up, I.combine i1 i2 low up
let of_repeat_val (v, i) len nb = V.of_repeat_val v len nb, I.of_repeat_val i len nb
let from_position (v, i) l len = V.from_position v l len, I.from_position i l len

let of_config c n = V.of_config c n, I.of_config c n
