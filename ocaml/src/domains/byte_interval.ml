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

module L = Log.Make(struct let name = "byte_interval" end)

type t =
  | BOT
  | I of int * int (* lower bound, upper bound *)

let lbound = 0
let ubound = 255
let top = lbound, ubound
let size _ = 8
let forget _ = top

let normalize l u =
  let l' = if l < lbound then lbound else l in
  let u' = if u > ubound then ubound else u in
  l', u'
  
let join (l1, u1) (l2, u2) =
  let l = min l1 l2 in
  let u = max u1 u2 in
  normalize l u

let widen (l1, u1) (l2, u2) =
  let l' = if l2 < l1 then lbound else l2 in
  let u' = if u1 < u2 then ubound else u2 in
  l', u'
