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


module L = Log.Make(struct let name = "interval" end)
         
type bound = Z.t
type t = bound * bound

let to_string (l, u) =
  Printf.sprintf "[ %s ; %s ]" (Z.to_string l) (Z.to_string u)

let singleton v = v, v

let equal (l1, u1) (l2, u2) = Z.compare l1 l2 = 0 && Z.compare u1 u2 = 0 

let lower_bound i = fst i
                  
let upper_bound i = snd i

let is_included (l1, u1) (l2, u2) = Z.compare l1 l2 <= 0 && Z.compare u1 u2 <= 0
