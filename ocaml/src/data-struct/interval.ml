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
         
type lower_bound = Z.t option (* None is -oo *)
type upper_bound = Z.t option  (* None is oo *)
                               
type t = lower_bound * upper_bound

let inf = None, None

let string_of_bound b sign =
  match b with
  | None -> sign ^ "oo"
  | Some z -> Z.format "%#x" z
            
let to_string (l, u) =
  Printf.sprintf "[%s ; %s]" (string_of_bound l "-") (string_of_bound u "+")

let lower_singleton v = v, None

let upper_singleton v = None, v

let of_bounds l u = Some l, Some u
                  
let equal (l1, u1) (l2, u2) =
  match l1, u1, l2, u2 with
  | Some l1, Some u1, Some l2, Some u2 -> Z.compare l1 l2 = 0 && Z.compare u1 u2 = 0
  | _ -> false

let lower_bound i = fst i
                  
let upper_bound i = snd i

let less_lower_bound b1 b2 cmp =
  match b1, b2 with
  | None, _ -> true
  | Some z1, Some z2 -> cmp (Z.compare z1 z2)
  | _ -> false

let less_upper_bound b1 b2 cmp =
  match b1, b2 with
  | _, None -> true
  | Some z1, Some z2 -> cmp (Z.compare z1 z2)
  | _ -> false

let icontains (l1, u1) (l2, u2) cmp =
  less_lower_bound l2 l1 cmp && less_upper_bound u1 u2 cmp
  
let strict_contains i1 i2 =
  L.debug2 (fun p -> p "%s < %s ?" (to_string i1) (to_string i2));
  let cmp = fun e -> e < 0 in
  icontains i1 i2 cmp

let contains i1 i2  =
  L.debug2 (fun p -> p "%s <= %s ?" (to_string i1) (to_string i2));
  let cmp = fun e -> e <= 0 in
  icontains i1 i2 cmp
