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


(* set of (possible) tainting sources *)
module Src = Set.Make (
  struct

    (* type of tainting sources *) 
    type src_id = int

    (*current id for the generation of fresh taint sources *)
    let (current_id: src_id ref) = ref 0
      
    (* returns a fresh source id and increments src_id *)
    let new_src () =
      current_id := !current_id + 1;
      !current_id

    (* a value may be surely Tainted or Maybe tainted *)
    type t =
      | Tainted of src_id (** surely tainted by the given source *)
      | Maybe of src_id (** maybe tainted by then given source *)

    (* comparison between tainting sources. Returns
    - 0 is equal
    - a negative number if the first source is less than the second one
    - a positive number otherwise *)
    let compare (src1: t) (src2: t): int =
      match src1, src2 with
      | Tainted id1, Tainted id2 -> id1 - id2
      | Tainted _, _ -> -1
      | Maybe _, Tainted _ -> 1
      | Maybe id1, Maybe id2 -> id1 - id2
  end
  )

let join (t1: t) (t2: t): t =
  match t1, t2 with
  | U, U -> U
  | _, U  | U, _ -> TOP
  | S src1, S src2 -> S (Src.union src1 src2) 
  | TOP, _  | _, TOP -> TOP


let logor (t1: t) (t2: t): t =
  match t1, t2 with
  | U, U -> U
  | t, U  | U, t -> t 
  | S src1, S src2 -> S (Src.union src1 src2)
  | _, _ -> TOP
     

let logand b1 b2 =
  match b1, b2 with
  | T, T -> T
  | T, U | U, T -> U
  | U, U -> U
  | TOP, U | U, TOP -> TOP
  | TOP, _ | _, TOP -> TOP

   
let meet b1 b2 =
  match b1, b2 with
  | T, T 	     -> T
  | U, U 	    -> U
  | b, TOP | TOP, b -> b
  | U, T | T, U     -> U

let to_char b =
  match b with
  | TOP -> '?'
  | T   -> '1'
  | U   -> '0'

let to_string b =
  match b with
  | TOP -> "?"
  | T   -> "1"
  | U   -> "0"

let equal b1 b2 = b1 = b2

let binary carry t1 t2 =
  match t1, t2 with
  | TOP, _ | _, TOP -> TOP
  | T, _ | _, T     -> T
  | U, U 	    -> if carry then T else U
						    
let add = binary
let sub = binary
let xor = binary false
let neg v = v

(* finite lattice => widen = join *)
let widen = join

(* default tainting value is Untainted *)
let default = U

let untaint _t = U
let taint _t = T

let min t1 t2 =
  match t1, t2 with
  | U, t  | t, U -> t
  | T, _  | _, T -> T
  | _, _ -> TOP
     
		      
let is_tainted t =
  match t with
  | T | TOP -> true
  | _ 	    -> false

let to_z t =
  match t with
  | U -> Z.zero
  | T -> Z.one
  | _ -> raise Exceptions.Concretization
