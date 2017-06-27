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

  (** data type *)
type t =
  | T   (** bit is tainted *)
  | U   (** bit is untainted *)
  | TOP (** top *)
	    
let join b1 b2 =
  match b1, b2 with
  | T, T 	    -> T
  | U, U 	    -> U
  | _, _            -> TOP

let logor b1 b2 =
  match b1, b2 with
  | T, _ | _, T -> T
  | U, U 	-> U
  | _, _ 	-> TOP

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
  | TOP -> raise Exceptions.Too_many_concrete_elements
