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
  | ZERO   (** zero *)
  | ONE   (** one *)
  | TOP (** top *)
       		     
let join b1 b2 =
  match b1, b2 with
  | ZERO, ZERO 	    	  -> ZERO
  | ONE, ONE 	    	  -> ONE
  | ONE, ZERO | ZERO, ONE -> ONE
  | _, _ 	    	  -> TOP
			 
let meet b1 b2 =
  match b1, b2 with
  | ZERO, ZERO 	    	  -> ZERO
  | ONE, ONE 	    	  -> ONE
  | ONE, ZERO | ZERO, ONE -> raise Exceptions.Empty
  | _, TOP | TOP, _ 	  -> TOP
			       
let to_char b =
  match b with
  | TOP  -> '?'
  | ZERO -> '0'
  | ONE  -> '1'

let to_string b =
  match b with
  | TOP  -> "?"
  | ZERO -> "0"
  | ONE  -> "1"

let equal b1 b2 =
  match b1, b2 with
  | TOP, _ | _, TOP 
  | ZERO, ZERO | ONE, ONE -> true
  | _, _ -> false 
			 
let add b1 b2 =
  match b1, b2 with
  | TOP, ZERO | ZERO, TOP -> TOP, false
  | TOP, _ | _, TOP 	  -> TOP, true
  | ZERO, ZERO 	    	  -> ZERO, false
  | ZERO, ONE | ONE, ZERO -> ONE, false
  | ONE, ONE 	    	  -> ZERO, true

let sub b1 b2 =
  match b1, b2 with
  | ONE, TOP | TOP, ZERO -> TOP, false
  | _, TOP | TOP, _ -> TOP, true
  | ZERO, ZERO 	    -> ZERO, false
  | ZERO, ONE       -> ONE, true
  | ONE, ZERO       -> ONE, false
  | ONE, ONE 	    -> ZERO, false
								
let xor b1 b2 =
  match b1, b2 with
  | TOP, _ | _, TOP 	  -> TOP
  | ZERO, ZERO 	    	  -> ZERO
  | ZERO, ONE | ONE, ZERO -> ONE
  | ONE, ONE 	    	  -> ZERO
			 
let lognot v =
  match v with
  | TOP  -> TOP
  | ZERO -> ONE
  | ONE  -> ZERO
		     
(* finite lattice => widen = join *)
let widen = join

let logand v1 v2 =
  match v1, v2 with
  | ZERO, _ | _, ZERO -> ZERO
  | ONE, ONE -> ONE
  | _, _ -> TOP

let logor v1 v2 =
  match v1, v2 with
  | ONE, _ | _, ONE -> ONE
  | ZERO, ZERO -> ZERO  
  | _, _ -> TOP
     
(* conversion to Z.t. May raise an exception if the conversion fails *)
let to_z v =
  match v with
  | TOP  -> raise Exceptions.Concretization
  | ZERO -> Z.zero
  | ONE  -> Z.one

let to_int v =
  match v with
  | TOP  -> raise Exceptions.Concretization
  | ZERO -> 0
  | ONE  -> 1
    
let eq v1 v2 =
  match v1, v2 with
  | TOP, _ | _, TOP 	      -> true
  | ZERO, ZERO | ONE, ONE     -> true
  | _, _ 	    	      -> false
			 
let neq v1 v2 =
  match v1, v2 with
  | TOP, _ | _, TOP 	      -> true
  | ZERO, ZERO | ONE, ONE     -> false
  | _, _ 	    	      -> true
			 
let leq v1 v2 =
  match v1, v2 with
  | ONE, ZERO -> false
  | _, _      -> true
			    
let lt v1 v2 =
  match v1, v2 with
  | ONE, _ | _, ZERO -> false
  | _, _             -> true
			 
let geq v1 v2 =
  match v1, v2 with
  | ZERO, ONE -> false
  | _, _      -> true
			    
let gt v1 v2 =
  match v1, v2 with
  | _, ONE | ZERO, _ -> false
  | _, _ 	     -> true

		       
let compare v1 op v2 =
  match op with
  | Asm.EQ  -> eq v1 v2
  | Asm.NEQ -> neq v1 v2
  | Asm.LEQ -> leq v1 v2
  | Asm.GEQ -> geq v2 v1
  | Asm.LT  -> lt v1 v2
  | Asm.GT  -> gt v1 v2
		  
let is_subset v1 v2 = eq v1 v2
