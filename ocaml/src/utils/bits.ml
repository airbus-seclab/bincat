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

(** convert a Z integer to its bit representation *)
let z_to_bit_string i =
  let bitstring = ref ""              in
  let two 	= Z.of_int 2          in
  let i'        = ref i               in
  while Z.compare !i' Z.zero > 0 do
    let bit = Z.rem !i' two in
    let q   = Z.div !i' two in
    if Z.equal bit Z.zero then
      bitstring := "0" ^ !bitstring
    else
      bitstring := "1" ^ !bitstring;
    i' := q
  done;
  !bitstring
       
(** convert the string representation of an integer to its bit representation *)
let string_to_bit_string i = z_to_bit_string (Z.of_string i) 
					     



(** builds 0xffff...ff with nb repetitions of the pattern ff *)
let ff nb =
  let ff = Z.of_int 0xff in
  let s = ref Z.zero in
  for _i = 1 to nb do
    s := Z.add ff (Z.shift_left !s 8)
  done;
  !s
					  
       
