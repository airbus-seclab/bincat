(*
  C2Newspeak: compiles C code into Newspeak. Newspeak is a minimal language 
  well-suited for static analysis.
  Copyright (C) 2007  Charles Hymans, Olivier Levillain
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.
  
  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.
  
  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

  Charles Hymans
  EADS Innovation Works - SE/CS
  12, rue Pasteur - BP 76 - 92152 Suresnes Cedex - France
  email: charles.hymans@penjili.org
*)

let to_string string_of_elt sep l =
  let rec to_string str l =
    match l with
	hd::[] -> str^(string_of_elt hd)
      | hd::tl -> to_string (str^(string_of_elt hd)^sep) tl
      | [] -> ""
  in
    to_string "" l

let merge compare l1 l2 =
  let rec merge l1 l2 =
    match (l1, l2) with
	(x::l1, y::_) when compare x y < 0 -> x::(merge l1 l2)
      | (x::_, y::l2) when compare x y > 0 -> y::(merge l1 l2)
      | (x::l1, _::l2) -> x::(merge l1 l2)
      | ([], l) | (l, []) -> l
  in
    merge l1 l2

let mapi f l =
  let rec mapi i l =
    match l with
	hd::tl -> (f i hd)::(mapi (i+1) tl)
      | [] -> []
  in
    mapi 0 l

let size_of size_of_elem l =
  List.fold_left (+) 0 (List.rev_map size_of_elem l)

let rec last = function
  | [] -> raise (Invalid_argument "last")
  | [x] -> x
  | _::tl -> last tl

let rec filter_map f = function
  |   []   -> []
  | hd::tl -> begin match f hd with
                | None   ->    filter_map f tl
                | Some v -> v::filter_map f tl
              end
