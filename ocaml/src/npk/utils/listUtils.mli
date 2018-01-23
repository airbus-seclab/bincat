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

val to_string: ('a -> string) -> string -> 'a list -> string

(** Contrarily to ocaml List.merge ignores duplicates *)
val merge: ('a -> 'a -> int) -> 'a list -> 'a list -> 'a list

val mapi: (int -> 'a -> 'b) -> 'a list -> 'b list

val size_of: ('a -> int) -> 'a list -> int

(**
 * Return the last element in a list in O(length) operarations.
 * Twice as fast as List.nth l ((List.length l) - 1)
 * @raise Invalid_argument "last" if its argument is []
 *)
val last : 'a list -> 'a

(**
 * Like List.map, but filter out the None elements.
 *)
val filter_map : ('a -> 'b option) -> 'a list -> 'b list
