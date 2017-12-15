(*
  C2Newspeak: compiles C code into Newspeak. Newspeak is a minimal language 
  well-suited for static analysis.
  Copyright (C) 2007, 2011  Charles Hymans, Olivier Levillain, Sarah Zennou
  
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

  Sarah Zennou
  EADS Innovation Works - SE/IS
  12, rue Pasteur - BP 76 - 92152 Suresnes Cedex - France
  email: sarah(dot)zennou(at)eads(dot)net
*)

val is_char_type_signed: bool ref
(* only defined in gnuc mode *)
val size_of_void: int ref
val size_of_char: int ref
val size_of_ptr: int ref
val size_of_int: int ref
val max_sizeof: int ref
val size_of_long: int ref
val size_of_longlong: int ref
val size_of_double: int ref
val size_of_float: int ref
val size_of_longdouble: int ref
val size_of_short: int ref
val size_of_byte: int ref
val max_array_length: int ref

val align_of_void: int ref
val align_of_char: int ref
val align_of_ptr: int ref
val align_of_int: int ref
val align_of_long: int ref
val align_of_longlong: int ref
val align_of_double: int ref
val align_of_float: int ref
val align_of_longdouble: int ref
val align_of_short: int ref


val is_little_endian: bool ref
val arithmetic_in_structs_allowed: bool ref
val unaligned_ptr_deref_allowed: bool ref
