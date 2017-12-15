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

let byte = 8 

let is_char_type_signed = ref true

(* only defined in gnuc mode *)
let size_of_void 	= ref (1*byte)

let size_of_ptr 	= ref (4* byte)
let size_of_byte 	= ref byte

let size_of_char 	= ref (1* byte)
let size_of_short 	= ref (2* byte)
let size_of_int 	= ref (4* byte)
let size_of_long 	= ref (4* byte)
let size_of_longlong 	= ref (8* byte)

let size_of_float 	= ref (4* byte) 
let size_of_double 	= ref (8* byte) 
let size_of_longdouble 	= ref (12*byte) 


let max_sizeof = ref max_int
let max_array_length 	= ref (max_int / byte)

let is_little_endian = ref true
let arithmetic_in_structs_allowed = ref true
let unaligned_ptr_deref_allowed = ref true

let align_of_void       = ref (!size_of_void)
let align_of_char       = ref (!size_of_char)
let align_of_ptr        = ref (!size_of_ptr)
let align_of_int        = ref (!size_of_int)
let align_of_long       = ref (!size_of_long)
let align_of_longlong   = ref (!size_of_longlong)
let align_of_double     = ref (!size_of_double)
let align_of_float      = ref (!size_of_float)
let align_of_longdouble = ref (!size_of_longdouble)
let align_of_short      = ref (!size_of_short)
