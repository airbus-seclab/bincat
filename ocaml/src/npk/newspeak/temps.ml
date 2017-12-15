(*
  C2Newspeak: compiles C code into Newspeak. Newspeak is a minimal language 
  well-suited for static analysis.
  Copyright (C) 2007-2010  Charles Hymans, Etienne Millon, Sarah Zennou
  
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
  EADS Innovation Works - SE/IS
  12, rue Pasteur - BP 76 - 92152 Suresnes Cedex - France
  email: charles.hymans@penjili.org

  Etienne Millon
  EADS Innovation Works - SE/IS
  12, rue Pasteur - BP 76 - 92152 Suresnes Cedex - France
  email: etienne.millon@eads.net
  
  Sarah Zennou
  EADS Innovation Works - SE/IS
  12, rue Pasteur - BP 76 - 92152 Suresnes Cedex - France
  email: sarah.zennou@eads.net
  
*)

type t = Cstr of string
       | Return
       | Value_of of string
       | Misc of string
       | Goto_label of string
       | Argv 
       | Argv_value
       | Arg
       | Ada_operator of string

let sep = "!"

let to_string id x =
  let id_str = string_of_int id in
    match x with
      | Cstr s          -> sep        ^ "cstr"     ^ "." ^ String.escaped s
      | Return          -> sep        ^ "return"
      | Value_of s      -> "value_of" ^ sep      ^ id_str ^ sep ^ s
      | Misc desc       -> "tmp_"     ^ desc     ^ sep    ^ id_str
      | Goto_label lbl  -> "goto"     ^ sep      ^ lbl
      | Argv            -> sep        ^ "ptr_array"
      | Arg             -> "arg"      ^ sep      ^ id_str
      | Argv_value      -> "argv_str" ^ sep      ^ id_str 
      | Ada_operator s  ->
          let operators =
            [ "and" ; "or" ; "xor" ; "=" ; "/="  ; "<"
            ; "<="  ; ">"  ; ">="  ; "+" ; "-"   ; "*"
            ; "/"   ; "mod" ; "rem" ; "**"
            ]
          in
	    if not (List.mem s operators) then begin
	      invalid_arg ("Temps.to_string: "^"ada operator '" ^ s ^ "'")
	    end;
            sep ^ "op" ^ s

let return_value = to_string 0 Return

let is_special s =
  let sep_chr = String.get sep 0 in
  String.contains s sep_chr

let is_return_value s =
  s = sep ^ "return"

let is_string_litteral s = 
  let re = Str.regexp ( "^" ^ "cstr" ^ Str.quote sep ) in
  Str.string_match re s 0

(**
  * Utility function.
  * Takes a regexp description **with a grouping pattern** and
  * extracts the matching part.
  *)
let extract_group (re:string) (s:string) :bool =
  if Str.string_match (Str.regexp re) s 0 then
    try
      let _ = Str.matched_group 1 s in true
    with Not_found -> false
  else
    false

let is_value_of =
  extract_group ( "^"
                ^ "value_of"
                ^ Str.quote sep ^ "[0-9]+"
                ^ Str.quote sep ^ "\\(.*\\)"
                ^ "$"
                )

let is_goto_label =
  extract_group ( "^" ^ "goto" ^ Str.quote sep
                ^ "\\(.*\\)"
                ^ "$"
                )

let is_ada_operator =
  extract_group ( "^" ^ Str.quote sep ^ "op"
                ^ "\\(.*\\)"
                ^ "$"
                )

let is_generic_temp =
  extract_group ( "^" ^ "tmp_"
                ^ "\\(.*\\)"
                ^ Str.quote sep ^ "[0-9]+"
                ^ "$"
                )

let is_fun_arg =
  extract_group ( "arg" ^ Str.quote sep ^ "[0-9]+"
		  ^ "$"
		)
