/* (*
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

  Sarah Zennou
  EADS Innovation Works - SE/CS
  12, rue Pasteur - BP 76 - 92152 Suresnes Cedex - France
*) */

%{

type opt =
  | OptInt of int
  | OptBool of bool

let opt_table = Hashtbl.create 10

let set_option k v =
  Hashtbl.replace opt_table k v

let mandatory_options =
  [ "size_of_byte" ; "size_of_ptr" ; "size_of_char" ; "size_of_short"
  ; "size_of_int" ; "size_of_long" ; "size_of_longlong" ; "size_of_float"
  ; "size_of_double" ; "size_of_longdouble"
  ; "align_of_ptr" ; "align_of_char"
  ; "align_of_short" ; "align_of_int" ; "align_of_long"
  ; "align_of_longlong" ; "align_of_float" ; "align_of_double"
  ; "align_of_longdouble" ; "is_char_type_signed" ; "is_little_endian"
  ; "arithmetic_in_structs_allowed" ; "unaligned_ptr_deref_allowed"
]

module StrSet = Set.Make(String)

let check () =
  let remaining_opts = ref (List.fold_right StrSet.add mandatory_options StrSet.empty) in
  Hashtbl.iter (fun optname optval ->
    remaining_opts := StrSet.remove optname !remaining_opts;
    match (optname, optval) with
    | "size_of_void", OptInt n when n > 0 -> Conf.size_of_void := n

    | "size_of_byte",       OptInt n when n > 0 -> Conf.size_of_byte := n
    | "size_of_ptr",        OptInt n when n > 0 -> Conf.size_of_ptr := n
    | "size_of_char",       OptInt n when n > 0 -> Conf.size_of_char := n
    | "size_of_short",      OptInt n when n > 0 -> Conf.size_of_short := n
    | "size_of_int",        OptInt n when n > 0 -> Conf.size_of_int := n
    | "size_of_long",       OptInt n when n > 0 -> Conf.size_of_long := n
    | "size_of_longlong",   OptInt n when n > 0 -> Conf.size_of_longlong := n
    | "size_of_float",      OptInt n when n > 0 -> Conf.size_of_float := n
    | "size_of_double",     OptInt n when n > 0 -> Conf.size_of_double := n
    | "size_of_longdouble", OptInt n when n > 0 -> Conf.size_of_longdouble := n

    | "align_of_ptr",        OptInt n when n > 0 -> Conf.align_of_ptr := n
    | "align_of_char",       OptInt n when n > 0 -> Conf.align_of_char := n
    | "align_of_short",      OptInt n when n > 0 -> Conf.align_of_short := n
    | "align_of_int",        OptInt n when n > 0 -> Conf.align_of_int := n
    | "align_of_long",       OptInt n when n > 0 -> Conf.align_of_long := n
    | "align_of_longlong",   OptInt n when n > 0 -> Conf.align_of_longlong := n
    | "align_of_float",      OptInt n when n > 0 -> Conf.align_of_float := n
    | "align_of_double",     OptInt n when n > 0 -> Conf.align_of_double := n
    | "align_of_longdouble", OptInt n when n > 0 -> Conf.align_of_longdouble := n

    | "is_char_type_signed", OptBool b -> Conf.is_char_type_signed := b

    | "is_little_endian", OptBool b ->
        Conf.is_little_endian := b

    | "arithmetic_in_structs_allowed", OptBool b ->
        Conf.arithmetic_in_structs_allowed := b

    | "unaligned_ptr_deref_allowed", OptBool b ->
        Conf.unaligned_ptr_deref_allowed := b

    | _ -> failwith ("Invalid option or type for : " ^ optname)
  ) opt_table;
  Conf.max_array_length := !Conf.max_sizeof / !Conf.size_of_byte;
  if not (StrSet.is_empty !remaining_opts) then
    begin
      print_endline "The following options are missing :";
      StrSet.iter print_endline !remaining_opts;
      failwith "Aborting"
    end


%}

%token<string> IDENTIFIER
%token<int> INTEGER
%token<bool> BOOLEAN
%token EQUAL
%token EOF

%type <unit> parse
%start parse

%%

parse:
    line parse { $1;$2 }
  | EOF        { check () }

line:
    IDENTIFIER EQUAL INTEGER { set_option $1 (OptInt $3) }
  | IDENTIFIER EQUAL BOOLEAN { set_option $1 (OptBool $3) }
