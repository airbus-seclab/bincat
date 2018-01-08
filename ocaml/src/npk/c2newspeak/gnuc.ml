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


open NpkParser
(* TODO : token_tbl redundant with parser => try to remove *)
let token_tbl = Hashtbl.create 50

let builtin_names = 
  ["__builtin_strchr"; 
   "__builtin_strcmp";
   "__builtin_strncpy";
   "__builtin_strncat";
   "__builtin_expect"
  ]

let builtins = 
  List.fold_left ( ^ ) "" 
    ["extern char *__builtin_strchr(char *str, char c);";
     "extern int __builtin_strcmp(char *str1, char *str2);";
     "extern char *__builtin_strncpy(char *dst, char *src, unsigned int sz);";
     "extern char *__builtin_strncat(char *dst, char *src, unsigned int sz);";
     "extern long int __builtin_expect(long int exp, long int val);";
    ]
(* TODO: check that all these tokens can not be function names!!!!
   otherwise do it somehow differently!!
*)
let _ = 
  Hashtbl.add token_tbl "__extension__" EXTENSION;
  (* prevent warnings when compiling in -pedantic *)

  Hashtbl.add token_tbl "__attribute__" ATTRIBUTE;
  Hashtbl.add token_tbl "__attribute" ATTRIBUTE;   
  Hashtbl.add token_tbl "__restrict" RESTRICT;
  Hashtbl.add token_tbl "__restrict__" RESTRICT;
  Hashtbl.add token_tbl "__builtin_va_list" VA_LIST;
  Hashtbl.add token_tbl "__inline__" INLINE;
  Hashtbl.add token_tbl "__inline" INLINE;
  Hashtbl.add token_tbl "__asm__" ASM;
  Hashtbl.add token_tbl "__asm" ASM;
  Hashtbl.add token_tbl "__cdecl" CDECL;
  (* __nothrow__: tells the compiler the function does not throw an exception *)

  (* __pure__: tells the compiler the function has no side-effects other than 
     the return value which depends on the arguments and globals *)

  Hashtbl.add token_tbl "__const" CONST;
  Hashtbl.add token_tbl "__const__" CONST;
  (* for function slightly more strict than pure, since const functions
     are assumed not to read global variables *)

  (* __nonnull__, __nonnull: tells the compiler the argument should always 
     be a non-null pointer *)

  (* __deprecated__: generates warnings when the function is used *)

  Hashtbl.add token_tbl "__builtin_constant_p" BUILTIN_CONSTANT_P;
  (* __builtin_constant_p(e): 
     returns 1 if expression e is a statically known constant,
     0 otherwise 
  *)
  Hashtbl.add token_tbl "__typeof" TYPEOF;
  Hashtbl.add token_tbl "typeof" TYPEOF;
  Hashtbl.add token_tbl "__typeof__" TYPEOF;
  Hashtbl.add token_tbl "__builtin_offsetof" OFFSETOF;
  Hashtbl.add token_tbl "__PRETTY_FUNCTION__" FUNNAME;
  Hashtbl.add token_tbl "__FUNCTION__" FUNNAME;
  Hashtbl.add token_tbl "__func__" FUNNAME;

  Hashtbl.add token_tbl "__signed__" SIGNED;
  Hashtbl.add token_tbl "__signed" SIGNED;

  Hashtbl.add token_tbl "__volatile__" VOLATILE;
  Hashtbl.add token_tbl "__volatile" VOLATILE;

  Hashtbl.add token_tbl "__label__" LABEL;

  List.iter (fun x -> Hashtbl.add token_tbl x (IDENTIFIER x)) builtin_names


let find_token str =
  if not !Npkcontext.accept_gnuc then raise Not_found;
  Hashtbl.find token_tbl str

let is_gnuc_token str = Hashtbl.mem token_tbl str
