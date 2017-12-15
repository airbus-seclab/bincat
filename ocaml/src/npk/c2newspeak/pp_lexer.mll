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

{
open Pp_parser

let remove_quotes str =
  let len = String.length str in
    String.sub str 1 (len-2)

}

let white_space = ' ' | '\t'
let section = '"''<' [^'>']* '>''"'
let string = '"' [^'"']* '"'

let letter = ['a'-'z'] | ['A'-'Z'] | '_'
let digit = ['0'-'9']

let integer = digit+
let identifier = letter (letter|digit)*

let new_line = '\r' | '\n' | "\r\n"

rule token = parse

  | "#"                   { SHARP }
    
  | "pragma"              { PRAGMA }
  | identifier            { IDENTIFIER }
  | integer               { INTEGER (int_of_string (Lexing.lexeme lexbuf)) }
  | section               { SECTION }
  | string                { STRING (remove_quotes (Lexing.lexeme lexbuf)) }
  | white_space           { token lexbuf }
  | new_line              { NEW_LINE }

  | "("                   { PUNCTUATOR }
  | ")"                   { PUNCTUATOR }
  | ","                   { PUNCTUATOR }

(* error fallback *)
  | _                     { Npkcontext.report_error "Preprocess_lexer" 
			      ("unknown keyword: "
			       ^(Lexing.lexeme lexbuf)
				^" in preprocessing directive") }
