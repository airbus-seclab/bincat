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

  Sarah Zennou
  EADS Innovation Works - SE/CS
  12, rue Pasteur - BP 76 - 92152 Suresnes Cedex - France
*)

{

open Abiparser
open Lexing

let set_loc lexbuf pos = 
  lexbuf.lex_curr_p <- pos;
  Npkcontext.set_loc (pos.pos_fname, pos.pos_lnum, pos.pos_cnum-pos.pos_bol)

let init fname lexbuf = 
  let pos = { lexbuf.lex_curr_p with pos_fname = fname } in
    set_loc lexbuf pos

let cnt_line lexbuf =
  let pos = 
    { 
      lexbuf.lex_curr_p with 
	pos_lnum = lexbuf.lex_curr_p.pos_lnum + 1;
	pos_bol = lexbuf.lex_curr_p.pos_cnum;
    }
  in
    set_loc lexbuf pos

}

let white_space = ' ' | '\t'
let new_line = '\r' | '\n' | "\r\n"
let integer = ['0'-'9']+
let letter = ['a'-'z'] | ['A'-'Z'] | '_'
let identifier = letter+

rule token = parse

    "false"     { BOOLEAN false }
  | "true"      { BOOLEAN true }
  | identifier  { IDENTIFIER (Lexing.lexeme lexbuf) }
  | integer     { INTEGER (int_of_string (Lexing.lexeme lexbuf)) }
  | "="         { EQUAL }
  | white_space { token lexbuf }
  | new_line    { cnt_line lexbuf; token lexbuf }
  | eof         { EOF }

