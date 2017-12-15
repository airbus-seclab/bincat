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
open Parser
open Lexing
open Pp_syntax

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

let unknown_lexeme lexbuf =
  let pos = Lexing.lexeme_start_p lexbuf in
  let line = string_of_int pos.pos_lnum in
  let lexeme = Lexing.lexeme lexbuf in
  let err_msg = "line: "^line^", unknown keyword: "^lexeme in
    Npkcontext.report_error "Lexer.unknown_lexeme" err_msg

let int_of_hex_character str =
  let str = "0x"^str in
    int_of_string str

let int_of_oct_character str =
  let str = "0o"^str in
    int_of_string str
 
let standard_token str =
  if Synthack.is_type str then TYPEDEF_NAME str 
  else IDENTIFIER str

let token_of_ident str = 
  try Gnuc.find_token str
  with Not_found -> standard_token str

let trim_newline str = 
  let i = 
    try String.index str '\r' 
    with Not_found -> 
      try String.index str '\n' 
      with Not_found -> 
	Npkcontext.report_error "Preprocess.trim_newline" "end of line expected"
  in
    String.sub str 0 i

let preprocess lexbuf =
  let line = Lexing.lexeme lexbuf in
  let directive = Pp_parser.parse Pp_lexer.token (Lexing.from_string line) in
  let line = trim_newline line in
    match directive with
      | Line (fname, line_nb) ->
	  let line_nb = line_nb - 1 in (* Because we are then 
					  going to count a new line *)
	  let pos = { 
	    lexbuf.lex_curr_p with pos_fname = fname; pos_lnum = line_nb;
	  } in
 	    set_loc lexbuf pos
      | Pragma -> 
	  Npkcontext.report_ignore_warning "Preprocessor.parse"
	    ("directive "^line) Npkcontext.Pragma
      | _ -> ()
}

let white_space = ' ' | '\t'
let new_line = '\r' | '\n' | "\r\n"
let line = [^'\r''\n']* new_line

let line_comment = "//" line

let letter = ['a'-'z'] | ['A'-'Z'] | '_'
let digit = ['0'-'9']
let oct_digit = ['0'-'7']
let hex_digit = digit | ['A'-'F'] | ['a'-'f']

let sign = ("U"|"u") as sign
let length = ("l"|"L"|"LL") as length
let hex_prefix = "0x" | "0X"

let oct_integer = ("0" as prefix) (oct_digit+ as value) sign? length?
let hex_integer = (hex_prefix as prefix) (hex_digit+ as value) sign? length?
let integer = (digit+ as value) sign? length?
let integer_constant = 
    (oct_integer | hex_integer | integer) sign? length?
  | (oct_integer | hex_integer | integer) length? sign?

let float = 
  ((digit+ | digit+ '.' digit+ | '.' digit+ | digit+ '.') 
     (('e'|'E') '-'? digit+)? as value)
    ("F"|"l"|"L" as suffix)?
let identifier = letter (letter|digit)*
let wide_string = 'L''"' [^'"']* '"'

let hex_character = 
    "\\x" (hex_digit as value)
  | "\\x" (hex_digit hex_digit as value)
let oct_character = 
    ("\\" (oct_digit as value))
  | ("\\" (oct_digit oct_digit as value))
  | ("\\" (oct_digit oct_digit oct_digit as value))
let wide_character = 'L''\'' _ '\''

rule token = parse

(* keywords *)
    "asm"               { ASM }
  | "break"             { BREAK }
  | "case"              { CASE }
  | "const"             { CONST }
  | "continue"          { CONTINUE }
  | "default"           { DEFAULT }
  | "do"                { DO }
  | "else"              { ELSE }
  | "enum"              { ENUM }
  | "extern"            { EXTERN }
  | "for"               { FOR }
  | "goto"              { GOTO }
  | "if"                { IF }
  | "inline"            { INLINE }
  | "register"          { REGISTER }
  | "auto"              { AUTO }
  | "return"            { RETURN }
  | "sizeof"            { SIZEOF }
  | "static"            { STATIC }
  | "switch"            { SWITCH }
  | "typedef"           { TYPEDEF }
  | "while"             { WHILE }

(* types *)
  | "char"              { CHAR }
  | "double"            { DOUBLE }
  | "float"             { FLOAT }
  | "int"               { INT }
  | "short"             { SHORT }
  | "long"              { LONG }
  | "struct"            { STRUCT }
  | "union"             { UNION }
  | "signed"            { SIGNED }
  | "unsigned"          { UNSIGNED }
  | "void"              { VOID }
  | "volatile"          { VOLATILE }

(* values *)
  | integer_constant    { INTEGER (prefix, value, sign, length) }
  | float               { FLOATCST (value, suffix) }
  | "'" ((('\\'_)|[^'\\''\''])+ as c)
    "'"                 { CHARACTER (character (Lexing.from_string c)) }
  | wide_character      { Npkcontext.report_error "Lexer.token" 
			    "wide characters not supported" }
  | '"' ((('\\'_)|[^'\\''"'])* as str)
    '"'                 { 
      let lexbuf = Lexing.from_string str in
      let res = ref "" in begin
	  try
	    while (true) do
	      res := !res^(String.make 1 (Char.chr (character lexbuf)))
	    done
	  with Exit -> ()
	end;
	STRING (!res) 
    }
  | wide_string         { Npkcontext.report_error "Lexer.token" 
			    "wide string literals not supported" }
(* punctuation *)
  | "..."               { ELLIPSIS }
  | ","                 { COMMA }
  | ":"                 { COLON }
  | "?"                 { QMARK }
  | "."                 { DOT }
  | "{"                 { LBRACE }
  | "}"                 { RBRACE }
  | "("                 { LPAREN }
  | ")"                 { RPAREN }
  | "["                 { LBRACKET }
  | "]"                 { RBRACKET }
  | "!"                 { NOT }
  | "=="                { EQEQ }
  | "!="                { NOTEQ }
  | "="                 { EQ }
  | "&="                { AMPERSANDEQ }
  | "|="                { OREQ }
  | "-="                { MINUSEQ }
  | "+="                { PLUSEQ }
  | "*="                { STAREQ }
  | "/="                { DIVEQ }
  | "%="                { MODEQ }
  | "^="                { BXOREQ }
  | "<<="               { SHIFTLEQ }
  | ">>="               { SHIFTREQ }
  | ";"                 { SEMICOLON }

(* operators *)
  | "&"                 { AMPERSAND }
  | "->"                { ARROW }
  | "+"                 { PLUS }
  | "-"                 { MINUS }
  | "/"                 { DIV }
  | "%"                 { MOD }
  | "++"                { PLUSPLUS }
  | "--"                { MINUSMINUS }
  | "&&"                { AND }
  | "||"                { OR }
  | "*"                 { STAR }
  | "<"                 { LT }
  | "<="                { LTEQ }
  | ">"                 { GT }
  | ">="                { GTEQ }
  | "<<"                { SHIFTL }
  | ">>"                { SHIFTR }
  | "^"                 { BXOR }
  | "|"                 { BOR }
  | "~"                 { BNOT }

  | identifier          { token_of_ident (Lexing.lexeme lexbuf) }

  | "#" line            { preprocess lexbuf; cnt_line lexbuf; 
			  token lexbuf }

  | "/*!npk"            { NPK (Parser.assertion npk_spec lexbuf) }
  | "/*"                { comment lexbuf }
  | line_comment        { cnt_line lexbuf; token lexbuf }
  | new_line            { cnt_line lexbuf; token lexbuf }
  | white_space         { token lexbuf }

  | eof                 { EOF }
(* error fallback *)
  | _                   { unknown_lexeme lexbuf }


and comment = parse
  | "*/"                { token lexbuf }
  | new_line            { cnt_line lexbuf; comment lexbuf }
  | _                   { comment lexbuf }

and npk_spec = parse
  | integer_constant    { INTEGER (prefix, value, sign, length) }
  | float               { FLOATCST (value, suffix) }
  | identifier          { IDENTIFIER (Lexing.lexeme lexbuf) }

  | "*/"                { EOF }
  | white_space         { npk_spec lexbuf }
  | new_line            { cnt_line lexbuf; npk_spec lexbuf }

  | _ as c              { SYMBOL c }

and character = parse
  | oct_character       { int_of_oct_character value }
  | hex_character       { int_of_hex_character value }
  | "\\t"               { 9 }
  | "\\n"               { 10 }
  | "\\v"               { 11 }
  | "\\f"               { 12 }
  | "\\r"               { 13 }
  | "\\\""              { 34 }
  | "\\\'"              { 39 }
  | "\\\\"              { 92 }
  | _ as c              { int_of_char c }
  | eof                 { raise Exit }
