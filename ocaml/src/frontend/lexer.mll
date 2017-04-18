(*
    This file is part of BinCAT.
    Copyright 2014-2017 - Airbus Group

    BinCAT is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or (at your
    option) any later version.

    BinCAT is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with BinCAT.  If not, see <http://www.gnu.org/licenses/>.
*)

{
  open Parser
  open Lexing
    exception SyntaxError of string
}


(* utilities *)
let letter 	 = ['a'-'z' 'A'-'Z']
let digit 	 = ['0'-'9']

(* integers *)
let hex_digits = ['0' -'9' 'a' - 'f' 'A'-'F']+
let hexa_int     = ("0X" | "0x") hex_digits
let dec_int      = digit+
let oct_int      = ("0o" | "0O") ['0'-'7']+
let integer = hexa_int | dec_int | oct_int

(* special characters *)
let path_symbols = '.' | '/' | '\\'
let white_space  = [' ' '\t' '\r']+
let newline 	 = "\r" | "\n" | "\r\n"


(* left operands in configuration rules *)
let value        = (digit | path_symbols | letter | '_' | '-' | '@')*

(* tokens *)
rule token = parse
  (* escape tokens *)
  | white_space 	    { token lexbuf }
  | newline 		    { new_line lexbuf; token lexbuf }
  | '#'         	    { comment lexbuf }
  (* section separators *)
  | '[' 		    { LEFT_SQ_BRACKET }
  | ']' 		    { RIGHT_SQ_BRACKET }
  (* tainting rules for functions *)
  | '='         	    { EQUAL }
  | '*'         	    { STAR }
  | '('         	    { LPAREN }
  | ')'         	    { RPAREN }
  | '<'         	    { LANGLE_BRACKET }
  | '>'         	    { RANGLE_BRACKET }
  | ','         	    { COMMA }
  | ';'         	    { SEMI_COLON }
  | '_'                     { UNDERSCORE }
  (* byte string *)
  | '|'         	    { read_bytes (Buffer.create 80) lexbuf }
  | '@'         	    { AT }
  (* end of file *)
  | eof         	    { EOF }
  (* specification of the intial configuration of a register *)
  | "reg"       	    { REG }
  (* specification of the intial configuration of a memory location *)
  | "mem"       	    { MEM }
  (* taint mask for a memory location or a register *)
  | '!'         	    { TAINT }
  (* mask for taint or value *)
  | '?' 		    { MASK }
  (* state section *)
  | "state"    		    { STATE }
  (* setting section *)
  | "settings"              { SETTINGS }
  (* loader section *)
  | "loader"                { LOADER }
  (* binary section *)
  | "binary"                { BINARY }
  (* analyzer section *)
  | "analyzer"  	    { ANALYZER }
  (* sections section *)
  | "section"  	    { SECTION }
  | "sections"  	    { SECTIONS }
  (* settings tokens *)
  | "mem_model" 	    { MEM_MODEL }
  | "op_sz"     	    { OP_SZ }
  | "mem_sz"    	    { MEM_SZ }
  | "stack_width" 	    { STACK_WIDTH }
  | "call_conv" 	    { CALL_CONV }
  | "flat"      	    { FLAT }
  | "segmented" 	    { SEGMENTED }
  | "cdecl"     	    { CDECL }
  | "stdcall"   	    { STDCALL }
  | "fastcall"  	    { FASTCALL }
  (* analyzer tokens *)
  | "unroll"    	    { UNROLL }
  | "cut"                   { CUT }
  | "verbose"               { VERBOSE }
  | "dotfile"               { DOTFILE }
  | "store_marshalled_cfa"  { STORE_MCFA }
  | "in_marshalled_cfa_file"   { IN_MCFA_FILE }
  | "out_marshalled_cfa_file"   { OUT_MCFA_FILE }
  (* address separator *)
  | "," 		    { COMMA }
  (* GDT tokens *)
  | "GDT"                   { GDT }
  (* loader tokens *)
  | "ss" 	    	    { SS }
  | "ds" 		    { DS }
  | "cs" 	    	    { CS }
  | "es" 		    { ES }
  | "fs" 		    { FS }
  | "gs" 		    { GS }
  | "code_va"               { CODE_VA }
  | "code_length"           { CODE_LENGTH }
  | "code_phys"             { CODE_PHYS_ADDR }
  | "analysis_ep"           { ENTRYPOINT }
  (* binary tokens *)
  | "filepath" 		    { FILEPATH }
  | "format" 		    { FORMAT }
  | "pe" 		    { PE }
  | "elf" 		    { ELF }
  | "binary" 		    { BINARY }
  | "mode"                  { MODE }
  | "protected"             { PROTECTED }
  | "real"                  { REAL }
  | "assert"                { ASSERT }
  | "call"                  { CALL }
  | "U"                     { U }
  | "T"                     { T }
  | "imports"               { IMPORTS }
  | "stack"                 { STACK }
  | "heap"                  { HEAP }
  | "analysis"              { ANALYSIS }
  | "forward_binary"        { FORWARD_BIN }
  | "forward_cfa"           { FORWARD_CFA }
  | "backward"              { BACKWARD }
  (* left operand of type integer *)
  | integer as i 	    { INT (Z.of_string i) }
  (* misc left operands *)
  | "headers"  	    { HEADER }
  | "override"      { OVERRIDE }
  | "TAINT_ALL"  	    { TAINT_ALL }
  | "TAINT_NONE"  	    { TAINT_NONE }
  | value as v      { STRING v }
 
      

(* skip comments *)
and comment = parse
  | ['\n' '\r']   { new_line lexbuf; token lexbuf }
  | [^ '\n' '\r'] { comment lexbuf }

(* read bytes spec : |[0-9A-F]+| *)
and read_bytes buf =
  parse
  | '|'       { if Buffer.length buf mod 2 != 0 then
                    raise (SyntaxError "Byte string length should be even !")
                else
                    HEX_BYTES (Buffer.contents buf)
              }
  | hex_digits
        { Buffer.add_string buf (Lexing.lexeme lexbuf);
          read_bytes buf lexbuf
        }
  | _ { raise (SyntaxError ("Illegal byte character: " ^ Lexing.lexeme lexbuf)) }
  | eof { raise (SyntaxError ("Byte string is not terminated")) }
