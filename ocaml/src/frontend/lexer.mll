(*
    This file is part of BinCAT.
    Copyright 2014-2020 - Airbus

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

  (* keyword table *)
let keywords = Hashtbl.create 50
let _ =
  List.iter (fun (keyword, token) -> Hashtbl.replace keywords keyword token)
     ["state", STATE;
    (* program section *)
     "program", PROGRAM;
     "load_elf_coredump", LOAD_ELF_COREDUMP;
     "load_pe_crashdump", LOAD_PE_CRASHDUMP;
    (* analyzer section *)
     "analyzer", ANALYZER;
    (* sections section *)
     "section", SECTION;
     "sections", SECTIONS;
    "architecture", ARCHITECTURE;
    "armv7", ARMV7;
    "ARMv7", ARMV7;
    "armv8", ARMV8;
    "ARMv8", ARMV8;
    "powerpc", POWERPC;
    "PowerPC", POWERPC;
    "POWERPC", POWERPC;
    "ppc"    , POWERPC;
    "PPC"    , POWERPC;
    "powerpc64", POWERPC64;
    "PowerPC64", POWERPC64;
    "POWERPC64", POWERPC64;
    "ppc64"    , POWERPC64;
    "PPC64"    , POWERPC64;
    "RV32I", RV32I;
    "RV64I", RV64I;
    "rv32i", RV32I;
    "rv64i", RV64I;
    "processor_version", PROCESSOR_VERSION;
    "endianness", ENDIANNESS;
    "little", LITTLE;
    "big", BIG;
    "x86", X86;
    "x64", X64;
    "IDA", IDA;
    (* settings tokens *)
    "mem_model", MEM_MODEL;
    "op_sz", OP_SZ;
    "mem_sz", MEM_SZ;
    "stack_width", STACK_WIDTH;
    "call_conv", CALL_CONV;
    "flat", FLAT;
    "segmented", SEGMENTED;
    "cdecl", CDECL;
    "stdcall", STDCALL;
    "fastcall", FASTCALL;
    "aapcs", AAPCS;
    "svr", SVR;
    "sysv", SYSV;
    "ms", MS;
    "riscv", RISCV;
    "RISCV", RISCV;
    "RiscV", RISCV;
    (* analyzer tokens *)
    "ini_version", INI_VERSION;
    "unroll", UNROLL;
    "function_unroll", FUN_UNROLL;
    "kset_bound", KSET_BOUND;
    "cut", CUT;
    "loglevel", LOGLEVEL;
    "store_marshalled_cfa", STORE_MCFA;
    "in_marshalled_cfa_file", IN_MCFA_FILE;
    "out_marshalled_cfa_file", OUT_MCFA_FILE;
    "ignore_unknown_relocations", IGNORE_UNKNOWN_RELOCATIONS;
    (* GDT tokens *)
    "GDT", GDT;
    (* loader tokens *)
    "ss", SS;
    "ds", DS;
    "cs", CS;
    "es", ES;
    "fs", FS;
    "gs", GS;
    "fs_base", FS_BASE;
    "gs_base", GS_BASE;
    "analysis_ep", ENTRYPOINT;
    (* binary tokens *)
    "filepath", FILEPATH;
    "format", FORMAT;
    "pe", PE;
    "elf", ELF;
    "elfobj", ELFOBJ;
    "manual", MANUAL;
    "raw", RAW;
    "mode", MODE;
    "protected", PROTECTED;
    "real", REAL;
    "assert", ASSERT;
    "call", CALL;
    "U", U;
    "T", T;
    "imports", IMPORTS;
    "heap", HEAP;
    "analysis", ANALYSIS;
    "forward_binary", FORWARD_BIN;
    "forward_cfa", FORWARD_CFA;
    "backward", BACKWARD;
    (* misc left operands *)
    "headers", HEADER;
    "override", OVERRIDE;
    "nop", NOP;
    "fun_skip", FUN_SKIP;
    "TAINT_ALL", TAINT_ALL;
    "TAINT_NONE", TAINT_NONE;
    "null", NULL;
    "os", OS;
    "linux", LINUX;
    "windows", WINDOWS;
    "taint_input", TAINT_INPUT;
    "MPX", MPX;
    "enabled", ENABLED;
    "disabled", DISABLED;
    ]

let strip_int s =
  let start = String.sub s 0 1 in
  let s' =
    if String.compare start "H" = 0 || String.compare start "S" = 0 then
      String.sub s 1 ((String.length s)-1)
    else s
  in
  Z.of_string s'
}



(* utilities *)
let letter   = ['a'-'z' 'A'-'Z']
let digit    = ['0'-'9']

(* integers *)
let hex_digits = ['0' -'9' 'a' - 'f' 'A'-'F']+
let hexa_int     = ("0X" | "0x") hex_digits
let dec_int      = digit+
let oct_int      = ("0o" | "0O") ['0'-'7']+
let integer = hexa_int | dec_int | oct_int
let global_integer = ("G" | "") integer
let heap_integer = "H" integer
                  
(* special characters *)
let path_symbols = '.' | '/' | '\\' | ':'
let white_space  = [' ' '\t' '\r']+
let newline      = "\r" | "\n" | "\r\n"


(* left operands in configuration rules *)
let value        = (digit | path_symbols | letter | '_' | '-' | '@')*

(* tokens *)
rule token = parse
                 
  (* escape tokens *)
  | white_space         { token lexbuf }
  | newline             { new_line lexbuf; token lexbuf }
  | '#'                 { comment lexbuf }
  (* section separators *)
  | '['             { LEFT_SQ_BRACKET }
  | ']'             { RIGHT_SQ_BRACKET }
  (* tainting rules for functions *)
  | '='                 { EQUAL }
  | '*'                 { STAR }
  | '('                 { LPAREN }
  | ')'                 { RPAREN }
  | '<'                 { LANGLE_BRACKET }
  | '>'                 { RANGLE_BRACKET }
  | ','                 { COMMA }
  | ';'                 { SEMI_COLON }
  | '_'                     { UNDERSCORE }
  (* byte string *)
  | '|'                 { HEX_BYTES(read_bytes (Buffer.create 80) lexbuf) }
  | "G|"                 { HEX_BYTES(read_bytes (Buffer.create 80) lexbuf) }
  | "H|"                 { HEAP_HEX_BYTES(read_bytes (Buffer.create 80) lexbuf) }
  (* quoted string *)
  | '"'                 { read_string (Buffer.create 80) lexbuf }
  | '@'                 { AT }
  (* end of file *)
  | eof                 { EOF }
  (* specification of the intial configuration of a register *)
  | "reg"               { REG }
  (* specification of the intial configuration of a memory location *)
  | "mem"               { MEM }
  (* taint mask for a memory location or a register *)
  | '!'                 { TAINT }
  (* mask for taint or value *)
  | '?'             { MASK }
  (* address separator *)
  | ","             { COMMA }
  (* left operand of type integer *)
  | global_integer as i        { INT (strip_int i) }
    | heap_integer as i { HINT (strip_int i) }
    | value as v      {
                   try
                     Hashtbl.find keywords v
                   with Not_found -> STRING v
                 }



(* skip comments *)
and comment = parse
  | ['\n' '\r']   { new_line lexbuf; token lexbuf }
  | [^ '\n' '\r'] { comment lexbuf }

(* read quoted string *)
and read_string buf =
  parse
  | '"'       { QUOTED_STRING (Buffer.contents buf) }
  | _
        { Buffer.add_string buf (Lexing.lexeme lexbuf);
          read_string buf lexbuf
        }
  | eof { raise (SyntaxError ("Byte string is not terminated")) }

(* read bytes spec : |[0-9A-F]+| *)
and read_bytes buf =
  parse
  | '|'       { if Buffer.length buf mod 2 != 0 then
                    raise (SyntaxError "Byte string length should be even !")
                else
                    Buffer.contents buf
              }
  | hex_digits
        { Buffer.add_string buf (Lexing.lexeme lexbuf);
          read_bytes buf lexbuf
        }
  | _ { raise (SyntaxError ("Illegal byte character: " ^ Lexing.lexeme lexbuf)) }
  | eof { raise (SyntaxError ("Byte string is not terminated")) }
