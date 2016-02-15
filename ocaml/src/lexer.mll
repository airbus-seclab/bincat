{
  open Parser
}

(* utilities *)
let letter 	 = ['a'-'z' 'A'-'Z'] 
let digit 	 = ['0'-'9']

(* integers *)
let hexa_int     = ("0x" | "0x") ['0' -'9' 'a' - 'f' 'A'-'F']+
let dec_int      = digit+
let oct_int      = ("0o" | "0O") ['0'-'7']+
let integer = hexa_int | dec_int | oct_int

(* special characters *)
let path_symbols = '.' | '/' 
let white_space  = [' ' '\t' '\r']+
let newline 	 = "\r" | "\n" | "\r\n"


(* left operands in configuration rules *)
let value        = (digit | path_symbols | letter | '_' )*

(* tokens *)
rule token = parse
  (* escape tokens *)
  | white_space 	    { token lexbuf }
  | newline 		    { token lexbuf }
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
  | '_'                     { UNDERSCORE }
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
  (* settings tokens *)
  | "mem-model" 	    { MEM_MODEL }
  | "op-sz"     	    { OP_SZ }
  | "mem-sz"    	    { MEM_SZ }
  | "stack-width" 	    { STACK_WIDTH }
  | "call-conv" 	    { CALL_CONV }
  | "flat"      	    { FLAT }
  | "segmented" 	    { SEGMENTED }
  | "cdecl"     	    { CDECL }
  | "stdcall"   	    { STDCALL }
  | "fastcall"  	    { FASTCALL }
  (* analyzer tokens *)
  | "unroll"    	    { UNROLL }
  | "dotfile"               { DOTFILE }
  (* loader tokens *)
  | "star_ss" 	    	    { SS }
  | "star_ds" 		    { DS }
  | "star_cs" 	    	    { CS }
  | "star_es" 		    { ES }
  | "star_fs" 		    { FS }
  | "star_gs" 		    { GS }
  | "code-length" 	    { CODE_LENGTH }
  | "entrypoint" 	    { ENTRYPOINT }
  (* binary tokens *)
  | "phys-code-addr"        { PHYS_CODE_ADDR }
  | "filepath" 		    { FILEPATH }
  | "format" 		    { FORMAT }
  | "pe" 		    { PE }
  | "elf" 		    { ELF }
  | "mode"                  { MODE }
  | "protected"             { PROTECTED }
  | "real"                  { REAL }

  (* left operand of type integer *)
  | integer as i 	    { INT i }
  (* misc left operands *)
  | value as v  	    { STRING v }

(* skip comments *)			    
and comment = parse
  | ['\n' '\r']   { token lexbuf }
  | [^ '\n' '\r'] { comment lexbuf }
