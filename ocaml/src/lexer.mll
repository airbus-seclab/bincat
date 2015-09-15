{
  open Parser
}

let letter 	= ['a'-'z'] | ['A'-'Z'] 
let digit 	= ['0'-'9']
let identifier 	= letter (letter|digit|'_')*
let white_space = ' ' | '\t' |'\r' | '\n' | "\r\n"

rule token = parse
  | white_space { token lexbuf }
  | '[' 	{ SECTION_START }
  | ']' 	{ SECTION_END }
  | eof         { EOF }
  | identifier 	{ STRING (Lexing.lexeme lexbuf) }
