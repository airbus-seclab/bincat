{
  open Parser
}

let letter 	= ['a'-'z'] | ['A'-'Z'] 
let digit 	= ['0'-'9']
let symb        = '_' | '.' | '/'
let identifier 	= (letter|digit|symb)*
let white_space = ' ' | '\t' |'\r' | '\n' | "\r\n"

rule token = parse
  | white_space { token lexbuf }
  | '[' 	{ LEFT_SQ_BRACKET }
  | ']' 	{ RIGHT_SQ_BRACKET }
  | '='         { EQUAL }
  | '*'         { STAR }
  | '@'         { AT }		
  | eof         { EOF }
  | "reg"       { REG }
  | "mem"       { MEM }
  | '#'         { comment lexbuf }
  | identifier 	{ STRING (Lexing.lexeme lexbuf) }

and comment = parse
  | '\n' { token lexbuf }
  | _    { comment lexbuf }
