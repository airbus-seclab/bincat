(**************************************************************************************************************************)
(* Intermediate language module *)
(**************************************************************************************************************************)
open Data
       
(** data type of register operands *)
type reg = 
  | T of Register.t 		  (** a complete register *)
  | P of Register.t * int * int (** a chunk of a register P (r, l, u)  means the chunk of register r that ranges from bit l to bit r *)
			      
(** data type of jump targets *)
type jmp_target = 
  | A of Address.t (** jump target is an address *)
  | R of Address.t * reg    (** R(s,r) means that the jump target is an address of segment _s_ whose value is the content _r_ *)
		       
(** type of binary operations *)
type binop =
  | Add    (** addition *)
  | Sub    (** substraction *)
  | Mul    (** unsigned multiplication *)
  | Div    (** unsigned division *)
  | Divs   (** signed division *)
  | Shl    (** left logical shift *)
  | Shr    (** right logical shift *)
  | Shrs   (** right logical shift with sign *)
  | Mod    (** unsigned modulo *)
  | And    (** bitwise AND *)
  | Or     (** bitwise OR *)
  | Xor    (** bitwise XOR *)
  | CmpEq  (** comparison for equality *)
  | CmpLeu (** comparion less than equal on unsigned operands *)
  | CmpLes (** comparion less than equal on signed operands *)
  | CmpLtu (** comparion strictly less than on unsigned operands *)
  | CmpLts (** comparison strictly less than on signed operands *)
      
(** type of unary operations *)
type unop =
  | SignExt of int (** [SignExt n] is a sign extension on _n_ bit width *)
  | Not 	     (** Negation *)
      
      
      
(** type of expressions *)
type exp =
  | Const of Word.t            (** a constant *)
  | Lval  of lval 	       (** a left value *)
  | BinOp of binop * exp * exp (** a binary operation *)
  | UnOp  of unop * exp        (** a unary operation *)
		      
 (** type of left values *)
 and lval =
   | V of reg 	    (** a register *)
   | M of exp * int (** M(e, n) is a memory adress whose value is _e_ and width is _n_ bits *) 
		  
			    
(** type of function calls *)
type fct =
  | I of reg 	   (** indirect call from register *)
  | D of Address.t (** direct call from address *)
	   
(** type of directives for the analyzer *)
type directive_t =
  | Remove of Register.t   (** remove the register *)
  | Push of exp 	   (** push the expression on the stack *)
  | Pop of reg 		   (** pop the stack and stores it on the given register *)
  | Undefine of Register.t (** forget the computed value of the given register *)
		  
(** type of statements *)
type stmt =
  | Load  of lval * lval    		   (** load the second argument into the first one *)
  | Store  of lval * exp    		   (** load the expression into the left value *)
  | Jcc	 of exp option * jmp_target option (** (un)conditional branch ; None expression is for unconditional jump ; None target is for intermediate block translation *)				    
  | Call of fct          		   (** call *)
  | Return         			   (** return *)
  | Unknown                  		   (** unknown (partial decoding) *)
  | Undef                    		   (** undefined (decoding error) *)
  | Nop                      		   (** no operation *)
  | Directive of directive_t 		   (** directive/hint for the analyzer *)
		   
let equal_unop op1 op2 =
  match op1, op2 with
  | Not, Not 		   -> true
  | SignExt i1, SignExt i2 -> i1 = i2
  | _, _ 		   -> false
				
let string_of_binop op =
  match op with
  | Add    -> "+"
  | Sub    -> "-"
  | Mul    -> "*"
  | Div    -> "/"
  | Divs   -> "/"
  | Shl    -> "<<"
  | Shr    -> ">>"
  | Shrs   -> ">>"
  | Mod    -> "%"
  | And    -> "&"
  | Or 	   -> "|"
  | Xor    -> "xor"
  | CmpEq  -> "="
  | CmpLeu -> "<="
  | CmpLes -> "<="
  | CmpLtu -> "<" 
  | CmpLts -> "<"
		
let string_of_unop op =
  match op with
  | SignExt i -> Printf.sprintf "SignExtension (%d)" i
  | Not       -> "!"
		   
let equal_reg r1 r2 =
  match r1, r2 with
  | T r1', T r2' 		     -> Register.equal r1' r2'
  | P (r1', l1, u1), P (r2', l2, u2) -> Register.equal r1' r2' && l1 = l2 && u1 = u2
  | _, _ 			     -> false
					  
let rec equal_lval lv1 lv2 =
  match lv1, lv2 with
  | V v1, V v2 		   -> equal_reg v1 v2
  | M (e1, i1), M (e2, i2) -> i1 = i2 && equal_exp e1 e2
  | _, _ 		   -> false
				
and equal_exp e1 e2 =
  match e1, e2 with
  | Const c1, Const c2 				 -> Word.compare c1 c2 = 0
  | BinOp (op1, e11, e12), BinOp (op2, e21, e22) -> op1 = op2 && equal_exp e11 e21 && equal_exp e12 e22
  | UnOp (op1, e1'), UnOp (op2, e2') 		 -> equal_unop op1 op2 && equal_exp e1' e2'
  | Lval lv1, Lval lv2 				 -> equal_lval lv1 lv2
  | _, _ 					 -> false
						      
let string_of_reg r =
  match r with
  | T r' 	 -> Register.name r'
  | P (r', l, u) -> Printf.sprintf "%s[%d, %d]" (Register.name r') l u
				   
				   
				   
let rec string_of_lval lv =
  match lv with
  | V r       -> string_of_reg r
  | M (e, i)  -> Printf.sprintf "M(%s)[:%d]" (string_of_exp e) i
     
and string_of_exp e =
  match e with
  | Const c 	       -> Word.to_string c
  | Lval lv 	       -> string_of_lval lv
  | BinOp (op, e1, e2) -> Printf.sprintf "(%s %s %s)" (string_of_exp e1) (string_of_binop op) (string_of_exp e2)
  | UnOp (op, e')      -> Printf.sprintf "%s %s" (string_of_unop op) (string_of_exp e')
					 
let string_of_stmt s =
  match s with
    Load _  	-> "load"
  | Store _ 	-> "store"
  | Jcc _ 	-> "jcc"
  | Call _ 	-> "call"
  | Return  	-> "return"
  | Unknown 	-> "unknown"
  | Undef 	-> "undef"
  | Nop 	-> "nop"
  | Directive _ -> "directive"

		     
