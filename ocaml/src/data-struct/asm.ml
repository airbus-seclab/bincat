(**************************************************************************************************************************)
(* Intermediate language module *)
(**************************************************************************************************************************)
open Data
       
(** data type of register operands *)
type reg = 
  | T of Register.t 		(** a register *)
  | P of Register.t * int * int (** a chunk of a register P (r, l, u) , i.e. r[l, u-1] *)
			      
		       
(** type of binary operations *)
type binop =
  | Add    (** addition *)
  | Sub    (** substraction *)
  | Mul    (** multiplication *)
  | Div    (** division *)
  | Mod    (** unsigned modulo *)
  | And    (** bitwise AND *)
  | Or     (** bitwise OR *)
  | Xor    (** bitwise XOR *)
  | Shl    (** left logical shift *)
  | Shr    (** right logical shift *)

(** comparison operators *)
type cmp =
  | EQ  (** equality *)
  | NEQ (** difference *)
  | LEQ (** less than or equal to *)
  | LT  (** strictly less than *)
  | GEQ (** greater than or equal to *)
  | GT  (** strictly greater than *)

  (** logical binary operators *)
type logbinop =
  | LogAnd (** logical and *)
  | LogOr  (** logical or *)

(** type of unary operations *)
type unop =
  | SignExt of int (** [SignExt n] is a sign extension to be on n bit width *)
  | ZeroExt of int (** [ZeroExt n] is a zero extension to be on n bit width *)
  | Not            (** not *)

(** logical unary operator *)
type bunop =
  | LogNot (** logical not *)
      
      
(** type of expressions *)
type exp =
  | Const of Word.t            (** a constant *)
  | Lval  of lval 	       (** a left value *)
  | BinOp of binop * exp * exp (** a binary operation *)
  | UnOp  of unop * exp        (** a unary operation *)
		      
 (** type of left values *)
 and lval =
   | V of reg 	    (** a register *)
   | M of exp * int (** M(e, n): content of the memory address e on n bit width *) 

(** boolean expression *)
type bexp =
  | BUnOp  of bunop * bexp           (** unary boolean operation *)
  | Cmp    of cmp * exp * exp        (** comparison *)
  | BBinOp of logbinop * bexp * bexp (** binary boolean operation *)
  | BConst of bool                   (** boolean constant true of false *)
		
	   
(** type of directives for the analyzer *)
type directive_t =
  | Remove of Register.t   (** remove the register *)
  | Forget of Register.t (** forget the content of the given register *)

(** data type of jump targets *)
type jmp_target = 
  | A of Address.t (** target is an absolute address *)
  | R of exp       (** target is the value of the expression *)

(** type of statements *)
type stmt =
  | Set  of lval * exp    		   (** store the expression into the left value *)
  | If of bexp * (stmt list) * (stmt list) (** conditional statement *)
  | Jmp	 of jmp_target                     (** jump *)				    
  | Call of jmp_target          	   (** call *)
  | Return        		           (** return *)
  | Nop                      		   (** no operation *)
  | Directive of directive_t 		   (** directive/hint for the analyzer *)
		   
let equal_bunop op1 op2 =
  match op1, op2 with
  | LogNot, LogNot  -> true
	      
let equal_unop op1 op2 =
  match op1, op2 with
  | SignExt i1, SignExt i2 -> i1 = i2
  | ZeroExt i1, ZeroExt i2 -> i1 = i2
  | Not, Not 		   -> true
  | _, _ 		   -> false
	      
let string_of_binop op =
  match op with
  | Add    -> "+"
  | Sub    -> "-"
  | Mul    -> "*"
  | Div    -> "/"
  | Mod    -> "%"
  | And    -> "&"
  | Or 	   -> "|"
  | Xor    -> "xor"
  | Shr    -> ">>"
  | Shl    -> "<<"
  
let string_of_cmp c =
  match c with
  | EQ  -> "="
  | NEQ -> "!="
  | LEQ -> "<="
  | LT  -> "<"
  | GEQ -> "<="
  | GT  -> ">" 


let string_of_logbinop o =
  match o with
  | LogAnd -> "&&"
  | LogOr  -> "||"
		 		
let string_of_unop op extended =
  match op with
  | SignExt i ->
     if extended then
       Printf.sprintf "SignExtension (%d)" i
     else
       ""
  | ZeroExt i -> Printf.sprintf "ZeroExtension (%d)" i
  | Not       -> "not"

let string_of_bunop op =
  match op with
  | LogNot       -> "!"
		   
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
				   
				   
				   
let rec string_of_lval lv extended =
  match lv with
  | V r       -> string_of_reg r
  | M (e, i)  -> Printf.sprintf "(%d)[%s]" i (string_of_exp e extended)
     
and string_of_exp e extended =
  match e with
  | Const c 	       -> Word.to_string c
  | Lval lv 	       -> string_of_lval lv extended
  | BinOp (op, e1, e2) -> Printf.sprintf "(%s %s %s)" (string_of_exp e1 extended) (string_of_binop op) (string_of_exp e2 extended)
  | UnOp (op, e')      -> Printf.sprintf "%s %s" (string_of_unop op extended) (string_of_exp e' extended)

let rec string_of_bexp e extended =
  match e with
  | BUnOp (o, e')      -> Printf.sprintf "%s %s" (string_of_bunop o) (string_of_bexp e' extended)
  | BBinOp (o, e1, e2) -> Printf.sprintf "(%s %s %s)" (string_of_bexp e1 extended) (string_of_logbinop o) (string_of_bexp e2 extended)
  | Cmp (c, e1, e2)    -> Printf.sprintf "%s %s %s" (string_of_exp e1 extended) (string_of_cmp c) (string_of_exp e2 extended)
  | BConst b 	       -> string_of_bool b

let string_of_jmp_target t extended =
  match t with
  | A a -> Address.to_string a
  | R e -> Printf.sprintf "%s" (string_of_exp e extended)

let string_of_directive d =
  match d with
  | Remove r -> Printf.sprintf "remove %s" (Register.name r)
  | Forget r -> Printf.sprintf "forget %s" (Register.name r)
			       
let string_of_stmt s extended =
  (* internal function used to factorize code in the printing of If-stmt *)
  let concat to_string ind l =
    List.fold_left (fun acc s -> Printf.sprintf "%s\n %s" acc (to_string ind s)) "" l
  in
  (* ind is a string of spaces to be added to the beginning of a line *)
  let rec to_string ind s =
    match s with
    | Set (dst, src)     	      -> Printf.sprintf "%s%s <- %s;" ind (string_of_lval dst extended) (string_of_exp src extended)
    | Jmp target 	              -> Printf.sprintf "%sjmp %s;"  ind (string_of_jmp_target target extended)
    | If (cond, then_stmts, else_stmts) ->
       let ind' = ind ^ "____" in
       Printf.sprintf "%sif (%s)%s\n %selse%s" ind (string_of_bexp cond extended) (concat to_string ind' then_stmts) ind (concat to_string ind' else_stmts)
    | Call _ 	       		     -> Printf.sprintf "%scall" ind
    | Return  	       		     -> Printf.sprintf "%sret" ind
    | Nop 	       		     -> Printf.sprintf "%snop" ind
    | Directive d        	     -> Printf.sprintf "%s%s" ind (string_of_directive d)
  in
  to_string "" s
		     
