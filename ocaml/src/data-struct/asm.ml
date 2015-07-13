(**************************************************************************************************************************)
(* Intermediate language module *)
(**************************************************************************************************************************)

(** this module type is the signature of the set of abstract types: *)
(** - addresses                                                     *)
(** - word                                                          *)
(** together with useful operations on these types                  *)
module type V =
  sig
    (** abstract data type for addresses *) 
    type address
    (** abstract data type for words *)
    type word

    (** abstract data type for segments *)
    type segment
	   
    (** [address_of_string s n] converts the string _s_ into an address of _n_ bits long **)
    val address_of_string: string -> int -> address
					      
    (** returns 0 if the two word parameters are equal ; *)
    val word_compare: word -> word -> int
    (** a negative integer if the first one is less than the second one *)
    (** a positive integer otherwise *)
					
    (** returns 0 if the two address parameters are equal ; *)			
    val address_compare: address -> address -> int
    (** a negative integer if the first one is less than the second one *)
    (** a positive integer otherwise *)

  end
    
module Make(Data: V) =
  struct
 (** data type of register operands *)
  type reg = 
    | T of Register.t 		  (** a complete register *)
    | P of Register.t * int * int (** a chunk of a register P (r, l, u)  means the chunk of register r that ranges from bit l to bit r *)

  (** data type of jump targets *)
  type jmp_target = 
    | A of Data.address (** jump target is an address *)
    | R of int * reg   (** R(s, r) means that the jump target is an address of segment _s_ whose value is the content _r_ *)

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
  | Const of Data.word 	       (** a constant *)
  | Lval  of lval 	       (** a left value *)
  | BinOp of binop * exp * exp (** a binary operation *)
  | UnOp  of unop * exp        (** a unary operation *)

 (** type of left values *)
 and lval =
   | V of reg 	    (** a register *)
   | M of exp * int (** M(e, n) is a memory adress whose value is _e_ and width is _n_ bits *) 

(** type of function calls *)
type fct =
  | I of reg 	      (** indirect call from register *)
  | D of Data.address (** direct call from address *)

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
  | Return of fct 			   (** return *)
  | Unknown                  		   (** unknown (partial decoding) *)
  | Undef                    		   (** undefined (decoding error) *)
  | Nop                      		   (** no operation *)
  | Directive of directive_t 		   (** directive/hint for the analyzer *)

		   
let string_of_stmt s =
  match s with
    Load _  	-> "load"
  | Store _ 	-> "store"
  | Jcc _ 	-> "jcc"
  | Call _ 	-> "call"
  | Return _ 	-> "return"
  | Unknown 	-> "unknown"
  | Undef 	-> "undef"
  | Nop 	-> "nop"
  | Directive _ -> "directive"
		       
let rec equal_exp e1 e2 =
  match e1, e2 with
    Const c1, Const c2 			       -> Data.word_compare c1 c2 = 0
  | Lval lv1, Lval lv2 			       -> equal_lval lv1 lv2
  | BinOp(op1, e11, e12), BinOp(op2, e21, e22) -> op1 = op2 && equal_exp e11 e21 && equal_exp e12 e22
  | UnOp(op1, e1), UnOp(op2, e2) 	       -> op1 = op2 && equal_exp e1 e2
  | _, _ 				       -> false

and equal_reg r1 r2 =
  match r1, r2 with
    T r1, T r2 			   -> Register.compare r1 r2 = 0
  | P (l1, u1, r1), P (l2, u2, r2) -> l1 = u1 && l2 = u2 && Register.compare r1 r2 = 0
  | _, _ 			   -> false

and equal_lval lv1 lv2 =
  match lv1, lv2 with
    V r1, V r2 		     -> equal_reg r1 r2
  | M (e1, sz1), M (e2, sz2) -> equal_exp e1 e2 && sz1 = sz2
  | _, _ 		     -> false

let equal_directive d1 d2 =
  match d1, d2 with
    Remove v1, Remove v2
  | Undefine v1, Undefine v2 -> Register.compare v1 v2 = 0
  | Push e1, Push e2 	     -> equal_exp e1 e2
  | Pop r1, Pop r2 	     -> equal_reg r1 r2
  | _, _ 		     -> false

let equal_target t1 t2 =
  match t1, t2 with
    A a1, A a2 		   -> Data.address_compare a1 a2 = 0
  | R (s1, r1), R (s2, r2) -> s1 = s2 && equal_reg r1 r2
  | _, _ 		   -> false

let equal_fct f1 f2 =
  match f1, f2 with
    I r1, I r2 -> equal_reg r1 r2
  | D a1, D a2 -> Data.address_compare a1 a2 = 0
  | _, _       -> false

let equal_stmt s1 s2 =
  match s1, s2 with
    Load(lv11, lv12), Load(lv21, lv22) 		   -> equal_lval lv11 lv21 && equal_lval lv12 lv22
  | Store(lv1, e1), Store(lv2, e2) 		   -> equal_lval lv1 lv2 && equal_exp e1 e2
  | Jcc (None, None), Jcc(None, None) 		   -> true
  | Jcc (None, Some a1), Jcc (None, Some a2) 	   -> equal_target a1 a2
  | Jcc (Some e1, None), Jcc (Some e2, None) 	   -> equal_exp e1 e2
  | Jcc (Some e1, Some a1), Jcc (Some e2, Some a2) -> equal_exp e1 e2 && equal_target a1 a2
  | Call f1, Call f2 				   -> equal_fct f1 f2
  | Nop, Nop | Undef, Undef | Unknown, Unknown 	   -> true
  | Directive d1, Directive d2 			   -> equal_directive d1 d2
  |_, _ 					   -> false
end

