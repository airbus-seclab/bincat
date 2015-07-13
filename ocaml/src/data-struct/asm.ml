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

end

