(** The Assembly Intermediate Language *)
module type T =
sig
  type word
  type address
  type reg =
    T of Register.t
  | P of int * int * Register.t

  type jmp_target = 
    A of address
  | R of int * reg

 type memory =
    M1 of word
  | M2 of int * reg (* [n:r]*)
  | M3 of int * reg * int * reg (* [n1:r1 + n2:r2] *)
  | M4 of int * reg * word (* [n:r] + w *)
  | M5 of int * reg * int * reg * word (* [n1:r1 + n2:r2] + w *)
  | M6 of int * int * reg * int * reg (* [s * n1:r1 + n2:r2] ; s in {2, 4, 8} *)
  | M7 of int * int * reg * word (* [s * n:r] + w ; s in {2, 4, 8} *)
  | M8 of int * int * reg * int * reg * word (* [s * n1:r1 + n2:r2] + w *)

(** type of binary operations *)
type binop =
    Add (** addition *)
  | Sub (** substraction *)
  | Mul (** unsigned multiplication *)
  | Div (** unsigned division *)
  | Divs (** signed division *)
  | Shl (** left logical shift *)
  | Shr (** right logical shift *)
  | Shrs (** right logical shift with sign *)
  | Mod (** unsigned modulo *)
  | And (** bitwise AND *)
  | Or  (** bitwise OR *)
  | Xor (** bitwise XOR *)
  | Gt (** comparison greater than *)
  | Eq (** comparison for equality *)

(** type of unary operation *)
type unop =
    Sign_extension of int
  | Not


(** type of function name *)
type fct =
    I of reg (* indirect call from register *)
  | D of address (* direct call from address *)

(** type of expressions *)
type exp =
    Const of word
  | Lval of lval
  | BinOp of binop * exp * exp
  | UnOp of unop * exp

(** type of left values : R for register addressing ; M for memory *)
and lval =
  V of reg
| M of memory * int


(** type of directives for the analyzer *)
type directive_t =
    Remove   of Register.t (* remove the variable *)
  | Push     of exp
  | Pop      of reg
  | Undefine of Register.t

(** type of statements *)
type stmt =
    Set     of lval * exp (** store the expression into the left value                       *)
  | Jcc	     of exp option * jmp_target option (** (un)conditional branch ; None is for unconditional                                           *)
  | Call     of fct        (** call                                                           *)
  | Unknown                (** unknown (partial decoding)                                     *)
  | Undef                  (** undefined (decoding error)                                     *)
  | Nop                    (** no operation                                                   *)
  | Directive of directive_t      (** directive for the analyzer *)

val jmp_target_of_immediate: int -> string -> int -> jmp_target
val jmp_target_of_register: int -> reg -> jmp_target


(** string conversion *)
val string_of_stmt: stmt -> string

val equal_stmt: stmt -> stmt -> bool
end

module Make(D: Data.T) = struct
  type word = D.Word.t
  type address = D.Address.t

 type reg = 
    T of Register.t
  | P of int * int * Register.t (* (l, u, r) = r[l, u] *)

  type jmp_target = 
    A of address
  | R of int * reg

 type memory =
    M1 of word
  | M2 of int * reg (* [n:r]*)
  | M3 of int * reg * int * reg (* [n1:r1 + n2:r2] *)
  | M4 of int * reg * word (* [n:r] + w *)
  | M5 of int * reg * int * reg * word (* [n1:r1 + n2:r2] + w *)
  | M6 of int * int * reg * int * reg (* [s * n1:r1 + n2:r2] ; s in {2, 4, 8} *)
  | M7 of int * int * reg * word (* [s * n:r] + w ; s in {2, 4, 8} *)
  | M8 of int * int * reg * int * reg * word (* [s * n1:r1 + n2:r2] + w *)

(** type of binary operations *)
  type binop =
    Add (** addition *)
  | Sub (** substraction *)
  | Mul (** unsigned multiplication *)
  | Div (** unsigned division *)
  | Divs (** signed division *)
  | Shl (** left logical shift *)
  | Shr (** right logical shift *)
  | Shrs (** right logical shift with sign *)
  | Mod (** unsigned modulo *)
  | And (** bitwise AND *)
  | Or  (** bitwise OR *)
  | Xor (** bitwise XOR *)
  | Gt (** comparison greater than *)
  | Eq (** comparison for equality *)

(** type of unary operation *)
type unop =
    Sign_extension of int
  | Not (** binary not *)



(** type of expressions *)
type exp =
    Const of D.Word.t
  | Lval of lval
  | BinOp of binop * exp * exp
  | UnOp of unop * exp
(** type of left values : V for register addressing ; M for memory *)
and lval =
  V of reg 
| M of memory * int

(** type of functions *)
type fct =
    I of reg (* indirect call from register *)
  | D of D.Address.t (* direct call from address *)

(** type of directives for the analyzer *)
type directive_t =
    Remove of Register.t (* remove the register *)
  | Push of exp
  | Pop of reg
  | Undefine of Register.t

(** type of statements *)
type stmt =
    Set     of lval * exp    (** store the expression into the left value                       *)
  | Jcc	    of exp option * jmp_target option        (** (un)conditional branch                *)
  | Call     of fct          (** call                                                           *)
  | Unknown                  (** unknown (partial decoding)                                     *)
  | Undef                    (** undefined (decoding error)                                     *)
  | Nop                      (** no operation                                                   *)
  | Directive of directive_t (** directive/hint for the analyzer *)


(** string conversion *)
let string_of_stmt s = 
  match s with
      Set _ 	    -> "set"
    | Jcc _ 	    -> "jcc"
    | Call _ 	    -> "call"
    | Unknown 	    -> "unknown"
    | Undef 	    -> "undef"
    | Nop 	    -> "nop"
    | Directive _   -> "#directive"

let jmp_target_of_immediate seg i sz = A (D.Address.of_string ((string_of_int seg)^":"^i) sz)

let jmp_target_of_register seg r = R (seg, r)

let rec equal_exp e1 e2 =
  match e1, e2 with
    Const c1, Const c2 			       -> D.Word.compare c1 c2 = 0
  | Lval lv1, Lval lv2 			       -> equal_lval lv1 lv2
  | BinOp(op1, e11, e12), BinOp(op2, e21, e22) -> op1 = op2 && equal_exp e11 e21 && equal_exp e12 e22
  | UnOp(op1, e1), UnOp(op2, e2) 	       -> op1 = op2 && equal_exp e1 e2
  | _, _ 				       -> false

and equal_reg r1 r2 =
  match r1, r2 with
    T r1, T r2 			   -> Register.compare r1 r2 = 0
  | P (l1, u1, r1), P (l2, u2, r2) -> l1 = u1 && l2 = u2 && Register.compare r1 r2 = 0
  | _, _ 			   -> false

and equal_memory m1 m2 =
  match m1, m2 with
    M1 w1, M1 w2 						       -> D.Word.compare w1 w2 = 0
  | M2 (n1, r1), M2 (n2, r2) 					       -> n1 = n2 && equal_reg r1 r2
  | M3 (n11, r11, n12, r12), M3 (n21, r21, n22, r22) 		       -> n11 = n21 && n12 = n22 && equal_reg r11 r21 && equal_reg r12 r22
  | M4 (n1, r1, w1), M4 (n2, r2, w2) 				       -> n1 = n2 && equal_reg r1 r2 && D.Word.compare w1 w2 = 0
  | M5 (n11, r11, n12, r12, w1), M5 (n21, r21, n22, r22, w2) 	       -> n11 = n21 && n12 = n22 && equal_reg r11 r21 && equal_reg r12 r22 && D.Word.compare w1 w2 = 0
  | M6 (n11, n12, r11, n13, r12), M6 (n21, n22, r21, n23, r22) 	       -> n11 = n21 && n12 = n22 && equal_reg r11 r21 && n13 = n23 && equal_reg r12 r22
  | M7 (n11, n12, r1, w1), M7 (n21, n22, r2, w2) 		       -> n11 = n21 && n12 = n22 && equal_reg r1 r2 && D.Word.compare w1 w2 = 0
  | M8 (n11, n12, r11, n13, r12, w1), M8 (n21, n22, r21, n23, r22, w2) -> n11 = n21 && n12 = n22 && n13 = n23 && equal_reg r11 r21 && equal_reg r12 r22 && D.Word.compare w1 w2 = 0
  | _, _ 							       -> false

and equal_lval lv1 lv2 =
  match lv1, lv2 with
    V r1, V r2 		     -> equal_reg r1 r2
  | M (m1, sz1), M (m2, sz2) -> equal_memory m1 m2 && sz1 = sz2
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
    A a1, A a2 		   -> D.Address.compare a1 a2 = 0
  | R (s1, r1), R (s2, r2) -> s1 = s2 && equal_reg r1 r2
  | _, _ 		   -> false

let equal_fct f1 f2 =
  match f1, f2 with
    I r1, I r2 -> equal_reg r1 r2
  | D a1, D a2 -> D.Address.compare a1 a2 = 0
  | _, _       -> false

let equal_stmt s1 s2 =
  match s1, s2 with
    Set(lv1, e1), Set(lv2, e2) 			   -> equal_lval lv1 lv2 && equal_exp e1 e2
  | Jcc (None, None), Jcc(None, None) 		   -> true
  | Jcc (None, Some a1), Jcc (None, Some a2) 	   -> equal_target a1 a2
  | Jcc (Some e1, None), Jcc (Some e2, None) 	   -> equal_exp e1 e2
  | Jcc (Some e1, Some a1), Jcc (Some e2, Some a2) -> equal_exp e1 e2 && equal_target a1 a2
  | Call f1, Call f2 				   -> equal_fct f1 f2
  | Nop, Nop | Undef, Undef | Unknown, Unknown 	   -> true
  | Directive d1, Directive d2 			   -> equal_directive d1 d2
  |_, _ 					   -> false
end

