(** The Assembly Intermediate Language *)
module type T =
sig
  type word
  type address

  type reg = 
    T of Register.t
  | P of int * int * Register.t (* (l, u, r) = r[l, u] *)

  type jmp_target = 
    A of address
  | R of int * reg (* R (n, v) <=> Address at n << 4 + v *)

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
    Add  (** addition *)
  | Sub  (** substraction *)
  | Mul  (** unsigned multiplication *)
  | Div  (** unsigned division *)
  | Divs (** signed division *)
  | Shl  (** left logical shift *)
  | Shr  (** right logical shift *)
  | Shrs (** right logical shift with sign *)
  | Mod  (** unsigned modulo *)
  | And  (** bitwise AND *)
  | Or   (** bitwise OR *)
  | Xor  (** bitwise XOR *)
  | Gt   (** comparison greater than *)
  | Eq   (** comparison for equality *)

(** type of unary operation *)
type unop =
    Sign_extension of int
  | Not

(** type of expressions *)
type exp =
    Const of word
  | Lval  of lval
  | BinOp of binop * exp * exp
  | UnOp  of unop * exp

(** type of left values : R for register addressing ; M for memory *)
and lval =
  V of reg 
| M of memory * int (* size in bits of the operand *)

(** type of directives for the analyzer *)
type directive_t =
    Remove   of Register.t (* remove the variable *)
  | Push     of exp 
  | Pop      of reg (* address size of the register for the pop *)
  | Undefine of Register.t (* set value to top *)
 
(** type of functions *)
type fct =
    I of reg (* indirect call from register ; call from memory can not be expressed for the while *)
  | D of address (* direct call from address *)

(** type of statements *)
type stmt =
    Set     of lval * exp (** store the expression into the left value                       *)
  | Jcc	     of exp option * jmp_target option (** (un)conditional branch ; None expression is for unconditional  jump ; None address is for intermediate block translation *)
  | Call     of fct        (** call                                                           *)
  | Unknown                (** unknown (partial decoding)                                     *)
  | Undef                  (** undefined (decoding error)                                     *)
  | Nop                    (** no operation                                                   *)
  | Directive of directive_t      (** directive for the analyzer *)


(* first int is the segment ; second int is the size of the immediate in bits *)
val jmp_target_of_immediate: int -> string -> int -> jmp_target
val jmp_target_of_register: int -> reg -> jmp_target

(** string conversion *)
val string_of_stmt: stmt -> string

val equal_stmt: stmt -> stmt -> bool
end

module Make: functor (D: Data.T) -> (T with type word = D.Word.t and type address = D.Address.t)
