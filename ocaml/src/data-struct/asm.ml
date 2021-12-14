(*
    This file is part of BinCAT.
    Copyright 2014-2021 - Airbus

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

(**************************************************************************************************************************)
(* Intermediate language module *)
(**************************************************************************************************************************)
open Data

(** data type of register operands *)
type reg =
  | T of Register.t         (** a register *)
  | P of Register.t * int * int (** a chunk of a register P (r, l, u) , i.e. r[l, u-1] *)


(** type of binary operations *)
type binop =
  | Add    (** addition *)
  | Sub    (** substraction *)
  | Mul    (** unsigned multiplication *)
  | Div    (** unsigned division *)
  | Mod    (** unsigned modulo *)
  | IMul   (** signed multiplication *)
  | IDiv   (** signed division *)
  | IMod   (** signed modulo *)
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
  | GES (** signed greater than or equal to *)
  | LTS (** signed less than *)

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
  | Lval  of lval              (** a left value *)
  | BinOp of binop * exp * exp (** a binary operation *)
  | UnOp  of unop * exp        (** a unary operation *)
  | TernOp of bexp * exp * exp (** special ternary operator to handle flag update *)

 (** type of left values *)
 and lval =
   | V of reg       (** a register *)
   | M of exp * int (** M(e, n): content of the memory address e on n bit width *)

(** boolean expression *)
and bexp =
  | BUnOp  of bunop * bexp           (** unary boolean operation *)
  | Cmp    of cmp * exp * exp        (** comparison *)
  | BBinOp of logbinop * bexp * bexp (** binary boolean operation *)
  | BConst of bool                   (** boolean constant true of false *)

(** data type of jump targets *)
type jmp_target =
  | A of Address.t (** target is an absolute address *)
  | R of exp       (** target is the value of the expression *)


(** a function is identified either by its name or its address in the code *)
type fun_t =
  | Fun_name of string
  | Fun_addr of Address.t

(** calling convention of functions *)
type calling_convention_t = {
  return: lval;
  arguments: int -> lval;
  callee_cleanup: int -> stmt list;
}

              
(** type of directives for the analyzer *)
and directive_t =
  | Remove of Register.t        (** remove the register *)
  | Forget of lval              (** forget the (partial) content of the given register or memory zone *)
  | Taint of exp option * lval  (** conditional tainting: if the expression is true then the left value must be tainted. None is for unconditional tainting *)
  | Type of lval * Types.t      (** type the left value with the given type *)
  | Unroll of exp * int         (** Unroll (e, bs) set the current unroll value to tmin (e, bs) *)
  | Default_unroll              (** set the current unroll value to the default value (in Config) *)
  | Unroll_until of exp * cmp * exp * int * int
        (** Unroll (e, cmp terminator, bs, sz) set the current unroll value to
            tmin (n, bs) where n is an offset from memory [e].
            This offset is the minimal integer where (sz)[e] cmp terminator is true
        *)
  | Handler of int * Address.t (** Handler(sig_nb, addr): handler of signal number _sig_nb_ is at address _addr_ *)
  | Stub of string * calling_convention_t (** Stub (f, args) is the stub of the function f with args as arguments *)
  | Skip of fun_t * calling_convention_t (** Skip (f, calling_conv) will skip the function _f_ but restablish the stack wrt the calling convention _calling_conv_ *)

(** type of statements *)
and stmt =
  | Set  of lval * exp                     (** store the expression into the left value *)
  | If of bexp * (stmt list) * (stmt list) (** conditional statement *)
  | Jmp  of jmp_target                     (** jump *)
  | Call of jmp_target                     (** call *)
  | Return                                 (** return *)
  | Nop                                    (** no operation *)
  | Directive of directive_t               (** directive/hint for the analyzer *)
  | Assert of bexp * string                (** an assert for invalid results *)

let equal_bunop op1 op2 =
  match op1, op2 with
  | LogNot, LogNot  -> true

let equal_unop op1 op2 =
  match op1, op2 with
  | SignExt i1, SignExt i2 -> i1 = i2
  | ZeroExt i1, ZeroExt i2 -> i1 = i2
  | Not, Not           -> true
  | _, _           -> false

let string_of_binop op =
  match op with
  | Add    -> "+"
  | Sub    -> "-"
  | IMul   -> "*"
  | IDiv   -> "/"
  | Mul    -> "*"
  | Div    -> "/"
  | Mod    -> "%"
  | IMod    -> "%"
  | And    -> "&"
  | Or     -> "|"
  | Xor    -> "xor"
  | Shr    -> ">>"
  | Shl    -> "<<"

let string_of_cmp c =
  match c with
  | EQ  -> "="
  | NEQ -> "!="
  | LEQ -> "<="
  | LT  -> "<"
  | GEQ -> ">="
  | GT  -> ">"
  | LTS -> "<"
  | GES -> ">="


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
  | T r1', T r2'             -> Register.equal r1' r2'
  | P (r1', l1, u1), P (r2', l2, u2) -> Register.equal r1' r2' && l1 = l2 && u1 = u2
  | _, _                 -> false

let rec equal_lval lv1 lv2 =
  match lv1, lv2 with
  | V v1, V v2         -> equal_reg v1 v2
  | M (e1, i1), M (e2, i2) -> i1 = i2 && equal_exp e1 e2
  | _, _           -> false

and equal_exp e1 e2 =
  match e1, e2 with
  | Const c1, Const c2               -> Word.compare c1 c2 = 0
  | BinOp (op1, e11, e12), BinOp (op2, e21, e22) -> op1 = op2 && equal_exp e11 e21 && equal_exp e12 e22
  | UnOp (op1, e1'), UnOp (op2, e2')         -> equal_unop op1 op2 && equal_exp e1' e2'
  | Lval lv1, Lval lv2               -> equal_lval lv1 lv2
  | _, _                     -> false

let string_of_reg r =
  match r with
  | T r'     -> Register.name r'
  | P (r', l, u) -> Printf.sprintf "%s[%d, %d]" (Register.name r') l u



let rec string_of_lval lv extended =
  match lv with
  | V r       -> string_of_reg r
  | M (e, i)  -> Printf.sprintf "(%d)[%s]" i (string_of_exp e extended)

and string_of_exp e extended =
  match e with
  | Const c            -> Word.to_string c
  | Lval lv            -> string_of_lval lv extended
  | BinOp (op, e1, e2) -> Printf.sprintf "(%s %s %s)" (string_of_exp e1 extended) (string_of_binop op) (string_of_exp e2 extended)
  | UnOp (op, e')      -> Printf.sprintf "%s %s" (string_of_unop op extended) (string_of_exp e' extended)
  | TernOp (c, e1, e2) -> Printf.sprintf "(%s?%s:%s)" (string_of_bexp c true) (string_of_exp e1 extended) (string_of_exp e2 extended)

and string_of_bexp e extended =
  match e with
  | BUnOp (o, e')      -> Printf.sprintf "%s %s" (string_of_bunop o) (string_of_bexp e' extended)
  | BBinOp (o, e1, e2) -> Printf.sprintf "(%s %s %s)" (string_of_bexp e1 extended) (string_of_logbinop o) (string_of_bexp e2 extended)
  | Cmp (c, e1, e2)    -> Printf.sprintf "%s %s %s" (string_of_exp e1 extended) (string_of_cmp c) (string_of_exp e2 extended)
  | BConst b           -> string_of_bool b

let string_of_jmp_target t extended =
  match t with
  | A a -> Address.to_string a
  | R e -> Printf.sprintf "%s" (string_of_exp e extended)

let string_of_fun f =
  match f with
  | Fun_name f -> f
  | Fun_addr a -> Data.Address.to_string a
                
let string_of_directive d extended =
  match d with
  | Remove r -> Printf.sprintf "remove %s" (Register.name r)
  | Forget lval -> Printf.sprintf "forget %s" (string_of_lval lval extended)
  | Taint (e, lv) ->
     begin
       match e with
       | None -> Printf.sprintf "taint %s" (string_of_lval lv false)
       | Some e' ->
      Printf.sprintf "if is_tainted (%s) taint %s" (string_of_exp e' false) (string_of_lval lv false)
     end

  | Type (lv, t) -> Printf.sprintf "type(%s, %s)" (string_of_lval lv false) (Types.to_string t)
  | Unroll (e, bs) -> Printf.sprintf "unroll current loop min (%s, %d) times" (string_of_exp e false) bs
  | Default_unroll -> "set unroll value to its default value"
  | Unroll_until (e, cmp, terminator, ub, sz) -> Printf.sprintf "unroll current loop min (n, %d) times with n = minimal offset from e such that (%d)[%s+n] %s %s" ub sz (string_of_exp e false) (string_of_cmp cmp) (string_of_exp terminator false)
  | Stub (f, cc) ->
     if extended then
       Printf.sprintf "%s <- stub of %s" (string_of_lval cc.return extended) f
     else
       Printf.sprintf "stub of %s" f

  | Handler (sig_nb, handler_addr) ->
     Printf.sprintf "the handler of signal %d is set at address %s" sig_nb (Address.to_string handler_addr)
    
  | Skip (f, cc) ->
     let fs = string_of_fun f in
     if extended then
       Printf.sprintf "%s <- skip of %s" (string_of_lval cc.return extended) fs
     else
       Printf.sprintf "skip of %s" fs


let string_of_target tgt =
  match tgt with
  | A addr -> Data.Address.to_string addr
  | R exp -> string_of_exp exp true

let string_of_stmt s extended =
    (* internal function used to factorize code in the printing of If-stmt *)
  let concat to_string ind l =
    List.fold_left (fun acc s -> Printf.sprintf "%s\n %s" acc (to_string ind s)) "" l
  in
  (* ind is a string of spaces to be added to the beginning of a line *)
  let rec to_string ind s =
    match s with
    | Set (dst, src)              -> Printf.sprintf "%s%s <- %s;" ind (string_of_lval dst extended) (string_of_exp src extended)
    | Jmp target                  -> Printf.sprintf "%sjmp %s;"  ind (string_of_jmp_target target extended)
    | If (cond, then_stmts, else_stmts) ->
       let ind' = ind ^ "____" in
       Printf.sprintf "%sif (%s)%s\n %selse%s" ind (string_of_bexp cond extended) (concat to_string ind' then_stmts) ind (concat to_string ind' else_stmts)
    | Call j                     -> Printf.sprintf "%scall %s" ind (string_of_target j)
    | Return                     -> Printf.sprintf "%sret" ind
    | Nop                        -> Printf.sprintf "%snop" ind
    | Directive d                -> Printf.sprintf "%s%s" ind (string_of_directive d extended)
    | Assert (bexp, msg) -> Printf.sprintf "Assert (%s, %s)" (string_of_bexp bexp extended) msg
  in
  to_string "" s

let string_of_stmts stmt_list extended =
  let list_str = List.map (fun s -> string_of_stmt s extended) stmt_list
  in Printf.sprintf "[ %s ]" (String.concat ",\n" list_str)


(** abstract data type for library functions *)
type import_desc_t = {
  name: string;        (** function name *)
  libname: string;     (** name of its library *)
  prologue: stmt list; (** tranfer operations for its prologue *)
  stub: stmt list;     (** transfer operations for the function itself *)
  epilogue: stmt list; (** transfer operations for its epilogue *)
  ret_addr: exp        (** return addr *)
  }


(** returns true whenever the given expression contains the given lvalue *)
let rec with_lval lv e =
  match e with
  | Const _ -> false
  | Lval lv' -> equal_lval lv lv'
  | BinOp (_, e1, e2)
  | TernOp (_, e1, e2)  -> (with_lval lv e1)  || (with_lval lv e2)
  | UnOp (_, e') -> with_lval lv e'

(** returns the length in bits of the given lvalue *)
let lval_length lv =
  match lv with
  | V (T r) -> Register.size r
  | V (P (_r, l, u)) -> u-l+1 
  | M (_, n) -> n
    
