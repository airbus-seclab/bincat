(*
  C2Newspeak: compiles C code into Newspeak. Newspeak is a minimal language 
  well-suited for static analysis.
  Copyright (C) 2007  Charles Hymans, Olivier Levillain
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.
  
  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.
  
  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

  Charles Hymans
  EADS Innovation Works - SE/CS
  12, rue Pasteur - BP 76 - 92152 Suresnes Cedex - France
  email: charles.hymans@penjili.org

  Olivier Levillain
  email: olivier.levillain@penjili.org
*)

(* TODO: extern storage not well handled !!! 
   By default, we accept extern as if they were declared but not defined 
*)

type t = {
  globals: (string, gdecl) Hashtbl.t;
  init: blk;
  fundecs: (Newspeak.fid, fundec) Hashtbl.t;
  src_lang: Newspeak.src_lang
}

and assertion = token list

and token = 
    SymbolToken of char
  | IdentToken of string
  | LvalToken of (lval * typ)
  | CstToken of Newspeak.cst

and gdecl = {
  global_type: typ;
  storage: storage;
  global_position: Newspeak.location;
  is_used: bool
}

and storage = 
    Extern
  | Declared of initialized

and initialized = bool

(* TODO: code cleanup, remove everything unecessary for link *)
and fundec = {
  arg_identifiers: string list;
  function_type: ftyp;
  body: blk;
  position: Newspeak.location;
}

and typ = 
    Scalar of Newspeak.scalar_t
  | Array of (typ * tmp_size_t)
  | Region of (field list * Newspeak.size_t)

and ftyp = typ list * typ list

and field = Newspeak.offset * typ

and blk = stmt list

and stmt = stmtkind * Newspeak.location

and stmtkind =
    Set of (lval * exp * typ)
  | Decl of (string * typ * blk)
  | Guard of exp
  | Select of (blk * blk)
  | InfLoop of blk
  | DoWith of (blk * Newspeak.lbl)
  | Goto of Newspeak.lbl
(* TODO: remove return value *)
(* in arguments, ftyp, fun exp, outputs *) (*extra int for avoiding ret confusion*)
  | Call of (exp list * ftyp * fn * lval list )
  | UserSpec of assertion

and arg =
  | In    of exp  (* Copy-in only (C style) *)
  | Out   of lval (* Copy-out only (no initializer) *)

and vid = int

and lval =
    Local of string
  | Global of string
  | Deref of (exp * Newspeak.size_t)
  | Shift of (lval * exp)
  | Str of string

and exp =
    Const of Newspeak.cst
  | Lval of (lval * typ)
  | AddrOf of (lval * tmp_nat)
  | AddrOfFun of (Newspeak.fid * ftyp)
  | UnOp of (unop * exp)
  | BinOp of (Newspeak.binop * exp * exp)

and fn =
    FunId of Newspeak.fid
  | FunDeref of exp

and unop =
    Belongs_tmp of (Newspeak.Nat.t * tmp_nat)
  | Coerce of Newspeak.bounds
  | Not
  | BNot of Newspeak.bounds
  | PtrToInt of Newspeak.ikind
  | IntToPtr of Newspeak.ikind
  | Cast of (Newspeak.scalar_t * Newspeak.scalar_t)

(* TODO: code cleanup: think about this! *)
and tmp_nat =
    Unknown (* flexible array *)
  | Known of Newspeak.Nat.t
  | Length of string
  | Mult of (tmp_nat * int)

and tmp_size_t = int option

module String_set :
  sig
    type elt = string
    type t
    val empty : t
    val mem : elt -> t -> bool
    val add : elt -> t -> t
    val union : t -> t -> t
    val iter : (elt -> unit) -> t -> unit
  end


val zero : exp
val zero_f : exp

(** [make_int_coerce t e] wraps e into a coerce expression using
    integer bounds of type t *)
val make_int_coerce : Newspeak.sign_t * Newspeak.size_t -> exp -> exp

val negate : exp -> exp

val dump: t -> unit

val string_of_unop: unop -> string

val string_of_typ : typ -> string

val string_of_tmp_size: tmp_size_t -> string

val string_of_lval: lval -> string

exception Uncomparable

(* More precise type 
   TODO: change name, not well chosen *)
val is_mp_typ : typ -> typ -> bool

val write: string -> t -> unit

val read: string -> t

val string_of_cast: Newspeak.scalar_t -> Newspeak.scalar_t -> string

val cast: Newspeak.scalar_t -> exp -> Newspeak.scalar_t -> exp
