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
*)

open Newspeak

type t = {
  globals: (string, ginfo) Hashtbl.t;
  init: blk;
  fundecs: (string, fundec) Hashtbl.t;
}
and assertion = token list

and token =
  | SymbolToken of char
  | IdentToken of string
  | LvalToken of typ_lv
  | CstToken of cst

and ginfo = typ * location * Npkil.storage

and fundec = {
  arg_identifiers: string list;
  function_type: ftyp;
  body: blk;
  position: location;
}

and typ =
    | Void
    | Scalar of Newspeak.scalar_t
    | Array of (typ * Npkil.tmp_size_t)
    | Struct of (field list * size_t)
    | Union of (field list * size_t)
    | Fun

and ftyp = typ list * typ

(** field's name, offset and typ 
    TODO: seems redundant? could remove the name??
*)
and field = (string * (Newspeak.offset * typ))

and blk = stmt list

and stmt = (stmtkind * Newspeak.location)

and stmtkind =
    | Block of (blk * Newspeak.lbl option)
    | Goto of Newspeak.lbl
    | Decl of (typ * string)
    | Set of (lv * typ * exp)
    | Loop of blk
    | Guard of exp
    | Select of (blk * blk)
    | Switch of (exp * (typ_exp * blk) list * blk)
    | Exp of exp
    | UserSpec of assertion

and typ_lv = (lv * typ) (* TODO: could this be switched to scalar_t too? *)

and typ_exp = (exp * scalar_t)

and lv =
(* variable identified by its unique id. Use fresh_id () to generate
   a new variable *)
    | Local of string
    | Global of string
    | Shift of (lv * exp)
    | Deref of (exp * typ)
(* the boolean is true if stmt is after, false otherwise *)
(* TODO: remove the boolean, by adding temporary variables and then
   having some optimization get
   rid of unnecessary temporary variable??? If better *)
    | BlkLv of (blk * lv * bool)
    | Str of string

and exp =
    | Const of cst
    | Lval of typ_lv
    | AddrOf of typ_lv
    | AddrOfFun of (string * ftyp)
    | Unop of (Npkil.unop * exp)
    | Binop of (Newspeak.binop * exp * exp)
    | Call of (ftyp * funexp * arg list)
    | BlkExp of (blk * exp * bool)

and arg =
  | In    of exp    (* Copy-in only (C style) *)
  | Out   of exp (*used to be typ_lv : Copy-out only (no initializer) *)
  | InOut of exp (*used to be typ_lv : Copy-in + Copy-out *)

and funexp =
    | Fname of string
    | FunDeref of exp

(* TODO: try to have the same constants as newspeak Nil ??*)
and cst =
    | CInt of Nat.t
    | CFloat of (float * string)

(** kind of C int type *)
val int_kind: unit -> Newspeak.ikind

(** type of C int type *)
val int_typ: unit -> typ

val exp_of_int: int -> exp

val exp_of_float: float -> exp

val fresh_id: unit -> vid

(** [normalize_exp e] returns (pref, e, post), where e is an expression without
    side effects (no Pref or Post constructs), and pref and post are blocks
    to be executed respectively before and after e. *)
val normalize_exp: exp -> (blk * exp * blk)

val normalize_lv: lv -> (blk * lv * blk)

val normalize: blk -> blk

val eval_exp: exp -> Newspeak.Nat.t

val cast: (exp * typ) -> typ -> exp

val string_of_typ: typ -> string

(* TODO: should remove this size_of_typ??? *)
val size_of_typ: typ -> int

val is_subtyp: typ -> typ -> bool

val string_of_exp: exp -> string

val string_of_lv: lv -> string

val is_large_blk: blk -> bool

val string_of_blk: blk -> string

val length_of_array: Npkil.tmp_size_t -> lv -> Npkil.tmp_nat

val scalar_of_typ: typ -> scalar_t

val remove_fst_deref: lv -> exp

val print: t -> unit

val size_of: t -> int

val build_if: location -> (exp * blk * blk) -> blk

val exp_is_false: exp -> bool
