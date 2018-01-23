(*
  C2Newspeak: compiles C code into Newspeak. Newspeak is a minimal language 
  well-suited for static analysis.
  Copyright (C) 2007-2011  Charles Hymans, Olivier Levillain, Sarah Zennou, Etienne Millon
  
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

  Sarah Zennou
  sarah(dot)zennou(at)eads(dot)net

  Etienne Millon
  etienne.millon@eads.net
*)

type t = {
  globals: Newspeak.globals;
  init: blk;
  fundecs: (Newspeak.fid, fundec) Hashtbl.t;
  ptr_sz: Newspeak.size_t;
  src_lang: Newspeak.src_lang;
  abi: Newspeak.abi_t;
}

and fundec = {
  position: Newspeak.location;
  ftyp: Newspeak.ftyp;
  body: blk;
}

and assertion = spec_token list

and spec_token =
  | SymbolToken of char
  | IdentToken of string
  | LvalToken of (lval * Newspeak.typ)
  | CstToken of Newspeak.cst

and stmtkind =
    Set of (lval * exp * Newspeak.scalar_t)
  | Copy of (lval * lval * Newspeak.size_t)
  | Guard of exp
  | Decl of (string * Newspeak.typ * blk)
  | Select of (blk * blk)
  | InfLoop of blk
  | DoWith of (blk * Newspeak.lbl)
  | Goto of Newspeak.lbl
  | Call of funexp
  | UserSpec of assertion

and stmt = stmtkind * Newspeak.location

and blk = stmt list

and funexp =
    FunId of Newspeak.fid
  | FunDeref of (exp * Newspeak.ftyp)

and lval =
    Local of Newspeak.vid
  | Global of string
  | Deref of (exp * Newspeak.size_t)
  | Shift of (lval * exp)

and exp =
    Const of Newspeak.cst
  | Lval of (lval * Newspeak.scalar_t)
  | AddrOf of lval
  | AddrOfFun of (Newspeak.fid * Newspeak.ftyp)
  | UnOp of (Newspeak.unop * exp)
  | BinOp of (Newspeak.binop * exp * exp)

val dump : t -> unit

(** [dump_globals glbdecls] prints the global definitions [glbdecls] to
    standard output. *)
val dump_globals: Newspeak.globals -> unit

val dump_fundec : string -> fundec -> unit


(* Visitor *)

type visitor_t =
    { mutable loc : Newspeak.location
    ; gdecl      : string -> Newspeak.typ -> bool
    ; func       : Newspeak.fid -> fundec -> bool
    ; func_after : unit -> unit
    ; stmt       : stmt -> bool
    ; funexp     : funexp -> bool
    ; exp        : Newspeak.location -> exp -> bool
    ; bexp       : exp -> unit
    ; lval       : lval -> bool
    ; unop       : Newspeak.unop -> unit
    ; binop      : Newspeak.binop -> unit
    ; size_t     : Newspeak.size_t -> unit
    ; length     : Newspeak.length -> unit
    ; typ        : Newspeak.typ -> unit
    }

val visit_nop : visitor_t

class visitor:
object
  method process_gdecl: string -> Newspeak.typ -> bool
  method process_fun: Newspeak.fid -> fundec -> bool
  method process_fun_after: unit -> unit
  method process_stmt: stmt -> bool
  method process_funexp: funexp -> bool
  method process_exp: exp -> bool
(* called on expressions that are used as guards of choices *)
  method process_bexp: exp -> unit
  method process_lval: lval -> bool
  method process_unop: Newspeak.unop -> unit
  method process_binop: Newspeak.binop -> unit
  method process_size_t: Newspeak.size_t -> unit
  method process_length: Newspeak.length -> unit
  method process_typ: Newspeak.typ -> unit

  (* Sets current location *)
  method set_loc: Newspeak.location -> unit
  (* Gets current location *)
  method get_loc: Newspeak.location
  method print_warning: string -> unit
  (* Throws an Invalid_argument in a standard way, with the file and line
     number *)
  method raise_error: string -> unit
end

val visit: visitor_t -> t -> unit

val collect_fid_addrof: t -> Newspeak.fid list

(* Negation of a boolean condition. *)
val negate : exp -> exp

val one : exp
val zero : exp

val string_of_exp : exp -> string
val string_of_stmt : stmt -> string
val string_of_blk : blk -> string

val simplify: bool -> t -> t
val simplify_blk: bool -> blk -> blk

val exp_of_int: int -> exp
val string_of_lval : lval -> string
val string_of_funexp: funexp -> string
val belongs_of_lval: lval -> (Newspeak.bounds * exp) list
val belongs_of_exp: exp -> (Newspeak.bounds * exp) list
val belongs_of_funexp: funexp -> (Newspeak.bounds * exp) list

class builder:
object
(* TODO: should have the same name as in the visitor!!! *)
  method set_curloc: Newspeak.location -> unit
  method curloc: Newspeak.location
  method process_global: string -> Newspeak.typ -> Newspeak.typ
  method process_lval: lval -> lval
  method process_exp: exp -> exp
  method process_blk: blk -> blk
  method enter_stmtkind: stmtkind -> unit
  method process_stmtkind: stmtkind -> stmtkind
  method process_size_t: Newspeak.size_t -> Newspeak.size_t
  method process_offset: Newspeak.offset -> Newspeak.offset
end

val build : builder -> t -> t
