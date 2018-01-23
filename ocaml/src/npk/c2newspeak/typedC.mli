(*
  C2Newspeak: compiles C code into Newspeak. Newspeak is a minimal language 
  well-suited for static analysis.
  Copyright (C) 2009-2011  Charles Hymans, Sarah Zennou
  
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

  Sarah Zennou
  sarah(dot)zennou(at)eads(dot)net
*)

(* TODO: is it possible to force in the data-type things like:
   &t[0] replaces t whenever necessary
*)

type t = {
  global_variables     : (string * glbinfo) list;
  function_declarations: (string * fundec) list;
  user_specifications  : assertion list
}

and glbinfo = (decl * Newspeak.location)

and fundec = {
  function_type: ftyp;
  body	       : blk;
  position     : Newspeak.location;
}

and assertion = spec_token list

and spec_token = 
    | SymbolToken of char
    | IdentToken  of string
    | LvalToken	  of typ_exp
    | CstToken	  of Cir.cst

and decl = {
  name		: string;
  t		: typ;
  is_static	: bool;
  is_extern	: bool;
  initialization: init option
}

and compdef    = (field_decl list * is_struct)

and is_struct  = bool

and field_decl = (string * typ)

and ftyp       = (typ * string) list option * typ

and typ        =
    | Void
    | Int      of Newspeak.ikind
    | Bitfield of (Newspeak.ikind * exp)
    | Float    of int
    | Ptr      of typ
    | Array    of array_typ
    | Comp     of aux_comp 
    | Fun      of ftyp
    | Va_arg

and aux_comp = Unknown of string | Known of compdef

and array_typ = typ * exp option

and init = 
    | Data of typ_exp
    | Sequence of (typ_exp Csyntax.init_designator * init) list

and stmt = (stmtkind * Newspeak.location)

and blk = stmt list

and stmtkind =
  | LocalDecl of (string * decl)
  | If	      of (exp * blk * blk)
      (* third parameter is the default case *)
  | CSwitch   of (typ_exp * (exp * blk * Newspeak.location) list * blk)
  | For	      of (blk * exp * blk * blk)
  | DoWhile   of (blk * exp)
  | Exp	      of typ_exp
  | Break
  | Continue
  | Return
  | Block     of blk
  | Goto      of lbl
  | Label     of lbl
  | UserSpec  of assertion

and lbl = string

and exp = 
    | Cst      of (Cir.cst * typ)
    | Local    of string
    | Global   of string
    | Field    of (typ_exp * string)
    | Index    of (exp * array_typ * typ_exp)
    | Deref    of typ_exp
    | AddrOf   of typ_exp
    | Unop     of (unop * typ * exp)
    | IfExp    of (exp * typ_exp * typ_exp * typ)
    | Binop    of ((binop * typ) * typ_exp * typ_exp)
    | Call     of (funexp * ftyp * typ_exp list)
    | Sizeof   of typ
    | Offsetof of (typ * offset_exp)
    | Str      of string
    | FunName
    | Cast     of (typ_exp * typ)
(* None is a regular assignment *)
    | Set      of (typ_exp * (binop * typ) option * typ_exp)
(* boolean is true if the operation is applied after the evaluation of the 
   expression *)
    | OpExp    of ((binop * typ) * typ_exp * bool)
    | BlkExp   of (blk * bool)

and funexp =
    Fname of string
  | FunDeref of typ_exp

and typ_exp = (exp * typ)

and unop = Not | BNot of Newspeak.ikind

and binop =
    | Plus
    | Minus
    | Mult
    | Div
    | Mod
    | Gt
    | Eq
    | BAnd
    | BXor
    | BOr
    | Shiftl
    | Shiftr


and aux_offset_exp = 
  | OffComp of string * aux_comp (* the string is the name of the aux_comp *)
  | OffField of aux_offset_exp * string * aux_comp (* the string is the name of the last field *)

and offset_exp =
  | OIdent of string
  | OField of aux_offset_exp * string
  | OArray of aux_offset_exp * string * typ_exp

val char_typ	 : unit -> typ
val uint_typ	 : unit -> typ
val int_typ	 : unit -> typ

val exp_of_char	 : char -> exp

val exp_of_int	 : int -> exp

val deref_typ	 : typ -> typ

val min_ftyp	 : ftyp -> ftyp -> ftyp

val min_typ	 : typ -> typ -> typ

val string_of_exp: exp -> string

val string_of_typ: typ -> string

val ftyp_of_typ	 : typ -> ftyp

val promote	 : Newspeak.ikind -> Newspeak.ikind

val comp_of_typ	 : typ -> (field_decl list * bool)

val equals_typ	 : typ -> typ -> bool

  (** [read name] retrieves the list of file names, program and size of
      pointers from a typedC npk file. **)
val read: string -> t

(** [write name prog] write the program prog into the file name *)
val write : string -> t -> unit
