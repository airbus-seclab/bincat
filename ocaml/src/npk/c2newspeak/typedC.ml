(*
  C2Newspeak: compiles C code into Newspeak. Newspeak is a minimal language 
  well-suited for static analysis.
  Copyright (C) 2009, 2011  Charles Hymans, Sarah Zennou
  
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
(* TODO: after typing do:
   side-effects removal: (lv++, lv+=e
   boolean expression normalization
   array access, pointer deref or addr_of normalization
   implicit cast additions
*)
module Nat = Newspeak.Nat

type t = {
  global_variables     : (string * glbinfo) list;
  function_declarations: (string * fundec) list;
  user_specifications  : assertion list
}
(* TODO: put the location inside the decl?? *)
and glbinfo = (decl * Newspeak.location)

and fundec = {
  function_type: ftyp;
  body	       : blk;
  position     : Newspeak.location;
}

and assertion = spec_token list

and spec_token = 
  | SymbolToken of char
  | IdentToken of string
  | LvalToken of typ_exp
  | CstToken of Cir.cst

and decl = {
  name: string;
  t: typ;
  is_static: bool;
  is_extern: bool;
  initialization: init option
}

and compdef = (field_decl list * is_struct)

(* true for a structure *)
and is_struct = bool

and field_decl = (string * typ)

and ftyp = (typ * string) list option * typ
      
and typ =
  | Void
  | Int of Newspeak.ikind
  | Bitfield of (Newspeak.ikind * exp)
  | Float of int
  | Ptr of typ
  | Array of array_typ
  | Comp of aux_comp
  | Fun of ftyp
  | Va_arg
     
and aux_comp = Unknown of string | Known of compdef

and array_typ = typ * exp option
 
and init = 
  | Data of typ_exp
  | Sequence of (typ_exp Csyntax.init_designator * init) list

and stmt = (stmtkind * Newspeak.location)

and blk = stmt list

and stmtkind =
    LocalDecl of (string * decl)
  | If of (exp * blk * blk)
  | CSwitch of (typ_exp * (exp * blk * Newspeak.location) list * blk)
      (* init, while exp is true do blk and then blk, 
	 continue jumps before the second blk 
	 init may contain break or continue stmt!
      *)
  | For of (blk * exp * blk * blk)
  | DoWhile of (blk * exp)
  | Exp of typ_exp
  | Break
  | Continue
  | Return
  | Block of blk
  | Goto of lbl
  | Label of lbl
  | UserSpec of assertion

and lbl = string

and exp = 
    | Cst of (Cir.cst * typ)
    | Local of string
    | Global of string
    | Field of (typ_exp * string)
    | Index of (exp * array_typ * typ_exp)
    | Deref of typ_exp
    | AddrOf of typ_exp
    | Unop of (unop * typ * exp)
    | IfExp of (exp * typ_exp * typ_exp * typ)
    | Binop of ((binop * typ) * typ_exp * typ_exp)
    | Call of (funexp * ftyp * typ_exp list)
    | Sizeof of typ
    | Offsetof of (typ * offset_exp)
    | Str of string
    | FunName
    | Cast of (typ_exp * typ)
(* None is a regular assignment *)
    | Set of (typ_exp * (binop * typ) option * typ_exp)
(* boolean is true if the operation is applied after the evaluation of the 
   expression *)
    | OpExp of ((binop * typ) * typ_exp * bool)
    | BlkExp of (blk * bool)

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
  | OffComp of string * aux_comp 
  | OffField of aux_offset_exp * string * aux_comp

and offset_exp =
  | OIdent of string
  | OField of aux_offset_exp * string
  | OArray of aux_offset_exp * string * typ_exp

let char_typ () = Int (Newspeak.char_kind ())

let int_kind () = (Newspeak.Signed, !Conf.size_of_int)

let uint_typ () = Int (Newspeak.Unsigned, !Conf.size_of_int)
let int_typ () = Int (int_kind ())

(* TODO: put in cir *)
let exp_of_char c = Cst (Cir.CInt (Nat.of_int (Char.code c)), char_typ ())

let exp_of_int i = Cst (Cir.CInt (Nat.of_int i), int_typ ())

let comp_of_typ t =
  match t with
      Comp c -> begin
	match c with
	    Known c -> c
	  | Unknown s -> 
	      Npkcontext.report_error "Csyntax.comp_of_typ" 
		("incomplete struct or union type " ^ s)
      end
    | _ -> 
	Npkcontext.report_error "Csyntax.comp_of_typ" 
	  "struct or union type expected"

let ftyp_of_typ t = 
  match t with
      Fun ft -> ft
    | _ -> Npkcontext.report_error "CoreC.ftyp_of_typ" "function type expected"

let deref_typ t =
  match t with
      Ptr t -> t
    | _ -> Npkcontext.report_error "CoreC.deref_typ" "pointer type expected"

let rec string_of_exp e =
  match e with
      Cst (Cir.CInt c, _) 	      -> Newspeak.Nat.to_string c
    | Cst _ 			      -> "Cst"
    | Local x | Global x 	      -> x
    | Field ((e, _), f) 	      -> (string_of_exp e)^"."^f
    | Index (e1, _, (e2, _)) 	      -> 
	"("^(string_of_exp e1)^")["^(string_of_exp e2)^"]"
    | Deref (e, _) 		      -> "*("^(string_of_exp e)^")"
    | AddrOf (e, _) 		      -> "&("^(string_of_exp e)^")"
    | Unop (_, _, e) 		      -> "op("^(string_of_exp e)^")"
    | IfExp (e1, (e2, _), (e3, _), _) -> 
	let e1 = string_of_exp e1 in
	let e2 = string_of_exp e2 in
	let e3 = string_of_exp e3 in
	  "("^e1^") ? ("^e2^") : ("^e3^")"
    | Binop (_, (e1, _), (e2, _))     -> 
	(string_of_exp e1) ^" op "^(string_of_exp e2)
    | Call _ 			      -> "Call"
    | Offsetof _ 		      -> "Offsetof"
    | Sizeof _ 			      -> "Sizeof"
    | Str _ 			      -> "Str"
    | FunName 			      -> "FunName"
    | Cast ((e, _), _) 		      -> 
	let e = string_of_exp e in
	  "(typ) "^e
    | Set ((lv, _), None, (e, _))     -> (string_of_exp lv)^" = "^(string_of_exp e)^";"
    | Set _ 			      -> "Set"
    | OpExp _ 			      -> "OpExp"
    | BlkExp _ 			      -> "BlkExp"

let rec string_of_typ t =
  match t with
    | Void -> "void"
    | Int (sign, sz) -> 
	let sign =
	  match sign with
	      Newspeak.Signed -> ""
	    | Newspeak.Unsigned -> "u"
	in
	  sign^"int"^(string_of_int sz)^"_t"
    | Bitfield _ -> "Bitfield"
    | Float _ -> "Float"
    | Ptr t' -> (string_of_typ t')^" *"
    | Array _ -> "Array"
    | Comp cmp -> (string_of_aux_cmp cmp)
    | Fun ft -> string_of_ftyp ft
    | Va_arg -> "va_arg"

and string_of_aux_cmp cmp =
  match cmp with
      Unknown s            -> "(Unknown struct or union "^ s^")"
    | Known (l, is_struct) -> 
	let start  = if is_struct then "struct" else "union" in
	let l' 	   = List.map (fun (s, t) -> (string_of_typ t)^" "^s^"; ") l in
	let fields = List.fold_left (fun s s' -> s'^s) "" (List.rev l') in
	start^" {"^fields^"}"

and string_of_ftyp (args_t, ret_t) =
  let args_t = 
    match args_t with
	None -> ""
      | Some l -> string_of_args_t l
  in
  let ret_t = string_of_typ ret_t in
    args_t^" -> "^ret_t

and string_of_args_t x =
  match x with
      (t, _)::[] -> string_of_typ t
    | (t, _)::tl -> (string_of_typ t)^", "^(string_of_args_t tl)
    | [] -> "void"

let rec equals_typ t1 t2 = 
  match (t1, t2) with
    | (Int k1, Int k2)
    | (Bitfield (k1, _), Bitfield (k2, _)) -> k1 = k2
    | (Ptr t1, Ptr t2)
    | (Array (t1, _), Array (t2, _)) 	   -> equals_typ t1 t2
    | (Fun ft1, Fun ft2) 		   -> equals_ftyp ft1 ft2
    | (Comp c1, Comp c2) 		   -> c1 = c2
    | _ 				   -> t1 = t2
	  
and equals_ftyp (args1, ret1) (args2, ret2) =
  let b =
    match (args1, args2) with
	(Some args1, Some args2) -> 
	  (List.for_all2 (fun (t1, _) (t2, _) -> equals_typ t1 t2) args1 args2)
      | (None, None) -> true
      | _ -> false
  in
    b && (equals_typ ret1 ret2)

let min_ftyp (args_t1, ret_t1) (args_t2, ret_t2) =  
  let equals (t1, _) (t2, _) = equals_typ t1 t2 in

  let args_t =  
    match (args_t1, args_t2) with  
        (None, args_t) | (args_t, None) -> args_t  
      | (Some args_t1, Some args_t2) ->
	  let eq = 
	    try List.for_all2 equals args_t1 args_t2 
	    with Invalid_argument _ -> false
	  in
            if not eq then begin
              Npkcontext.report_error "TypedC.min_ftyp"
		"different argument types for function"
            end;
            Some args_t1
  in
    if (not (equals_typ ret_t1 ret_t2)) then begin
      Npkcontext.report_error "TypedC.min_ftyp" 
	"different return types for unction"
    end;
    (args_t, ret_t1)

let min_typ t1 t2 =
  match (t1, t2) with
      (Array (_, None), Array _) -> t2
    | _ -> t1


	
let promote k = 
  match k with
      (_, n) when n < !Conf.size_of_int -> int_kind ()
    | _ -> k

let write name prog =
  let cout = open_out_bin name in
    Marshal.to_channel cout "TNPK!" [];
    Marshal.to_channel cout prog [];
    close_out cout
      
let read name =
  try
    let cin = open_in_bin name in
    let str = Marshal.from_channel cin in
    if str <> "TNPK!" then
      invalid_arg ("TypedC.read: "^name^" is not a typed npk file");
    let res = Marshal.from_channel cin in
    close_in cin;
    res
  with Failure _ ->
    invalid_arg ("TypedC.read: unable to open "^name)
