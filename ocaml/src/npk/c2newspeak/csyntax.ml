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
module N = Newspeak

type t = (global * N.location) list

and assertion = spec_token list

and spec_token = 
  | SymbolToken of char
  | IdentToken of string
  | CstToken of cst
      
and global = 
    (* true if static *)
  | FunctionDef of (string * ftyp * bool * blk)
  | GlbDecl of (string * decl)
  | GlbUserSpec of assertion

and decl = 
    VDecl of vdecl
  | EDecl of exp
(* struct or union: composite *)
  | CDecl of (field_decl list * is_struct)
  
and vdecl = {
  t: typ;
  is_static: bool;
  is_extern: bool;
  initialization: init option
}

(* true for structure, false for union *)
and is_struct = bool

and field_decl = (typ * string * Newspeak.location)

and ftyp = (typ * string) list option * typ

and typ =
  | Void
  | Int of Newspeak.ikind
  | Bitfield of (Newspeak.ikind * exp)
  | Float of int
  | Ptr of typ
  | Array of (typ * exp option)
  | Comp of string
  | Fun of ftyp
  | Va_arg
  | Typeof of exp
      
and init = 
  | Data of exp
  | Sequence of (exp init_designator * init) list

and 'exp init_designator =
    | InitField of string
    | InitIndex of 'exp
    | InitAnon

and stmt = (stmtkind * N.location)

and blk = stmt list

and stmtkind =
    LocalDecl of (string * decl)
  | If of (exp * blk * blk)
  | CSwitch of (exp * (exp * blk * N.location) list * blk)
      (* init, while exp is true do blk and then blk, 
	 continue jumps before the second blk 
	 init may cotain break or continue stmt!
      *)
  | For of (blk * exp * blk * blk)
  | DoWhile of (blk * exp)
  | Exp of exp
  | Break
  | Continue
  | Return
  | Block of blk
  | Goto of lbl
  | Label of lbl
  | UserSpec of assertion

and lbl = string

and static = bool

and exp = 
  | Cst of cst
  | Var of string
  | RetVar
  | Field of (exp * string)
  | Index of (exp * exp)
  | AddrOf of exp
  | Unop of (unop * exp)
  | IfExp of (exp * exp * exp)
  | Binop of (binop * exp * exp)
  | Call of (exp * exp list)
  | Sizeof of typ
  | SizeofE of exp
  | Offsetof of (typ * offset_exp)
  | Str of string
  | FunName
  | Cast of (exp * typ)
      (* None is a regular assignment *)
  | Set of (exp * binop option * exp)
      (* boolean is true if the operation is applied after the evaluation of the 
	 expression *)
  | OpExp of (binop * exp * bool)
      (* block ended by and expression *)
  | BlkExp of blk
      
and cst = (Cir.cst * typ)

and unop = Not | BNot

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
    OffComp of string
  | OffField of aux_offset_exp * string

(* TODO: this type could probably be simplified *)
and offset_exp =
  | OIdent of string
  | OField of aux_offset_exp * string
  | OArray of aux_offset_exp * string * exp

let char_typ () = Int (N.char_kind ())
  
let int_typ () = Int (N.Signed, !Conf.size_of_int)

let long_typ () = Int (N.Signed, !Conf.size_of_long)

let uint_typ () = Int (N.Unsigned, !Conf.size_of_int)

let exp_of_char c = Cst (Cir.CInt (N.Nat.of_int (Char.code c)), char_typ ())

let exp_of_int i = Cst (Cir.CInt (N.Nat.of_int i), int_typ ())

let nat_of_lexeme base x =
  let read_digit c = (int_of_char c) - (int_of_char '0') in
  let read_hex_digit c =
    if ('0' <= c) && (c <= '9') then (int_of_char c) - (int_of_char '0')
    else if  ('a' <= c) && (c <= 'f') 
    then (int_of_char c) - (int_of_char 'a') + 10
    else (int_of_char c) - (int_of_char 'A') + 10
  in
  let (read_digit, base) =
    match base with
	None -> (read_digit, 10)
      | Some "0" -> (read_digit, 8)
      | Some ("0x"|"0X") -> (read_hex_digit, 16)
      | _ -> Npkcontext.report_error "Csyntax.nat_of_lexeme" "invalid base"
  in
  let v = ref N.Nat.zero in
  let add_digit c =
    let d = read_digit c in
      v := N.Nat.mul_int base !v;
      v := N.Nat.add_int d !v
  in
    String.iter add_digit x;
    !v

(* See C standard ANSI 6.4.4 *)
let int_cst_of_lexeme (base, x, sign, min_sz) = 
  let x = nat_of_lexeme base x in
  let possible_signs = 
    match (base, sign) with
(* TODO: not in conformance with standard. strange *)
	(None, None) -> [N.Signed; N.Unsigned]
      | (Some _, None) -> [N.Signed; N.Unsigned]
      | (_, Some ('u'|'U')) -> [N.Unsigned]
      | _ -> 
	  Npkcontext.report_error "Csyntax.int_cst_of_lexeme" 
	    "unreachable statement"
  in
  let min_sz =
    match min_sz with
	None -> !Conf.size_of_int
      | Some ("L"|"l") -> !Conf.size_of_long
      | Some "LL" -> !Conf.size_of_longlong
      | _ -> 
	  Npkcontext.report_error "Csyntax.int_cst_of_lexeme" 
	    "unreachable statement"
  in
  let is_kind (sign, sz) =
    ((sz >= min_sz)
      && (List.mem sign possible_signs)
      && (Newspeak.belongs x (Newspeak.domain_of_typ (sign, sz))))
  in
  let ikind_tbl =
    [(N.Signed, !Conf.size_of_int); (N.Unsigned, !Conf.size_of_int); 
     (N.Signed, !Conf.size_of_long); (N.Unsigned, !Conf.size_of_long); 
     (N.Signed, !Conf.size_of_longlong); (N.Unsigned, !Conf.size_of_longlong)
    ]    
  in
  let k = 
    try List.find is_kind ikind_tbl 
    with Not_found -> 
      Npkcontext.report_error "Csyntax.int_cst_of_lexeme"
	("unexpected integer constant: "^(N.Nat.to_string x))
  in
    (Cir.CInt x, Int k)

let char_cst_of_lexeme x = (Cir.CInt (N.Nat.of_int x), char_typ ())

(* ANSI C: 6.4.4.2 *)
let float_cst_of_lexeme (value, suffix) =
  let f = 
    try float_of_string value 
    with Failure _->
      Npkcontext.report_error "Csyntax.float_cst_of_lexeme" 
	"float not representable"
  in
(* TODO: should really think about floating points, I don't know whether it
   is really necessary to keep the suffix on the bare string representation of
   the float??? *)
  let (lexeme, sz) = 
    match suffix with
	None -> (value, !Conf.size_of_double)
      | Some 'F' -> (value^"F", !Conf.size_of_float)
      | Some 'L' | Some 'l' -> (value^"L", !Conf.size_of_longdouble)
      | _ -> 
	  Npkcontext.report_error "Csyntax.float_cst_of_lexeme" 
	    "unknown suffix for float"
  in
    (Cir.CFloat (f, lexeme), Float sz)

let string_of_binop op =
  match op with
      Plus -> "+"
    | Minus -> "-"
    | Mult -> "*"
    | Div -> "/"
    | Mod -> "%"
    | Gt -> ">"
    | Eq -> "=="
    | BAnd -> "&"
    | BXor -> "bxor"
    | BOr -> "|"
    | Shiftl -> "<<"
    | Shiftr -> ">>"

let string_of_unop op =
  match op with
      Not -> "!"
    | BNot -> "BNot"

let rec string_of_typ margin t =
  match t with
      Void -> "void"
    | Int (sgn, sz) -> 
	let sgn = 
	  match sgn with
	      N.Unsigned -> "unsigned "
	    | N.Signed -> ""
	in
	let sz = string_of_int sz in
	  sgn^"int"^sz
    | Ptr t -> "*"^(string_of_typ margin t)
    | Array (t, None) -> (string_of_typ margin t)^"[?]"
    | Array (t, Some x) -> (string_of_typ margin t)^"["^(string_of_exp margin x)^"]"
    | Bitfield _ -> "Bitfield"
    | Float _ -> "Float"
    | Comp _ -> "Comp"
    | Fun _ -> "Fun"
    | Va_arg -> "..."
    | Typeof _ -> "typeof"
	
and string_of_exp margin e =
  match e with
      Cst (Cir.CInt c, _) -> N.Nat.to_string c
    | Cst _ -> "Cst"
    | Var x -> x
    | RetVar -> "!RetVar"
    | Field (e, f) -> (string_of_exp margin e)^"."^f
    | Index (e1, e2) -> 
	"("^(string_of_exp margin e1)^")["^(string_of_exp margin e2)^"]"
    | AddrOf _ -> "AddrOf"
    | Unop (op, e) -> (string_of_unop op)^"("^(string_of_exp margin e)^")"
    | IfExp (e1, e2, e3) -> 
	let e1 = string_of_exp margin e1 in
	let e2 = string_of_exp margin e2 in
	let e3 = string_of_exp margin e3 in
	  "("^e1^") ? ("^e2^") : ("^e3^")"
    | Binop (op, e1, e2) -> 
	(string_of_exp margin e1) ^" "^(string_of_binop op)^" "
	^(string_of_exp margin e2)
    | Call _ -> "Call"
    | Offsetof _ -> "Offsetof"
    | Sizeof _ -> "Sizeof"
    | SizeofE _ -> "SizeofE"
    | Str _ -> "Str"
    | FunName -> "FunName"
    | Cast (e, t) -> 
	let e = string_of_exp margin e in
	let t = string_of_typ margin t in
	  "("^t^") "^e
    | Set (lv, None, e) -> 
	(string_of_exp margin lv)^" = "^(string_of_exp margin e)^";"
    | Set _ -> "Set"
    | OpExp _ -> "OpExp"
    | BlkExp _ -> "BlkExp"

and string_of_decl margin d =
  match d with
    | VDecl d -> (string_of_typ margin d.t)
    | CDecl _ -> "ctyp"
    | EDecl _ -> "etyp"

and string_of_stmt margin (x, _) =
  match x with
      Block blk -> "{\n"^(string_of_blk (margin^"  ") blk)^margin^"}"
	  
    | Goto lbl -> "goto "^lbl^";"
	
    | Label lbl -> lbl^": "

    | LocalDecl (x, d) -> 
	let d = string_of_decl margin d in
	  d^" "^x^";"
	
    | If (e, blk1, blk2) -> 
	"if ("^(string_of_exp margin e)^") {\n"
	^(string_of_blk (margin^"  ") blk1)
	^margin^"} else {\n"
	^(string_of_blk (margin^"  ") blk2)
	^margin^"}"
	  
    | For (blk1, e, blk2, blk3) -> 
	(string_of_blk margin blk1)
	^"For (;" ^ (string_of_exp margin e) ^"; ) {\n"
	^(string_of_blk (margin^" ") blk3)
	^(string_of_blk (margin^" ") blk2)
	^margin^"}"

    | DoWhile (blk, e) ->
	"do {\n"
	^(string_of_blk (margin^" ") blk)
	^"} while("^(string_of_exp margin e)^")"

    | CSwitch (e, cases, default) ->
	let margin' = margin^" " in
	let print_case (e, blk, _) s =
	  (margin^"case "^(string_of_exp margin e)^":\n"
	   ^(string_of_blk margin' blk))::s
	in
	let s = List.fold_right print_case cases [] in
	let s = String.concat "\n" s in
	  "switch ("^(string_of_exp margin e)^"){\n"
	  ^s^"\n"
	  ^margin^"default:\n"^
	    (string_of_blk margin' default)
	  ^margin^"}"

    | Exp e -> string_of_exp margin e 

    | Return -> "Return"

    | Break -> "break;"

    | Continue -> "continue;"

    | UserSpec _ -> "UserSpec"

and string_of_blk margin x =
  match x with
      [] -> ""
    | hd::tl -> 
	margin^(string_of_stmt margin hd)^"\n"^(string_of_blk margin tl)
	  
let string_of_ftyp margin (args_t, _) =
  let string_of_arg (t, _) = string_of_typ margin t in
  let args =
    match args_t with
	None -> "? -> ret_t"
      | Some args_t -> ListUtils.to_string string_of_arg ", " args_t
  in
    "("^args^") -> ret_t"

let ftyp_of_typ t =
  match t with
      Fun t -> t
    | _ -> 
	Npkcontext.report_error "Csyntax.ftyp_of_typ" "function type expected"

let string_of_typ = string_of_typ ""

let string_of_fname (args_t, ret_t) name = 
  let string_of_arg_t (t,  _) = string_of_typ t in
  let args_t = 
    match args_t with
	None -> ""
      | Some args_t -> ListUtils.to_string string_of_arg_t ", " args_t
  in
  let ret_t = string_of_typ ret_t in
    ret_t^" "^name^"("^args_t^")"

let print prog =
  let s = ref "" in
  let print (g, _) =
    match g with 
	FunctionDef (name, t, b, blk) ->
	  let b = if b then "static" else "" in
	  let blk = string_of_blk "  " blk in
	  let name = string_of_fname t name in
	    s := !s ^ b ^ name ^ " {\n" ^ blk ^"}"

      | GlbDecl (x, d) -> 
	  let d = string_of_decl "" d in
	    s := !s ^ (d^" "^x^";\n")

      | GlbUserSpec _ -> ()
  in
    List.iter print prog;
    print_endline !s

let string_of_ftyp = string_of_ftyp ""
let string_of_exp = string_of_exp ""
let string_of_blk = string_of_blk ""

let rec size_of globals = ListUtils.size_of size_of_global globals

and size_of_global (x, _) =
  match x with
      FunctionDef (_, _, _, body) -> (size_of_blk body) + 1
    | _ -> 1

and size_of_blk x = ListUtils.size_of size_of_stmt x

and size_of_stmt (x, _) =
  match x with
      If (_, br1, br2) -> (size_of_blk br1) + (size_of_blk br2) + 1
    | CSwitch (_, cases, default) -> 
	1 + (ListUtils.size_of size_of_case cases) + (size_of_blk default)
    | For (init, _, body, final) -> 
	1 + (size_of_blk init) + (size_of_blk body) + (size_of_blk final)
    | DoWhile (body, _) -> 1 + (size_of_blk body)
    | Block body -> 1 + (size_of_blk body)
    | _ -> 1

and size_of_case (_, body, _) = size_of_blk body

let and_bexp e1 e2 =
  IfExp (e1, IfExp (e2, exp_of_int 1, exp_of_int 0), exp_of_int 0)

let or_bexp e1 e2 =
  IfExp (e1, exp_of_int 1, IfExp (e2, exp_of_int 1, exp_of_int 0))

(* TODO: remove this, put in normalize!! and remove it from parser too *)
(* TODO: think about this simplification, this is a bit hacky?? *)
let rec normalize_bexp e =
  match e with
      Var _ | Field _ | Index _ | Call _ | OpExp _ 
    | Set _ | Str _ | Cast _ 
    | Binop ((Plus|Minus|Mult|Div|Mod|BAnd|BXor|BOr|Shiftl|Shiftr), _, _) ->
	Unop (Not, Binop (Eq, e, exp_of_int 0))
    | Unop (Not, e) -> Unop (Not, normalize_bexp e)
    | IfExp (c, e1, e2) -> 
	IfExp (normalize_bexp c, normalize_bexp e1, normalize_bexp e2)
    | _ -> e

