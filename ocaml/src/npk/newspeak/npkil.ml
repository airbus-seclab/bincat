(*
  C2Newspeak: compiles C code into Newspeak. Newspeak is a minimal language 
  well-suited for static analysis.
  Copyright (C) 2007-2022  Charles Hymans, Olivier Levillain
  
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

(* TODO: should count local variables from beginning of function !! *)

module N = Newspeak

type t = {
  globals: (string, gdecl) Hashtbl.t;
  init: blk;
  fundecs: (N.fid, fundec) Hashtbl.t;
  src_lang: N.src_lang
}

and gdecl = {
  global_type: typ;
  storage: storage;
  global_position: N.location;
  is_used: bool
}

and storage = 
    Extern
  | Declared of initialized

and initialized = bool

and fundec =  {
  arg_identifiers: string list;
  function_type: ftyp;
  body: blk;
  position: N.location;
}

and stmtkind =
    Set of (lval * exp * typ)
  | Decl of (string * typ * blk)
  | Guard of exp
  | Select of (blk * blk)
  | InfLoop of blk
  | DoWith of (blk * N.lbl)
  | Goto of N.lbl
(* TODO: remove return value *)
(* in arguments, ftyp, fun exp, outputs *)
  | Call of (exp list * ftyp * fn * lval list )
  | UserSpec of assertion

(* TODO: remove this type, unused *)
and arg =
  | In    of exp  (* Copy-in only (C style) *)
  | Out   of lval (* Copy-out only (no initializer) *)

and assertion = token list

and token = 
    SymbolToken of char
  | IdentToken of string
  | LvalToken of (lval * typ)
  | CstToken of Newspeak.cst

and stmt = stmtkind * N.location

and blk = stmt list

and vid = int

and lval =
    Local of string
  | Global of string
  | Deref of (exp * N.size_t)
  | Shift of (lval * exp)
  | Str of string

and exp =
    Const of N.cst
  | Lval of (lval * typ)
  | AddrOf of (lval * tmp_nat)
  | AddrOfFun of (N.fid * ftyp)
  | UnOp of (unop * exp)
  | BinOp of (N.binop * exp * exp)

and fn =
    FunId of N.fid
  | FunDeref of exp

and unop =
(* right bound is excluded! *)
      Belongs_tmp of (N.Nat.t * tmp_nat)
    | Coerce of N.bounds
    | Not
    | BNot of N.bounds
    | PtrToInt of N.ikind
    | IntToPtr of N.ikind
    | Cast of (N.scalar_t * N.scalar_t)

and typ = 
    Scalar of N.scalar_t
  | Array of (typ * tmp_size_t)
  | Region of (field list * N.size_t)

and tmp_size_t = int option

and ftyp = typ list * typ list

and field = N.offset * typ

and tmp_nat = 
    Unknown (* flexible array *)
  | Known of N.Nat.t
  | Length of string (* length of global array *)
  | Mult of (tmp_nat * int)

module String_set = 
  Set.Make (struct type t = string let compare = Stdlib.compare end)

let zero = Const (N.CInt N.Nat.zero)
let zero_f = Const (N.CFloat (0., "0."))

let make_int_coerce t e = UnOp (Coerce (Newspeak.domain_of_typ t), e)

let rec seq sep f l =
  match l with
    | [] -> ""
    | [e] -> f e
    | e::r -> (f e)^sep^(seq sep f r)

let string_of_size_t = string_of_int

let string_of_sign_t sg =
  match sg with
      N.Unsigned -> "u"
    | N.Signed -> ""

let string_of_scalar s =
  match s with
      N.Int (sg,sz) -> (string_of_sign_t sg)^"int"^(string_of_size_t sz)
    | N.Float sz -> "float" ^ (string_of_size_t sz)
    | N.Ptr -> "ptr"
    | N.FunPtr -> "fptr"

let string_of_tmp_size sz =
  match sz with
      Some sz -> string_of_size_t sz
    | None -> "?"

let rec string_of_typ t =
  match t with
      Scalar s -> string_of_scalar s
    | Array (t, sz) -> (string_of_typ t)^"["^(string_of_tmp_size sz)^"]"
    | Region (lst, sz) ->
	let string_of_elt (off, t) = 
	  (string_of_typ t)^" "^(string_of_size_t off) 
	in
	  "{"^(seq ";" string_of_elt lst)^"}"^(string_of_size_t sz)

let string_of_fid fid = fid

let rec string_of_tmp_nat x =
  match x with
      Unknown 	  -> "?"
    | Known i 	  -> N.Nat.to_string i
    | Length v 	  -> "len("^v^")"
    | Mult (v, n) -> "("^(string_of_tmp_nat v)^" * "^(string_of_int n)^")"

let string_of_unop (op: unop) =
  match op with
      Belongs_tmp (l, u) ->
	"belongs["^l^","^(string_of_tmp_nat u)^"-1]"
    | Coerce r -> "coerce"^(Newspeak.string_of_bounds r)
    | Cast (typ, typ') ->
	"("^(string_of_scalar typ')^" <= "^(string_of_scalar typ)^")"
    | Not -> "!"
    | BNot _ -> "~"
    | PtrToInt i -> "("^(string_of_scalar (N.Int i))^")"
    | IntToPtr _ -> "(ptr)"
	  
let rec string_of_lval lv =
  match lv with
      Local vid -> vid
    | Global name -> "Global("^name^")"
    | Deref (e, sz) -> "["^(string_of_exp e)^"]"^(string_of_size_t sz)
    | Shift (lv, sh) -> (string_of_lval lv)^" + "^(string_of_exp sh)
    | Str str -> str

and string_of_exp e =
  match e with
      Const c -> Newspeak.string_of_cst c
    | Lval (lv, t) -> (string_of_lval lv)^"_"^(string_of_typ t)
    | AddrOf (lv, sz) -> "&_"^(string_of_tmp_nat sz)^"("^(string_of_lval lv)^")"
    | AddrOfFun (fid, _) -> "&fun"^(string_of_fid fid)

    | UnOp (Not, BinOp (op, e1, e2)) ->
	"("^(string_of_exp e2)^" "^(N.string_of_binop op)^
	  " "^(string_of_exp e1)^")"

    | BinOp (op, e1, e2) ->
	"("^(string_of_exp e1)^" "^(N.string_of_binop op)^
	  " "^(string_of_exp e2)^")"
	  
    | UnOp (op, exp) -> (string_of_unop op)^" "^(string_of_exp exp)

	  
and string_of_fn f =
  match f with
      FunId fid -> (string_of_fid fid)
    | FunDeref exp -> "["^(string_of_exp exp)^"]"

let rec string_of_exp_list l =
  match l with
      [] -> ""
    | e::[] -> string_of_exp e
    | e::tl -> string_of_exp e ^ ", " ^ string_of_exp_list tl

let dump prog = 
  let cur_fun = ref "" in
  let lbl_index = ref 0 in

  let string_of_lbl l = "lbl"^(string_of_int l) in

  let rec dump_blk align b =
    match b with
      | hd::[] -> dump_stmt align true hd
      | hd::r ->
	  dump_stmt align false hd;
	  List.iter (dump_stmt align false) r
      | [] -> ()

  and dump_stmt align only (sk, _) =
    print_string align;
    match sk with
	Set (lv, e, t) ->
	  print_endline ((string_of_lval lv)^" =("^(string_of_typ t)^
			    ") "^(string_of_exp e)^";")

      | Decl (name, t, body) ->
	  if only then begin
	    print_endline ((string_of_typ t)^" "^name^";");
	    dump_blk align body
	  end else begin
	    print_endline "{";
	    let new_align = align^"  " in
	      print_string new_align;
		print_endline ((string_of_typ t)^" "^name^";");
		dump_blk new_align body;
		print_endline (align^"}")
	    end
	     
      | DoWith  (body, lbl) ->
	  print_endline "do {";
	  dump_blk (align^"  ") body;
	  print_endline (align^"} with lbl"^(string_of_int lbl)^":");

      | Goto l -> print_endline ("goto "^(string_of_lbl l)^";")
	    
      | Call (args, _, f, _) -> 
	  let args = string_of_exp_list args in
	    print_endline ((string_of_fn f)^"("^args^");")
	    
      | Guard b -> print_endline ("guard("^(string_of_exp b)^");")

      | Select (body1, body2) ->
	  print_endline (align^"choose {");
	  print_endline (align^" -->");
	  dump_blk (align^"  ") body1;
	  print_endline (align^" -->");
	  dump_blk (align^"  ") body2;
	  print_endline (align^"}")

      | InfLoop body -> 
	  print_endline "while (1) {";
	  dump_blk (align^"  ") body;
	  print_endline (align^"}")

      | UserSpec _ -> print_endline (align^"UserSpec;")
  in
 
  let dump_fundec name body =
    cur_fun := name;
    lbl_index := 0;
    print_endline (name^"() {");
    dump_blk "  " body;
    print_endline "}";
    print_newline ()
  in

  let print_usedglbs title globs =
    print_endline title;
    let print_used_global x declaration =
      if declaration.is_used then print_endline x
    in
    Hashtbl.iter print_used_global globs;
    print_newline ()
  in

  let print_glob n declaration =
    let str = (string_of_typ declaration.global_type)^" "^n in
    let str = 
      match declaration.storage with
	  Extern -> "extern "^str
	| _ -> str 
    in
      print_endline (str^";")
  in

  let print_fundef n fundec =
    dump_fundec n fundec.body;
    print_newline ()
  in
    print_usedglbs "Global used" prog.globals;

    print_endline "Global variables";
    Hashtbl.iter print_glob prog.globals;
    print_newline ();

    print_endline "Function definitions";
    Hashtbl.iter print_fundef prog.fundecs

exception Uncomparable

(* TODO: this is no good recode. Careful. *)
let is_mp_typ t1 t2 =
  let rec is_mp_typs_aux t1 t2 =
    match (t1, t2) with
	(Scalar sc1, Scalar sc2) when sc1 = sc2 -> true

      | (Array (t1, None), Array (t2, Some _)) -> 
	  let _ = is_mp_typs_aux t1 t2 in
	    false

      | (Array (t1, _), Array (t2, None)) -> is_mp_typs_aux t1 t2

      | (Array (t1, Some l1), Array (t2, Some l2)) when l1 = l2 ->
	  is_mp_typs_aux t1 t2
    
      | (Region (f1, n1), Region (f2, n2)) when n1 = n2 ->
	  is_mp_fields f1 f2
	    
      | _ -> raise Uncomparable

  and is_mp_fields f1 f2 =
    match (f1, f2) with
	([], []) -> true
      | ((o1, t1)::f1, (o2, t2)::f2) when o1 = o2 ->
	  (is_mp_fields f1 f2) && (is_mp_typs_aux t1 t2)
      | _ -> raise Uncomparable
  in
    is_mp_typs_aux t1 t2

let write out_name prog = 
  Npkcontext.print_debug ("Writing "^(out_name)^"...");
  let ch_out = open_out_bin out_name in
    Marshal.to_channel ch_out "NPKO" [];
    Marshal.to_channel ch_out prog [];
    close_out ch_out;
    Npkcontext.print_debug ("Writing done.")
    
let read fname =
  let cin = open_in_bin fname in
    Npkcontext.print_debug ("Importing "^fname^"...");
    let str = Marshal.from_channel cin in
      if str <> "NPKO" then begin 
	close_in cin;
	Npkcontext.report_error 
	  "Npkil.read_header" (fname^" is an invalid .npko file")
      end;
      let prog = Marshal.from_channel cin in
	Npkcontext.print_debug ("Importing done.");
	close_in cin;
	prog

let string_of_cast t1 t2 =
  match t1, t2 with
      N.Int _, N.Ptr -> "from integer to pointer"
    | N.Ptr, N.Int _ -> "from pointer to integer"
    | _ -> (string_of_scalar t1)^" -> "^(string_of_scalar t2)

let print_castor_err t t' =
  Npkcontext.report_accept_warning "Npkil.print_castor_err" 
    ("dirty cast "^(string_of_cast t t')) Npkcontext.DirtyCast

(* TODO: code cleanup: this could be also used by cilcompiler ? *)
let cast t e t' =
    match t, t' with
      _ when t = t' -> e
    | N.Int _, (N.Ptr|N.FunPtr) when e = zero -> Const N.Nil
    | N.Ptr, N.Int ((_, n) as k) when n = !Conf.size_of_ptr -> 
	print_castor_err t t';
	UnOp (PtrToInt k, e)
    | N.Int ((_, n) as k), N.Ptr when (n = !Conf.size_of_ptr) -> 
	print_castor_err t t';
	UnOp (IntToPtr k, e)
    | N.FunPtr, N.Ptr ->
	print_castor_err t t';
	UnOp (Cast (t, t'), e)
    | N.Ptr, N.FunPtr ->
	print_castor_err t t';
	UnOp (Cast (t, t'), e)
    | N.Float _, N.Float _ | N.Int _, N.Float _ -> UnOp (Cast (t, t'), e)
    | N.Float _, N.Int (sign, _) -> 
	if (sign = N.Unsigned) then begin
	  Npkcontext.report_warning "Npkil.cast"
	    ("cast from float to unsigned integer: "
	      ^"sign may be lost: "^(string_of_cast t t'))
	end;
	UnOp (Cast (t, t'), e)
    | N.Int (_, n), N.FunPtr when n = !Conf.size_of_ptr -> 
	print_castor_err t t';
	UnOp (Cast (t, t'), e)
    | _ -> 
	Npkcontext.report_error "Npkil.cast"
	  ("invalid cast "^(string_of_cast t t'))

let rec negate e =
  match e with
    | UnOp (Not, BinOp (N.Eq t, e1, e2)) -> BinOp (N.Eq t, e1, e2)
    | UnOp (Not, e) -> e
    | BinOp (N.Gt t, e1, e2) -> UnOp (Not, BinOp (N.Gt t, e1, e2))
    | BinOp (N.Eq t, e1, e2) -> UnOp (Not, BinOp (N.Eq t, e1, e2))
    | UnOp (Coerce i, e) -> UnOp (Coerce i, negate e)
    | _ -> UnOp (Not, e)

