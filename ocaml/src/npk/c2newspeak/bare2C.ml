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

open BareSyntax
module T = Csyntax

let gen_tmp_id =
  let tmp_cnt = ref 0 in
  let gen_tmp_id () = 
    incr tmp_cnt;
    Temps.to_string !tmp_cnt (Temps.Misc "parser")
  in
    gen_tmp_id

(* TODO: try to remove this global table *)
let typedefs = Hashtbl.create 100

let init_tbls () =
  Hashtbl.clear typedefs;
(* initialize table of predefined types *)
(* GNU C predefined types *)
(* TODO: clean up put in gnuc.ml and think about architecture *)
  if !Npkcontext.accept_gnuc 
  then Hashtbl.add typedefs "_Bool" (Csyntax.Int (Newspeak.Unsigned, 1))

let _ = 
  init_tbls ()

let define_type x t = Hashtbl.add typedefs x t

let apply_attrs attrs t =
  match (attrs, t) with
      ([], _) -> t
    | (new_sz::[], T.Int (sign, _)) -> T.Int (sign, new_sz)
    | (_::[], _) -> 
	Npkcontext.report_error "NpkParser.apply_attr" 
	  "wrong type, integer expected"
    | _ -> 
	Npkcontext.report_error "NpkParser.apply_attr" 
	  "more than one attribute not handled yet"

let rec normalize_base_typ t =
  match t with
    | Integer k -> [], T.Int k
    | Float n -> [], T.Float n
    | Void -> [], T.Void
    | Va_arg -> [], T.Va_arg
    | Name x -> [], Hashtbl.find typedefs x
    | Composite ((_, (n, _)) as v) -> normalize_compdef v, T.Comp n
    | TypeofExpr e -> [], T.Typeof (process_exp e)
    | Enum None -> [], T.Int (Cir.int_kind ())
    | Enum (Some f) -> define_enum f, T.Int (Cir.int_kind ())
    | Label -> [], T.Ptr T.Void
    | PtrTo t ->
            let (sdecl, t') = normalize_base_typ t in
            sdecl, T.Ptr t'
    | ArrayOf (t, e) ->
            let (sdecl, t') = normalize_base_typ t in
            let e' = process_exp e in
            sdecl, T.Array (t', Some e')

and define_enum e =
  let rec define_enum e n =
    match e with
	(x, v)::tl ->
	  let n = 
	    match v with
		None -> n
	      | Some n -> process_exp n
	  in
	  let n' = Csyntax.Binop (Csyntax.Plus, n, Csyntax.exp_of_int 1) in
	    (x, Csyntax.EDecl n)::(define_enum tl n')
      | [] -> []
  in
    define_enum e (Csyntax.exp_of_int 0)

and normalize_compdef (is_struct, (n, f)) =
  match f with
      None -> []
    | Some f -> 
	let (decls, f) = normalize_fields f in
	  (decls@(n, T.CDecl (f, is_struct))::[])

and normalize_fields f =
  match f with
      (b, v, bits)::tl ->
	let (decls, (t, x, loc)) = normalize_decl (b, v) in
	let t =
	  match (bits, t) with
	      (None, _) -> t
	    | (Some n, T.Int k) -> T.Bitfield (k, process_exp n)
	    | _ -> 
		Npkcontext.report_error "Bare2C.normalize_field" 
		  "bit-fields allowed only with integer types"
	in
	let x = 
	  match x with
	      Some x -> x
	    | None -> "!anonymous_field"
	in
	let (decls', f) = normalize_fields tl in
	  (decls@decls', (t, x, loc)::f)
    | [] -> ([], [])

and normalize_decl (b, v) =
  let (symbdecls, t) = normalize_base_typ b in
  let d = normalize_var_modifier t v in
    (symbdecls, d)

(* TODO: remove all calls to functions in synthack *)
and normalize_var_modifier b (derefs, v) =
  let b = apply_derefs derefs b in
    match v with
	Abstract -> (b, None, Newspeak.unknown_loc)
      | Variable (x, loc) -> (b, Some x, loc)
      | Function (x, args) ->
	  let ft = normalize_ftyp (args, b) in
	    normalize_var_modifier ft x
      | Array (v, n) -> 
	  let n = 
	    match n with
		None -> None
	      | Some n -> Some (process_exp n)
	  in
	  normalize_var_modifier (T.Array (b, n)) v

and normalize_ftyp (args, ret) =
  let args = List.map normalize_arg args in
  let args =
    match args with
	[] -> None
      | (T.Void, _)::[] -> Some []
      | args -> Some args
  in
    T.Fun (args, ret)

and normalize_arg a = 
  let (symbdecls, (t, x, _)) = normalize_decl a in
  let t =
    match t with
	T.Array (elt_t, _) -> T.Ptr elt_t
      | T.Fun _ -> T.Ptr t
      | _ -> t
  in
  let x = 
    match x with
	Some x -> x
      | None -> "silent argument"
  in
    if (symbdecls <> []) then begin
      Npkcontext.report_error "Bare2C.normalize_arg" 
	"symbol definition not allowed in argument"
    end;
    (t, x)

and apply_derefs n b = if n = 0 then b else apply_derefs (n-1) (T.Ptr b)

and process_decls (build_sdecl, build_vdecl) (b, m) =
  let (sdecls, b) = normalize_base_typ b in
  let build_vdecl ((v, attrs), init) res =
    let b = apply_attrs attrs b in
    let (t, x, loc) = normalize_var_modifier b v in
      match x with
	| None -> res
	| Some x -> build_vdecl res (t, x, loc, init)
  in
  let sdecls = List.map build_sdecl sdecls in
  let vdecls = List.fold_right build_vdecl m [] in
    sdecls@vdecls

(* TODO: clean this code and find a way to factor with previous function *)
and build_typedef loc d =
  let build_vdecl l (t, x, _, _) = 
    (* TODO: remove this => not necessary anymore?? *)
    define_type x t;
    l
  in
  let build_sdecl x = (T.LocalDecl x, loc) in
    process_decls (build_sdecl, build_vdecl) d

and build_stmtdecl loc (static, extern) d =
(* TODO: think about cleaning this location thing up!!! *)
(* for enum decls it seems the location is in double *)
  let build_vdecl l (t, x, loc, init) = 
    let init = process_init_option init in
(* TODO: factor the various VDecl creations!! *)
    let d = 
      { T.t = t; is_static = static; is_extern = extern; initialization = init }
    in
      (T.LocalDecl (x, T.VDecl d), loc)::l 
  in
  let build_sdecl x = (T.LocalDecl x, loc) in
    process_decls (build_sdecl, build_vdecl) d

and process_init_option x =
  match x with
      None -> None
    | Some x -> Some (process_init x)

and process_init x =
  match x with
      Data e -> T.Data (process_exp e)
    | Sequence sequence -> T.Sequence (process_init_sequence sequence)

and process_init_sequence x =
  List.map (fun (d, i) -> (process_designator d, process_init i)) x

and process_designator = function
    | T.InitAnon -> T.InitAnon
    | T.InitField f -> T.InitField f
    | T.InitIndex e -> T.InitIndex (process_exp e)

and process_blk x = 
  let result = ref [] in
  let process_stmt (x, loc) =
    Npkcontext.set_loc loc;
(* TODO: optimization: think about this concatenation, maybe not efficient *)
    result := (!result)@(process_stmtkind loc x)
  in
    List.iter process_stmt x;
    !result

and process_stmtkind loc x =
  match x with
      LocalDecl (modifiers, d) -> build_stmtdecl loc modifiers d
    | Exp e -> 
	let e = process_exp e in
	  (T.Exp e, loc)::[]
    | Return None -> (T.Return, loc)::[]
    | Return Some e -> 
	let e = process_exp e in
	  (T.Exp (T.Set (T.RetVar, None, e)), loc)::(T.Return, loc)::[]
    | Block body -> 
	let body = process_blk body in
	  (T.Block body, loc)::[]
    | If (condition, body1, body2) -> 
(* TODO: move normalize_bexp from Csyntax to bare2C *)
	let condition = Csyntax.normalize_bexp (process_exp condition) in
	let body1 = process_blk body1 in
	let body2 = process_blk body2 in
	  (T.If (condition, body1, body2), loc)::[]
    | For (init, condition, body, continue) -> 
	if (init = []) then  begin
	  Npkcontext.report_warning "NpkParser.iteration_statement" 
	    "init statement expected"
	end else if (continue = []) then begin
	  Npkcontext.report_warning "NpkParser.iteration_statement" 
	    "increment statement expected"
	end;
	if (condition = None) then begin
	  Npkcontext.report_warning "NpkParser.expression_statement" 
	    "halting condition should be explicit"
	end;
	let init = process_blk init in
	let condition = 
	  match condition with
	      None -> Csyntax.exp_of_int 1
	    | Some condition -> Csyntax.normalize_bexp (process_exp condition) 
	in
	let body = process_blk body in
	let continue = process_blk continue in
	  (T.For (init, condition, body, continue), loc)::[]
    | While (condition, body) -> 
	let condition = Csyntax.normalize_bexp (process_exp condition) in
	let body = process_blk body in
	  (T.For ([], condition, body, []), loc)::[]
    | DoWhile (body, condition) -> 
	let body = process_blk body in
	let condition = Csyntax.normalize_bexp (process_exp condition) in
	  (T.DoWhile (body, condition), loc)::[]
    | CSwitch (e, (choices, default_body)) -> 
	let e = process_exp e in
	let choices = List.map process_choice choices in
	let default_body = process_blk default_body in
	  (T.CSwitch (e, choices, default_body), loc)::[]
    | Break -> (T.Break, loc)::[]
    | Continue -> (T.Continue, loc)::[]
    | Typedef d -> build_typedef loc d
    | LabeledStmt (lbl, body) -> 
	let body = process_blk body in
	  (T.Label lbl, loc)::body
    | Goto lbl -> 
	Npkcontext.report_accept_warning "NpkParser.statement" "goto statement"
	  Npkcontext.ForwardGoto;
	(T.Goto lbl, loc)::[]
    | UserSpec a -> (T.UserSpec a, loc)::[]
    | Asm | Skip -> []

and process_choice (value, body, loc) = 
  (process_exp value, process_blk body, loc)

and process_exp e =
  match e with
      Cst c -> T.Cst c
    | Var x -> T.Var x
    | Field (e, f) -> T.Field (process_exp e, f)
    | Index (a, i) -> T.Index (process_exp a, process_exp i)
    | AddrOf e -> T.AddrOf (process_exp e)
    | Unop (op, e) -> T.Unop (op, process_exp e)
    | IfExp (c, Some e1, e2) -> 
(* TODO: factor these function calls = process_bexp *)
	let c = Csyntax.normalize_bexp (process_exp c) in
	let e1 = process_exp e1 in
	let e2 = process_exp e2 in
	  T.IfExp (c, e1, e2)
    | IfExp (c, None, e2) -> 
(* TODO: move normalize_bexp into bare2C *)
	let e = Csyntax.normalize_bexp (process_exp c) in
	let loc = Npkcontext.get_loc () in
	let t = T.Typeof e in
	let d = 
	  {
	    T.t = t; is_static = false; is_extern = false;
	    initialization = Some (T.Data e)
	  }
	in
	let id = gen_tmp_id () in
	let decl = (T.LocalDecl (id, T.VDecl d), loc) in
	let e' = T.Var id in
	let e2 = process_exp e2 in
	  T.BlkExp( [ decl; ( T.Exp (T.IfExp(e', e', e2)), loc ) ] )
    | Binop (op, e1, e2) -> T.Binop (op, process_exp e1, process_exp e2)
    | And (e1, e2) ->
	let c = Csyntax.normalize_bexp (process_exp e1) in
	let e1 = Csyntax.normalize_bexp (process_exp e2) in
	  T.IfExp (c, e1, Csyntax.exp_of_int 0) 
    | Or (e1, e2) ->
	let c = Csyntax.normalize_bexp (process_exp e1) in
	let e2 = Csyntax.normalize_bexp (process_exp e2) in
	  T.IfExp (c, Csyntax.exp_of_int 1, e2) 
    | Call (f, args) -> T.Call (process_exp f, List.map process_exp args)
    | Sizeof t -> 
	let t = build_type_decl t in
	  T.Sizeof t
    | SizeofE e -> T.SizeofE (process_exp e)
    | Offsetof (t, o) -> T.Offsetof (build_type_decl t, process_offset_exp o)
    | Str x -> T.Str x
    | FunName -> T.FunName
    | Cast (e, t) -> 
	let e = process_exp e in
	let t = build_type_decl t in
	  T.Cast (e, t)
    | Set (lv, op, e) -> T.Set (process_exp lv, op, process_exp e)
    | OpExp (op, e, is_before) -> T.OpExp (op, process_exp e, is_before)
    | BlkExp body -> T.BlkExp (process_blk body)
    | LocalComposite (t, init, loc) -> 
(* TODO: use Npkcontext.get_loc here, instead of adding a location to the
   instruction *)
	let (blk, t) = build_type_blk loc t in
	let d =
	  {
	    T.t = t; is_static = false; is_extern = false; 
	    initialization = Some (T.Sequence (process_init_sequence init))
	  }
	in
	let id = gen_tmp_id () in
	let decl = (T.LocalDecl (id, T.VDecl d), loc) in
	let e = (T.Exp (T.Var id), loc) in
	  Npkcontext.report_accept_warning "NpkParser.cast_expression" 
	    "local composite creation" Npkcontext.DirtySyntax;
	  T.BlkExp (blk@decl::e::[])

and process_aux_offset_exp o =
  match o with
      OffComp s -> T.OffComp s
    | OffField (o, s) -> T.OffField (process_aux_offset_exp o, s)

and process_offset_exp o =
  match o with
      OIdent s -> T.OIdent s
    | OField (o, s) -> T.OField (process_aux_offset_exp o, s)
    | OArray (o, s, e) -> T.OArray (process_aux_offset_exp o, s, process_exp e)

and build_type_decl d =
  let (sdecls, (t, _, _)) = normalize_decl d in
    if (sdecls <> []) then begin 
      Npkcontext.report_error "NpkParser.build_type_decl" 
       "unexpected enum or composite declaration"
    end;
    t

and build_type_blk loc d =
  let (sdecls, (t, _, _)) = normalize_decl d in
  let sdecls = List.map (fun x -> (T.LocalDecl x, loc)) sdecls in
    (sdecls, t)

let build_fundef static ((b, m), body) =
  let (_, (t, x, loc)) = normalize_decl (b, m) in
  let x =
    match x with
      | Some x -> x
      | None -> 
	  (* TODO: code cleanup remove these things !!! *)
	  Npkcontext.report_error "Firstpass.translate_global" 
	    "unknown function name"
  in
  let t = Csyntax.ftyp_of_typ t in
  let body = process_blk body in
    (T.FunctionDef (x, t, static, body), loc)::[]

(* TODO: move code out of synthack and parser into bare2C => remove synthack?? *)

let process_glbdecls (build_sdecl, build_vdecl) (b, m) =
  let (sdecls, b) = normalize_base_typ b in
  let build_vdecl ((v, attrs), init) res =
    let b = apply_attrs attrs b in
    let (t, x, loc) = normalize_var_modifier b v in
      match x with
	| None -> res
	| Some x -> build_vdecl res (t, x, loc, init)
  in
  let sdecls = List.map build_sdecl sdecls in
  let vdecls = List.fold_right build_vdecl m [] in
    sdecls@vdecls

let build_glbdecl loc (static, extern) d =
  let build_vdecl l (t, x, loc, init) = 
    let init = process_init_option init in
    let d = 
      { T.t = t; is_static = static; is_extern = extern; initialization = init }
    in
    (T.GlbDecl (x, T.VDecl d), loc)::l
  in
  let build_sdecl x = (T.GlbDecl x, loc) in
    process_glbdecls (build_sdecl, build_vdecl) d

let build_glbtypedef loc d =
  let build_vdecl l (t, x, _, _) = 
    define_type x t;
    l
  in
  let build_sdecl x = (T.GlbDecl x, loc) in
    process_glbdecls (build_sdecl, build_vdecl) d

let process_global (x, loc) =
  Npkcontext.set_loc loc;
  match x with
      FunctionDef (static, x) -> build_fundef static x
    | GlbDecl (modifiers, d) -> build_glbdecl loc modifiers d
    | GlbTypedef x -> build_glbtypedef loc x
    | GlbUserSpec x -> (T.GlbUserSpec x, loc)::[]
    | GlbSkip -> 
	Npkcontext.report_accept_warning "NpkParser.translation_unit" 
	  "unnecessary semicolon" Npkcontext.DirtySyntax;
	[]


let process x = 
  let result = ref [] in
  let process_global x =
(* TODO: optimization: think about this concatenation, maybe not efficient *)
    result := (!result)@(process_global x)
  in
    List.iter process_global x;
    !result
