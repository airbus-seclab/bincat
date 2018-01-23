(*
  C2Newspeak: compiles C code into Newspeak. Newspeak is a minimal language 
  well-suited for static analysis.
  Copyright (C) 2007-2011  Charles Hymans, Olivier Levillain, Sarah Zennou
  
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
  EADS Innovation Works - SE/IS
  12, rue Pasteur - BP 76 - 92152 Suresnes Cedex - France
  email: sarah(dot)zennou(at)eads(dot)net
*)

(* TODO: should not fill initializations with 0 by default!!!! 
   should push array length evaluation till newspeak
*)

(* TODO: should rename firstpass to semantic ??? see compiler Appel book *)
open TypedC
module C = Cir
module K = Npkil
module N = Newspeak
module Nat = Newspeak.Nat

(* TODO: should compile directly to Npkil, without going through Cir
   TODO: should remove Cir
*)

let ret_lbl = 0
let cnt_lbl = 1
let brk_lbl = 2
let default_lbl = 3

(* functions *)
let find_field f r =
  try List.assoc f r 
  with Not_found -> 
    Npkcontext.report_error "TypedC2Cir.translate_lv" 
      ("unknown field '"^f^"' in union or structure")


(* [next_aligned o x] returns the smallest integer greater or equal than o,
   which is equal to 0 modulo x *)
let next_aligned o x =
  let m = o mod x in
    if m = 0 then o else o + (x - m)

(* For detecting integers index, accesses and Addrof (accesss)*)
let warn_report () =
  Npkcontext.report_accept_warning "Firstparse.translate_array_access" 
    "expression of type signed integer used as an array index" Npkcontext.SignedIndex 

let check_array_type_length typ =
  let rec length typ =
    match typ with
	C.Array (typ', n) -> begin
	  match n with
	      None -> raise Exit
	    | Some n -> Nat.mul (Nat.of_int n) (length typ') 
	end
      | C.Void -> raise Exit
      | C.Scalar s -> 
	  begin
	    match s with
		N.Int (_, sz) -> Nat.of_int sz
	      | N.Float sz -> Nat.of_int sz
	      | N.Ptr -> Nat.of_int (!Conf.size_of_ptr)
	      | N.FunPtr -> Nat.of_int (!Conf.size_of_ptr)
	  end
      | C.Struct (_, sz) -> Nat.of_int sz
      | C.Union (_, sz) -> Nat.of_int sz
      | C.Fun -> raise Exit
  in
    try 
      let sz = length typ in 
	if Nat.compare sz (Nat.of_int !Conf.max_array_length) > 0 then
	  Npkcontext.report_error "Firstpass.translate_typ" 
	    "invalid size for array"
    with Exit -> ()

let rec check_index_type i t =
  match t with 
      Int (N.Signed, _) -> check_exp i
    | _ -> ()
and check_exp i =
  match i with
      C.Lval _ -> warn_report ()
    | C.Const (C.CInt c)  when Nat.compare c Nat.zero < 0 -> warn_report ()
    | C.Unop (K.Coerce _, C.Binop (N.MinusI, C.Const  (C.CInt c), e)) 
	when Nat.compare c Nat.zero = 0 ->  
	check_exp e
    | C.Binop  (_, e1, e2) -> check_exp e1; check_exp e2
    | C.BlkExp (_, e, _) -> check_exp e    
    | _ -> ()

let build_initialization_set v scalars =
  let loc = Npkcontext.get_loc () in
  let build_set (o, t, e) =
    let lv = C.Shift (v, C.exp_of_int o) in
      (C.Set (lv, t, e), loc)
  in
    List.map build_set scalars

(*
   Sets scope of variables so that no goto escapes a variable declaration
   block
*)
let translate prog =
  let glbdecls = Hashtbl.create 100 in
  let fundefs = Hashtbl.create 100 in
  let init = ref [] in
    
  (* TODO: used_globals and one pass could be removed, if cir had a structure
     type with only the name and a hashtbl of structure names to type!!!, 
     should be done!*)
  let used_globals = Hashtbl.create 100 in
    (* Used to generate static variables names *)
  let current_fun = ref "" in

  let tmp_cnt = ref 0 in

  let lbl_tbl = Hashtbl.create 10 in
  let lbl_cnt = ref default_lbl in

  let new_lbl () =
    incr lbl_cnt;
    !lbl_cnt
  in

  let add_formals (args_t, _) =
    let args_id = List.map snd args_t in
    let ret_name = Temps.to_string 0 Temps.Return in
      (ret_name, args_id)
  in

  let update_global x name (t, storage) =
    let loc = Npkcontext.get_loc () in
    let info =
      try 
	let (prev_t, prev_loc, prev_storage) = Hashtbl.find used_globals name in
	let t = TypedC.min_typ t prev_t in
	  match (prev_storage, storage) with
	      (K.Extern, _)  
	    | (K.Declared false, K.Declared _) -> (t, loc, storage)
	    | (K.Declared _, K.Extern) 
	    | (K.Declared _, K.Declared false) -> 
		(t, prev_loc, prev_storage)
	    | (K.Declared true, K.Declared true) -> 
		Npkcontext.report_error "Firstpass.update_global"
		  ("global variable "^x^" initialized twice")
      with Not_found -> (t, loc, storage)
    in
      (* TODO: remove used_globals in firstpass, done in cir2npkil?? *)
      Hashtbl.replace used_globals name info
  in

  let translate_lbl lbl =
    try Hashtbl.find lbl_tbl lbl
    with Not_found -> 
      let lbl' = new_lbl () in
	Hashtbl.add lbl_tbl lbl lbl';
	lbl'
  in

  let rec cast (e, t1) t2 = 
    match t2 with
	Comp (TypedC.Known (f, false)) 
	  when not (TypedC.equals_typ t1 t2) ->
	    if not (List.exists (fun (_, f_t) -> f_t = t1) f) 
	    then Npkcontext.report_error "Firstpass.cast" "incompatible type";
	    (e, t1)
      | _ -> 	     
	  let t1' = translate_typ t1 in
	  let t2' = translate_typ t2 in
	    (C.cast (e, t1') t2', t2)

  (* TODO: this should be simplified because a bit is done already in 
     csyntax2TypedC!!! *)
  and translate_init t x =
    let res : (int * C.typ * C.exp) list ref =
      ref []
    in
    let rec translate o t x =
      match (x, t) with
	| (Data (e, t1), _) -> 
	    (* TODO: should I be using translate_set here too??? *)
	    let e = translate_exp false (e, t1) in
	    let (e, _) = cast (e, t1) t in
	      res := (o, translate_typ t, e)::!res;
	      t
		
	| (Sequence seq, Array (t, len)) -> 
	    let n = 
	      match translate_array_len len with
		  Some n -> n
		| None -> List.length seq
	    in
	      translate_sequence o t n seq;
	      Array (t, Some (exp_of_int n))
		
	| (Sequence seq, Comp (TypedC.Known (f, true))) ->
	    let (f, _, _) = translate_struct f in
	      translate_field_sequence o f seq;
	      t

	| (Sequence ((Csyntax.InitAnon, v)::[]), Comp (TypedC.Known (r, false))) ->
	    let (r, _, _) = translate_union r in
	    let (f_o, f_t) = 
	      match r with
		  (_, b)::_ -> b
		| _ -> 
		    Npkcontext.report_error "Firstpass.translate_init"
		      "unexpected empty union"
	    in
	    let _ = translate (o + f_o) f_t v in
	      t

	| (Sequence ((Csyntax.InitField f, v)::[]), Comp (TypedC.Known (r, false) )) ->
	    let (r, _, _) = translate_union r in
	    let (f_o, f_t) = find_field f r in
	    let _ = translate (o + f_o) f_t v in
	      t
	    	
	| (Sequence _, _) -> 
	    Npkcontext.report_error "Firstpass.translate_init"
	      "this type of initialization not implemented yet"
	      
    and translate_field_sequence o fields seq =
      let rec remove f l =
	match l with 
	    [] -> []
	  | (f', x)::l -> 
	      if String.compare f f' = 0 then l else (f', x)::(remove f l)
      in
      let rec next f fields =
	match fields with
	    [] -> raise Not_found 
	  | (f', _)::fields -> 
	      if String.compare f f' = 0 then List.hd fields else next f fields
      in
      let rec fold not_init seq current =
	match seq with
	    [] -> List.iter (fun (_, (f_o, t)) -> 
			       let f_o = o + f_o in
				 ignore (fill_with_zeros f_o t)) not_init
	      
	  | (fname, hd)::seq when not_init <> [] -> begin
	      try 
		let name, (f_o, t) = 
		  match fname with 
		      Csyntax.InitField f -> List.find (fun (f', _) -> String.compare f f' = 0) fields
		    | Csyntax.InitAnon -> current
		    | Csyntax.InitIndex _e -> assert false
		in
		let not_init' = remove name not_init in
		let f_o' = o + f_o in
		let _ = translate f_o' t hd in
		let current' = 
		  try next name fields
		  with
		      Failure _ -> current 
		    | Not_found ->  
			Npkcontext.report_accept_warning 
			  "Firstpass.translate_init.translate_field_sequence" 
			  "extra initializer for structure" Npkcontext.DirtySyntax;
			current
		in
		  fold not_init' seq current'
	      with Not_found ->
		Npkcontext.report_error 
		  "Firstpass.translate_init.translate_field_sequence" 
		  "Unknown field "
	    end
	      
	  | _ -> 
	      Npkcontext.report_accept_warning 
		"Firstpass.translate_init.translate_field_sequence" 
		"extra initializer for structure" Npkcontext.DirtySyntax
		
      in fold fields seq (List.hd fields)
	   
    and translate_sequence o t n seq =
      match seq with
	  (Csyntax.InitAnon, hd)::tl when n > 0 ->
	    let _ = translate o t hd in
	    let o = o + size_of t in
	      translate_sequence o t (n-1) tl
	| (Csyntax.InitField _, _)::_ ->
	    Npkcontext.report_error 
	      "Firstpass.translate_init.translate_sequence" 
	      "anonymous initializer expected for array"

	| (Csyntax.InitIndex offset_expr, v)::tl ->
            let offset_expr' = translate_exp false offset_expr in
            let o = size_of t * (Nat.to_int (C.eval_exp offset_expr')) in
            let _ = translate o t v in
            translate_sequence o t (n-1) tl
	      
	| (Csyntax.InitAnon, _)::_ -> 
	    Npkcontext.report_accept_warning 
	      "Firstpass.translate_init.translate_sequence" 
	      "extra initializer for array" Npkcontext.DirtySyntax
	
	| [] when n > 0 -> 
	    let _ = fill_with_zeros o t in
	    let o = o + size_of t in
	    let n = n - 1 in
	      if (n = 0) then begin
		Npkcontext.report_warning 
		  "Firstpass.translate_init.translate_sequence" 
		  "not enough initializers for array"
	      end;
	      translate_sequence o t n []
	| [] -> ()
	    
    and fill_with_zeros o t =
      match t with
	  Int _ -> res := (o, translate_typ t, C.exp_of_int 0)::!res
	| Ptr _ -> 
	    (* TODO: inefficient: t is translated twice *)
	    let e = translate_exp false (exp_of_int 0, int_typ ()) in
	    let (e, t) = cast (e, int_typ ()) t in
	      res := (o, translate_typ t, e)::!res
	| Float _ -> 
	    res := (o, translate_typ t, C.exp_of_float 0.)::!res
	| Array (t, n) ->
	    let n = 
	      match translate_array_len n with
		  Some n -> n
		| None -> 
		    Npkcontext.report_error 
		      "Firstpass.translate_init.fill_with_zeros"
		      "unreachable statement"
	    in
	    let sz = size_of t in
	    let o = ref o in
	      for _i = 0 to n - 1 do
		fill_with_zeros !o t;
		o := !o + sz
	      done
		
	| Comp (TypedC.Known c) -> 
	    let (f, _, _) = translate_comp c in
	    let fill_field (_, (f_o, t)) = fill_with_zeros (o + f_o) t in
	      List.iter fill_field f

	| _ -> 
	    Npkcontext.report_error "Firstpass.translate_init.fill_with_zeros"
	      "this type of zero initialization not implemented yet"
    in
    let t = translate 0 t x in
      (List.rev !res, t)

  and translate_glb_init name t x =
    match x with
	None -> (t, false)
      | Some i -> 
	  let (i, t) = translate_init t i in
	  let i = build_initialization_set (C.Global name) i in
	    init := i@(!init);
	    (t, true)

  and translate_lv x =
    match x with
	Local x -> C.Local x
      | Global x -> C.Global x
      | Field ((lv, t), f) -> 
	  let lv = translate_lv lv in
	  let (r, _, _) = translate_comp (TypedC.comp_of_typ t) in
	  let (o, _) = find_field f r in
	  let o = C.exp_of_int o in
	    C.Shift (lv, o)

      | Index (e, (t, len), (idx, idx_t)) -> 
	  let lv = translate_lv e in
	  let n = translate_array_len len in
	  let i = translate_exp false (idx, idx_t) in
	    translate_array_access (lv, t, n) (i, idx_t)

      | Deref (e, t) -> deref (translate_exp false (e, t), t)

      | OpExp (op, (lv, t), is_after) -> 
	  let loc = Npkcontext.get_loc () in
	  let e = Cst (C.CInt (Nat.of_int 1), TypedC.int_typ ())  in
	  let (incr, _) = 
	    translate_set ((lv, t), Some op, (e, TypedC.int_typ ())) 
	  in
	  let (lv, _, _) = incr in
	    C.BlkLv ((C.Set incr, loc)::[], lv, is_after)

      | Str str -> C.Str str

      | FunName -> C.Str !current_fun

      | Cast ((lv, _), _) -> 
	  Npkcontext.report_accept_warning "Firstpass.translate_stmt" 
	    "cast of left value" Npkcontext.DirtySyntax;
	  translate_lv lv

      | BlkExp (blk, is_after) -> 
	  (* TODO: simplify translate_blk_exp so that it is unnecessary to throw away
	     a value with _ !!! *)
	  let (body, (e, _)) = translate_blk_exp blk in
	  let lv =
	    match e with
		C.Lval (lv, _) -> lv
	      | _ -> 
		  Npkcontext.report_error "Firstpass.translate_lv" 
		    "left value expected"
	  in
	    C.BlkLv (body, lv, is_after)

      | _ -> 
	  Npkcontext.report_error "Firstpass.translate_lv" "left value expected"

  and translate_array_access (lv, t, n) i =
    try
      let (i, typ) = i in
	check_index_type i typ;
	let len = 
	  try C.length_of_array n lv 
	  with Invalid_argument _ when !Npkcontext.accept_flex_array -> 
	    raise Exit
	in
	let sz = C.exp_of_int (size_of t) in
	let o = C.Unop (K.Belongs_tmp (Nat.zero, len), i) in
	let o = C.Binop (N.MultI, o, sz) in
	  C.Shift (lv, o)
    with Exit -> 
      let e = C.remove_fst_deref lv in
      let e = translate_binop false (Plus, Ptr t) (e, Ptr t) i in
	deref e

  and translate_exp is_sz (e, t) =
    let rec translate e =
      match e with
	  Cst (c, _) -> C.Const c
	    
	| Local _ | Global _  
	| Field _ | Index _ | Deref _ | OpExp _ | Str _ | FunName -> 
	    let lv = translate_lv e in
	      C.Lval (lv, translate_typ t)
		
	| AddrOf (Index (lv, (t, len), (Cst (C.CInt i, _), _)), _)
	    when Nat.compare i Nat.zero = 0 ->
	    let lv = translate_lv lv in
	      addr_of (lv, Array (t, len))

	| AddrOf (Index (lv, (t, len), e), t') ->
	    let base = 
	      AddrOf (Index (lv, (t, len), (exp_of_int 0, int_typ ())), t') 
	    in
	      (*Case AddrOf Access, the access is check to detected integers*)  
	    let access  = translate_exp is_sz e in
	      check_index_type access (snd e);
	      translate (Binop ((Plus, Ptr t), (base, Ptr t), e))

	| AddrOf (Field ((_e, t), _f) as lv, _)
               when !Conf.arithmetic_in_structs_allowed ->
            addr_of (translate_lv lv, t)

	| AddrOf (lv, t) -> addr_of (translate_lv lv, t)

	| Unop x -> C.Unop (translate_unop x)
	    
	| Binop ((op, t), (e1, t1), (e2, t2)) -> 
	    let e1 = translate_exp is_sz (e1, t1) in
	    let e2 = translate_exp is_sz (e2, t2) in
	      (* TODO: remove need for typ in translate_binop !!! *)
	    let (e, _) = translate_binop is_sz (op, t) (e1, t1) (e2, t2) in
	      e
		
	| IfExp (c, (e1, _), (e2, _), t) -> begin
	    try
	      let v = C.eval_exp (translate c) in
	      let e = if Nat.compare v Nat.zero <> 0 then e1 else e2 in
		translate e
	    with Invalid_argument _ -> 
	      let loc = Npkcontext.get_loc () in
	      let (x, decl, v) = gen_tmp t in
	      let blk1 = 
		(Exp (Set ((Local x, t), None, (e1, t)), t), loc)::[] 
	      in
	      let blk2 = 
		(Exp (Set ((Local x, t), None, (e2, t)), t), loc)::[] 
	      in
	      let set = (If (c, blk1, blk2), loc) in
	      let set = translate_stmt set in
		C.BlkExp (decl::set, C.Lval (v, translate_typ t), false)
	  end

	| Sizeof t -> 
	    let sz = (size_of t) / 8 in
	      C.exp_of_int sz
		
	| Cast ((e, t1), t2) -> 
	    let e = translate_exp is_sz (e, t1) in
	    let (e, _) = cast (e, t1) t2 in
	      e

	(* TODO: introduce type funexp in corec??*)
	| Call (e, (Some args_t, ret_t), args) -> 
	    let e = translate_funexp e in
	      (* here translate_args refines args_t and this is useful 
		 in some cases should/could?? be implemented during 
		 csyntax2CoreC too!!! 
	      *)
	      (* TODO: think about it *)
	    let (args, args_t) = translate_args args args_t in
            let args = List.map (fun x -> C.In x) args in
	    let ft = translate_ftyp (args_t, ret_t) in
	      C.Call (ft, e, args)

	| Call _ -> 
	    Npkcontext.report_error "Firstpass.translate_exp" 
	      "unreachable code"
	      
	| Set set ->
	    Npkcontext.report_accept_warning "Firstpass.translate_exp" 
	      "assignment within expression" Npkcontext.DirtySyntax;
	    let loc = Npkcontext.get_loc () in
	    let (set, _) = translate_set set in
	    let (lv', t', _) = set in
	    let e = C.Lval (lv', t') in
	      C.BlkExp ((C.Set set, loc)::[], e, false)
	      	
	| BlkExp (blk, is_after) -> 
	    let (body, (e, _)) = translate_blk_exp blk in
	      C.BlkExp (body, e, is_after)

	| Offsetof (t, f) -> 
	    let (r, _, _) = translate_comp (TypedC.comp_of_typ t) in
	    let o 	  = find_offset_field f r in
	      C.exp_of_int (o / !Conf.size_of_byte)
		
    and find_offset_field f r =
      let translate c =
	match c with
	  | Unknown s -> 
	      Npkcontext.report_error "TypedC2Cir.translate" 
		("incomplete struct or union type " ^ s)
	  | Known (fields, k) -> 
	      let (r, _, _) = 
		if k then translate_struct fields
		else translate_union fields
	      in r
      in
      let rec find e =
	match e with
	    OffComp (s, t) -> 0, translate t, s
	  | OffField (e', f, t) ->
	      let o, r , s	= find e' in
	      let o', _ = find_field f r in
		o+o', translate t, s
      in
      let check f tab =
	let translate_cmp c =
	  match c with
	      Unknown s ->
		Npkcontext.report_error "TypedC2Cir.check" 
		  ("incomplete struct/union "^s)
	    | Known (c, _) -> 
		try 
		  match find_field tab c with
		      Array (t, Some  _) as a -> 
			let t' = translate_typ a in
			  C.size_of_typ t', translate_typ t
			    (*TODO optimize: t is translated twice *)
		    | Array _ ->
			Npkcontext.report_error "TypedC2Cir.check" 
			  "unknown size of struct/union field"
		    | _ 	   ->  Npkcontext.report_error "TypedC2Cir.check" 
			"expected struct/union field of type array"
		with Not_found -> Npkcontext.report_error "TypedC2Cir.check" 
		  ("unknown field " ^tab) 
	in
	match f with
	    OffComp (_, c) 
	  | OffField (_, _, c) -> translate_cmp c	     
      in
	match f with
	    OIdent f 	  -> fst (find_field f r)
	  | OField (e, f) ->
	      let o', r', s = find e in
	      let o, _ 	 = find_field f r' in
	      let o2, _ = find_field s r in 
		o+o'+o2
	  | OArray (f, tab, e) ->
	      let len, t     = check f tab in
	      let o', r', s  = find f in
	      let o' 	     = let o, _ = find_field tab r' in o+o' in
	      let o 	     = Nat.to_int (Cir.eval_exp (translate_exp false e)) in 
	      let sz = C.size_of_typ t in
	      let o = o*sz in
	      let o = if o = 0 then 0 else o-1 in
		(*TODO optimize: e is translated twice *)
		if o <= len then 
		  let o2, _ = find_field s r in	 
		    o' + o + o2 
		else Npkcontext.report_error "TypedC2Cir.find_offset_field"
		  "array access in offsetof is out of bounds"
    in
      translate e

  and translate_funexp e =
    match e with
	Fname x -> C.Fname x
      | FunDeref e -> C.FunDeref (translate_exp false e)


  and deref (e, t) =
    match t with
	Ptr t -> C.Deref (e, translate_typ t)
      | _ -> 
	  Npkcontext.report_error "Firstpass.deref_typ" "pointer type expected"
	    
  (* TODO: code cleanup: get rid of call to length_of_array in cir2npkil 
     with AddrOf and put it in here *)
  and addr_of (e, t) = 
    match (e, t) with
	(C.Global f, Fun (Some args_t, ret_t)) -> 
	  C.AddrOfFun (f, translate_ftyp (args_t, ret_t))
      | (_, Fun (None, _)) -> 
	  Npkcontext.report_error "Firstpass.addr_of" 
	    "incomplete type for function"
      | _ -> C.AddrOf (e, translate_typ t)

  and translate_set ((lv, lv_t), op, (e, e_t)) =
    let lv = translate_lv lv in
    let e = translate_exp false (e, e_t) in
    let t' = translate_typ lv_t in
    let (lv, e) =
      match op with
	  None -> (lv, (e, e_t))
	| Some op -> 
	    let (pref, lv', post) = C.normalize_lv lv in
	    let e' = (C.Lval (lv', t'), lv_t) in
	    let e = translate_binop false op e' (e, e_t) in
	    let lv = C.BlkLv (post, C.BlkLv (pref, lv', false), true) in
	      if (post <> []) then begin
		Npkcontext.report_warning "Firstpass.translate_set" 
		  "expression without post effects expected"
	      end;
	      (lv, e)
    in
    let (e, t) = cast e lv_t in
    let set = (lv, t', e) in
      (set, t)


  and init_va_args loc lv x =
    let rec init_va_args lv x =
      match x with
	  (e, t)::tl ->
	    let sz = size_of t in
	    let t = translate_typ t in
	    let set = (C.Set (lv, t, e), loc) in
	    let lv = C.Shift (lv, C.exp_of_int sz) in
	    let init = init_va_args lv tl in
	      set::init
	| [] -> []
    in
      init_va_args lv x

  and translate_va_args x =
    match x with
	(e, t)::tl -> 
	  let (args, sz) = translate_va_args tl in
	  let e = translate_exp false (e, t) in
	    ((e, t)::args, size_of t + sz)
      | [] -> ([], 0)

  and translate_args args args_t =
    let rec translate_args args args_t =
      match (args, args_t) with
	  ([], (Va_arg, id)::[]) ->
	    let e = translate_exp false (exp_of_int 0, int_typ ()) in
	    let (e, _) = cast (e, int_typ ()) (Ptr (char_typ ())) in
	      (e::[], (Va_arg, id)::[])
	| (_, (Va_arg, id)::[]) -> 
	    let (args, sz)   = translate_va_args args in
	    let loc 	     = Npkcontext.get_loc () in
	    let sz 	     = if sz mod 8 = 0 then sz/8 else (sz/8)+1 in
	    let t 	     = Array (char_typ (), Some (exp_of_int sz)) in
	    let (_, decl, v) = gen_tmp t in
	    let e 	     = addr_of (v, t) in
	    let init 	     = init_va_args loc v args in
	      ((C.BlkExp (decl::init, e, false))::[], (Va_arg, id)::[])

	| ((e, t1)::args, (t2, id)::args_t) ->
	    let e = translate_exp false (e, t1) in
	    let (e, t2) = cast (e, t1) t2 in
	    let (args, args_t) = translate_args args args_t in
	      (e::args, (t2, id)::args_t)
	| ([], []) -> ([], [])
	| _ -> 
	    Npkcontext.report_error "Firstpass.translate_exp" 
	      "different types at function call"
    in
      translate_args args args_t

  and gen_tmp t =
    let loc = Npkcontext.get_loc () in
    let x = Temps.to_string !tmp_cnt (Temps.Misc "firstpass") in
    let t = translate_typ t in
    let decl = (C.Decl (t, x), loc) in
      incr tmp_cnt;
      (x, decl, C.Local x)

  and translate_field (x, (o, t)) = (x, (o, translate_typ t))

  and translate_comp (f, is_struct) = 
    if is_struct then translate_struct f else translate_union f

  and translate_struct f =
    let o = ref 0 in
    let last_align = ref 1 in
    let translate (x, t) =
      let cur_align = align_of t in
      let o' = next_aligned !o cur_align in
      let (o', t, sz) =
	match t with
	    Bitfield ((s, n), sz) ->
	      let sz = translate_exp false (sz, int_typ ()) in
	      let sz = Nat.to_int (C.eval_exp sz) in
		if sz > n then begin
		  Npkcontext.report_error "Firstpass.process_struct_fields"
		    "width of bitfield exceeds its type"
		end;
		let o' = if !o+sz <= o' then !o else o' in
		  (o', Int (s, sz), sz)
	  | Array (_, None) -> 
	      Npkcontext.report_accept_warning 
		"Firstpass.process_struct_fields" "flexible array member"
		Npkcontext.FlexArray;
	      (!o, t, 0)
	  | _ -> (o', t, size_of t)
      in
	if o' > max_int-sz then begin
	  Npkcontext.report_error "Firstpass.process_struct_fields" 
	    "invalid size for structure"
	end;
	o := o'+sz;
	last_align := max !last_align cur_align;
	(x, (o', t))
    in
    let f = List.map translate f in
    let sz = next_aligned !o !last_align in
      (f, sz, !last_align)

  and translate_union f =
    let n = ref 0 in
    let align = ref 0 in
    let translate (x, t) =
      let sz = size_of t in
      let align' = align_of t in
	align := max !align align';
	if !n < sz then n := sz;
	(x, (0, t))
    in
    let f = List.map translate f in
      (f, !n, !align)

  and translate_scalar_typ t =
    match t with
      | Int k 		      -> N.Int k
      | Float n 	      -> N.Float n	
      | Ptr (Fun _) 	      -> N.FunPtr
      | Ptr _ 		      -> N.Ptr
      | Va_arg 		      -> N.Ptr
      | Bitfield ((s, n), sz) -> 
	  let sz = translate_exp false (sz, int_typ ()) in
	  let sz = Nat.to_int (C.eval_exp sz) in
	    if sz > n then begin
	      Npkcontext.report_error "Firstpass.process_struct_fields"
		"width of bitfield exceeds its type"
	    end;
	    N.Int (s, sz)
      | _ 		      -> 
	  Npkcontext.report_error "Firstpass.translate_scalar_typ" 
	    "scalar type expected"

  and translate_typ t =
    match t with
	Void -> C.Void
      | Int _ | Float _ | Ptr (Fun _) | Ptr _ | Va_arg | Bitfield _ -> 
	  C.Scalar (translate_scalar_typ t)
      | Fun _ -> C.Fun
      | Array (t, len) ->
	  let t = translate_typ t in
	  let len = translate_array_len len in
	    C.Array (t, len)
      | Comp c -> 
	  let (f, is_struct) = 
	    match c with
		TypedC.Known x -> x
	      | TypedC.Unknown s -> 
		  Npkcontext.report_error "Firstpass.translate_typ"
		    ("incomplete type for struct or union "^s)
	  in
	  let (f, sz, _) = translate_comp (f, is_struct) in
	  let f = List.map translate_field f in
	    if is_struct then C.Struct (f, sz) else C.Union (f, sz)

  and translate_array_len x =
    match x with
	None -> None
      | Some e -> 
	  let e = translate_exp true (e, int_typ ()) in
	  let i = 
	    try Nat.to_int (C.eval_exp e) 
	    with Invalid_argument _ -> 
	      (* TODO: should print the expression e?? *)
	      Npkcontext.report_error "Firstpass.translate_typ" 
		"invalid size for array"
	  in
	    if (i < 0) || (i > !Conf.max_array_length) then begin
	      (* TODO: should print the expression e?? *)
	      Npkcontext.report_error "Firstpass.translate_typ" 
		"invalid size for array"
	    end;
	    if (i = 0) && (not !Npkcontext.accept_gnuc) then begin
	      Npkcontext.report_error "Firstpass.translate_typ" 
		"array should have at least 1 element"
	    end;
	    Some i

  and translate_ftyp (args, ret) =
    let translate_arg (t, _) = translate_typ t in
    let args = List.map translate_arg args in
    let ret = translate_typ ret in
      (args, ret)

  and translate_blk x =
    let (body, _) = translate_blk_aux false x in
      body

  and translate_blk_exp x =
    let (body, e) = translate_blk_aux true x in
      match e with
	  Some e -> (body, e)
	| None -> 
	    Npkcontext.report_error "Firstpass.translate_blk_exp" 
	      "expression expected"

  and translate_local_decl loc x d =
    if d.is_static || d.is_extern then begin
      declare_global d.is_extern x d.name d.t d.initialization;
      []
    end else begin
      (* TODO: see if more can be factored with translate_global_decl *) 
      let (init, t) = 
	match d.initialization with
	    None -> ([], d.t)
	  | Some init -> translate_init d.t init
      in
      let init = build_initialization_set (C.Local x) init in
      let t' = translate_typ t in
	check_array_type_length t';
	let decl = (C.Decl (t', x), loc) in
	  decl::init
    end

  (* type and translate blk *)
  and translate_blk_aux ends_with_exp x = 
    let rec translate x =
      match x with
	  (Exp (e, t), _)::[] when ends_with_exp -> 
	    let e = translate_exp false (e, t) in
	      (([], []), Some (e, t))
		
	| (LocalDecl (x, d), loc)::body -> begin
	    Npkcontext.set_loc loc;
	    let decl = translate_local_decl loc x d in
	    let (body, e) = translate_blk_aux ends_with_exp body in
	      ((decl@body, []), e)
	  end
	    (* TODO: do the case where suffix is <> [] *)
	    (* TODO: remove body, suffix from For, use goto and labels
	       remove break. *)
	| ((Label lbl, loc) as stmt)::tl -> 
	    let lbl = translate_lbl lbl in
	    let tl = 
	      match tl with
		  (For ([], e, body, []), loc)::tl ->
		    (For ([], e, body@(stmt::[]), []), loc)::tl
		| _ -> tl
	    in
	    let ((x, tl), e) = translate tl in
	      (([], (lbl, loc, x)::tl), e)

	| hd::tl -> 
	    let hd = translate_stmt hd in
	    let ((x, tl), e) = translate tl in
	      ((hd@x, tl), e)
		
	| [] -> (([], []), None)
    in
    let rec stitch (x, tl) =
      match tl with
	  [] -> x
	| (lbl, loc, blk)::tl -> 
	    let blk = (C.Block (x, Some lbl), loc)::blk in
	      stitch (blk, tl)
    in
    let (blk, e) = translate x in
      (stitch blk, e)

  and translate_stmt_exp loc (e, t) =
    match e with
	Set (lv, op, (IfExp (c, e1, e2, t), _)) -> 
	  let e = 
	    IfExp (c, (Set (lv, op, e1), snd e1), 
		   (Set (lv, op, e2), snd e2), t) 
	  in
	    translate_stmt_exp loc (e, t)

      | Set set -> 
	  let (set, _) = translate_set set in
	    (C.Set set, loc)::[]

      | Cast (e, Void) -> 
	  Npkcontext.report_accept_warning "Firstpass.translate_stmt" 
	    "cast to void" Npkcontext.DirtySyntax;
	  translate_stmt_exp loc e

      | IfExp (c, e1, e2, _) ->
	  let blk1 = (Exp e1, loc)::[] in
	  let blk2 = (Exp e2, loc)::[] in
	    translate_stmt (If (c, blk1, blk2), loc)

      | _ -> 
	  let e = translate_exp false (e, t) in
	    (C.Exp e, loc)::[]

  (* type and translate_stmt *)
  and translate_stmt (x, loc) = 
    Npkcontext.set_loc loc;
    match x with
	Exp e -> translate_stmt_exp loc e

      | Break -> (C.Goto brk_lbl, loc)::[]

      | Continue -> (C.Goto cnt_lbl, loc)::[]

      | Return -> (C.Goto ret_lbl, loc)::[]

      | Goto lbl -> 
	  let lbl = translate_lbl lbl in
	    (C.Goto lbl, loc)::[]

      | If (e, blk1, blk2) ->
	  let blk1 = translate_blk blk1 in
	  let blk2 = translate_blk blk2 in
	    translate_if loc (e, blk1, blk2)

      (* TODO: why is it necessary to have a block construction with None? *)
      | Block body -> (C.Block (translate_blk body, None), loc)::[]

      | DoWhile (body, e) -> 
	  let body = translate_blk body					 in
	  let guard = translate_stmt (If (e, [], (Break, loc)::[]), loc) in
	  let body = (C.Block (body@guard, Some cnt_lbl), loc)::[]	 in
	    (C.Block ((C.Loop body, loc)::[], Some brk_lbl), loc)::[]

      | For (init, e, body, suffix) ->
	  let init   = (C.Block (translate_blk init, Some cnt_lbl), loc)  in
	  let guard  = translate_stmt (If (e, [], (Break, loc)::[]), loc) in
	  let body   = translate_blk body				  in
	  let body   = (C.Block (guard@body, Some cnt_lbl), loc)	  in
	  let suffix = translate_blk suffix				  in
	  let loop   = (C.Loop (body::suffix), loc)			  in
	    (C.Block (init::loop::[], Some brk_lbl), loc)::[]

      | CSwitch (e, choices, default) -> 
	  let e 		 = translate_exp false e			    in
	  let (last_lbl, switch) = translate_switch choices			    in
	  let default_action 	 = (C.Goto default_lbl, loc)::[]		    in
	  let switch 		 = (C.Switch (e, switch, default_action), loc)::[]  in
	  let body 		 = translate_cases (last_lbl, switch) choices	    in
	  let default 		 = translate_blk default			    in
	  let body 		 = (C.Block (body, Some default_lbl), loc)::default in
	    (C.Block (body, Some brk_lbl), loc)::[]

      | UserSpec x -> (translate_assertion loc x)::[]

      | Label _ | LocalDecl _ -> 
	  Npkcontext.report_error "Firstpass.translate_stmt" "unreachable code"

  and translate_assertion loc x = (C.UserSpec (List.map translate_token x), loc)

  and translate_token x =
    match x with
	SymbolToken x 	  -> C.SymbolToken x
      | IdentToken x 	  -> C.IdentToken x
      | CstToken c 	  -> C.CstToken c
      | LvalToken (lv, t) -> 
	  let lv = translate_lv lv in
	  let t  = translate_typ t in
	    C.LvalToken (lv, t)
    

  (* TODO: think about this: simplify *)
  and translate_if loc (e, blk1, blk2) =
    (* restores the location that may have been destroyed during 
       the translation of blk1 and blk2
    *)
    Npkcontext.set_loc loc;
    (* TODO: this is a bit of a hack!! *)
    let rec select (blk1, blk2) =
      match (blk1, blk2) with
	  (_::(C.Guard c, _)::_, blk) when C.exp_is_false c -> blk
	| (blk, _::(C.Guard c, _)::_) when C.exp_is_false c -> blk
	| ((C.Guard c, _)::_, blk) when C.exp_is_false c -> blk
	| (blk, (C.Guard c, _)::_) when C.exp_is_false c -> blk
	| (hd1::tl1, hd2::tl2) when hd1 == hd2 -> hd1::(select (tl1, tl2))
	| _ -> (C.Select (blk1, blk2), loc)::[]
    in
    let rec translate_guard e =
      match e with
	  IfExp (Cst (C.CInt c, _), (t, _), _, _) 
	    when (Nat.compare c Nat.zero <> 0)->
	      translate_guard t
	| IfExp (Cst (C.CInt c, _), _, (f, _), _) 
	    when (Nat.compare c Nat.zero = 0) -> 
	    translate_guard f
	| IfExp (IfExp (c, t1, f1, _), t2, f2, t) -> 
	    translate_guard (IfExp (c, (IfExp (fst t1, t2, f2, t), t), 
				    (IfExp (fst f1, t2, f2, t), t), t))
	| IfExp (c, (t, _), (f, _), _) -> 
	    let c = translate_exp false (c, int_typ ()) in
	    let (pref, c, post) = C.normalize_exp c in
	    let guard_c = (C.Guard c, loc) in
	    let guard_not_c = (C.Guard (C.Unop (K.Not, c)), loc) in
	    let (t1, t2) = translate_guard t in
	    let (f1, f2) = translate_guard f in
	    let e1 = select (guard_c::post@t1, guard_not_c::post@f1) in
	    let e2 = select (guard_c::post@t2, guard_not_c::post@f2) in
	      (pref@e1, pref@e2)
	| Unop (Not, _, e) -> 
	    let (e1, e2) = translate_guard e in
	      (e2, e1)

	| BlkExp (blk, is_after) -> 
	    (* TODO: clean up and optimize, see if BlkExp could not 
	       be simplified!!! *)
	    let (body, e) = 
	      match List.rev blk with
		  (Exp (e, _), _)::tl -> (List.rev tl, e)
		| _ -> 
		    Npkcontext.report_error "Firstpass.translate_if" 
		      "unexpected block expression"
	    in
	    let body = translate_blk body in
	    let (br1, br2) = translate_guard e in
	      if is_after then (br1@body, br2@body)
	      else (body@br1, body@br2)

	| e -> 
	    let e = translate_exp false (e, int_typ ()) in
	    let (pref, e, post) = C.normalize_exp e in
	    let guard_e = pref@(C.Guard e, loc)::post in
	    let guard_not_e = pref@(C.Guard (C.Unop (K.Not, e)), loc)::post in
	      (guard_e, guard_not_e)
    in
    let (guard1, guard2) = translate_guard e in
    let blk1 = guard1@blk1 in
    let blk2 = guard2@blk2 in
      select (blk1, blk2)

  and translate_switch x =
    match x with
	(e, body, loc)::tl ->
	  let e = translate_exp false (e, int_typ ()) in
	  let t = translate_scalar_typ (int_typ ()) in
	  let (lbl, tl) = translate_switch tl in
	  let lbl = if body = [] then lbl else lbl+1 in
	    (lbl, ((e, t), (C.Goto lbl, loc)::[])::tl)
      | [] -> (default_lbl, [])

  and translate_cases (lbl, body) x =
    match x with
	(_, [], _)::tl -> translate_cases (lbl, body) tl
      | (_, case, loc)::tl ->
	  let case = translate_blk case in
	  let body = (C.Block (body, Some lbl), loc)::case in
	    translate_cases (lbl-1, body) tl
      | [] -> body

  and normalize_binop is_sz (op, t) (e1, t1) (e2, t2) =
    let cast e t = fst (cast e t) in
      match (op, t1, t2) with
	  (* TODO: this should be put in the typing phase!! *)
	  (* Would simplify this normalization as the operation is not modified!!! *)
	  (* Maybe possible to just have to do two casts!! *)
	| (Minus, Ptr _, Int _) -> 
	    let e2 = 
	      translate_binop is_sz (Minus, t2) (C.exp_of_int 0, t2) (e2, t2) 
	    in
 	      (Plus, (e1, t1), e2)
		
	| ((Mult|Plus|Minus|Div|Mod|BAnd|BXor|BOr|Gt|Eq), Int _, Int _) -> 
	    let e1 = cast (e1, t1) t in
	    let e2 = cast (e2, t2) t in
	      (op, (e1, t), (e2, t))
		
	| ((Mult|Plus|Minus|Div|Gt|Eq), Float _, Float _) -> 
	    let e1 = cast (e1, t1) t in
	    let e2 = cast (e2, t2) t in
	      (op, (e1, t), (e2, t))
		
	| ((Mult|Plus|Minus|Div|Gt|Eq), Float _, Int _)
	| ((Gt|Eq), Ptr _, Int _) ->
	    let e2 = cast (e2, t2) t1 in
	      (op, (e1, t1), (e2, t1))
		
	| ((Mult|Plus|Minus|Div|Gt|Eq), Int _, Float _)
	| ((Gt|Eq), Int _, Ptr _) -> 
	    let e1 = cast (e1, t1) t2 in
	      (op, (e1, t2), (e2, t2))
		
	| ((Shiftl|Shiftr), Int _, Int _) -> 
	    let e1 = cast (e1, t1) t in
	      (op, (e1, t), (e2, t))
		
	| (Plus, Int _, Ptr _) -> (Plus, (e2, t2), (e1, t1))
	    
	| _ -> (op, (e1, t1), (e2, t2))
	    
  and translate_binop is_sz (op, t) e1 e2 =
    (* TODO: think about it, maybe there are nicer ways to write this!!!*)
    let (op, (e1, t1), (e2, t2)) = normalize_binop is_sz (op, t) e1 e2 in
    let t = 
      match op with
	  Gt|Eq -> int_typ ()
	| _ -> t
    in
    let op =
      match (op, t1, t2) with
	  (* Arithmetic operations *)
	  (* Thanks to normalization t1 = t2 *)
	  (Mult, Int _, Int _) -> N.MultI
	| (Plus, Int _, Int _) -> N.PlusI
	| (Minus, Int _, Int _) -> N.MinusI
	| (Div, Int _, Int _) -> N.DivI
	| (Mod, Int _, Int _) -> N.Mod
	| (BAnd, Int k, Int _) -> N.BAnd (Newspeak.domain_of_typ k)
	| (BXor, Int k, Int _) -> N.BXor (Newspeak.domain_of_typ k)
	| (BOr, Int k, Int _) -> N.BOr (Newspeak.domain_of_typ k)
	    
	(* Thanks to normalization t1 = t2 *)
	| (Shiftl, Int _, Int _) -> N.Shiftlt
	| (Shiftr, Int _, Int _) -> N.Shiftrt
	    
	(* Float operations *)
	(* Thanks to normalization t1 = t2 *)
	| (Mult, Float n, Float _) -> N.MultF n
	| (Plus, Float n, Float _) -> N.PlusF n
	| (Minus, Float n, Float _) -> N.MinusF n
	| (Div, Float n, Float _) -> N.DivF n
	    
	(* Pointer operations *)
	| (Plus, Ptr _, Int _) -> N.PlusPI
	    
	| (Minus, Ptr _, Ptr _) -> N.MinusPP
	    
	(* Integer comparisons *)
	(* Thanks to normalization t1 = t2 *)
	(* Function translate_scalar_typ will ensure they are both scalar 
	   types *)
	| (Gt, _, _) -> N.Gt (translate_scalar_typ t1)
	| (Eq, _, _) -> N.Eq (translate_scalar_typ t1)
	    
	| _ ->
	    Npkcontext.report_error "Firstpass.translate_binop" 
	      "unexpected binary operator and arguments"
    in
    let e2 = 
      match (op, t) with
	  (N.PlusPI, Ptr t) -> 
	    if is_sz then e2
	    else let step = C.exp_of_int (size_of t) in
	      C.Binop (N.MultI, e2, step)
	| _ -> e2
    in
    let e = C.Binop (op, e1, e2) in
    let e = 
      (* add coerce if necessary *)
      match (op, t1, t) with
	  ((N.PlusI|N.MinusI|N.MultI|N.DivI|N.Shiftlt|N.Shiftrt), _, Int k) -> 
	    C.Unop (K.Coerce (Newspeak.domain_of_typ k), e)
	| (N.MinusPP, Ptr t, _) -> 
	    let step = size_of t in
	    let e = C.Binop (N.DivI, e, C.exp_of_int step) in
	      C.Unop (K.Coerce (Newspeak.domain_of_typ (C.int_kind ())), e)
	| _ -> e
    in
      (e, t)

  and translate_unop (op, t, e) = 
    let e = translate_exp false (e, t) in
    let e = 
      match (op, t) with
	  (Not, Ptr _) -> 
	    (* TODO: this is a bit of a hack, have Nil in cir?? *)
	    let nil = 
	      C.Unop (K.Cast (N.Int (C.int_kind ()), N.Ptr), C.exp_of_int 0) 
	    in
	      C.Binop (Newspeak.Eq Newspeak.Ptr, e, nil)
	| _ -> e
    in
    let op =
      match op with
	  Not -> K.Not
	| BNot k -> K.BNot (Newspeak.domain_of_typ k)
    in
      (op, e)


  and size_of t = C.size_of_typ (translate_typ t)

  and align_of t =
    match t with
	Comp (TypedC.Known c) -> 
	  let (_, _, a) = translate_comp c in
	    a
      | Array (t, _) -> align_of t
      | Bitfield (k, _) -> align_of (Int k)
      | _ -> size_of t

  (* TODO: simplify code of global declaration!!! *)
  and declare_global extern x name t init =
    update_global x name (t, K.Extern);
    let (t, init) = translate_glb_init name t init in
    let init = if extern then K.Extern else K.Declared init in
      update_global x name (t, init)
  in

  let translate_fundecl (f, declaration) =
    Npkcontext.set_loc declaration.position;
    current_fun := f;
    let ft = 
      match declaration.function_type with
	  (Some args_t, ret_t) -> (args_t, ret_t)
	| (None, _) -> 
	    Npkcontext.report_error "Firstpass.translate_global" 
	      "unreachable code"
    in
    let (_, args)   = add_formals ft in
    let body 	    = translate_blk declaration.body in
    let body 	    = (C.Block (body, Some ret_lbl), declaration.position)::[] in
    let ftyp 	    = translate_ftyp ft in
    let declaration = 
      {
	C.arg_identifiers = args;
	C.function_type = ftyp;
	C.body = body;
	C.position = declaration.position;
      }
    in
      Hashtbl.replace fundefs f declaration;
      current_fun := "";
      Hashtbl.clear lbl_tbl;
      lbl_cnt := default_lbl
  in
    
  (* TODO: a tad hacky!! Think about it *)
  (* TODO: could be done in the parser *)
  (* TODO: should be done in csyntax2CoreC *)
  let translate_global (x, (d, loc)) =
    Npkcontext.set_loc loc;
    (* TODO:TODO:TODO: remove static?? *)
    (* TODO:TODO:TODO: think about name and x difference, shouldn't there be 
       only normalized names in typedC? *)
    declare_global d.is_extern x d.name d.t d.initialization
  in

  let _add_glbdecl name (t, loc, storage) =
    Npkcontext.set_loc loc;
    try	Hashtbl.add glbdecls name (translate_typ t, loc, storage)
    with _ -> 
      (* TODO: could at least print a warning here *)
      ()
  in

    (* TODO: a tad inefficient *)
    (* seems necessary because of 536.c and 540.c and 679.c 
       maybe should really think about this and be stricter
       so as to perform everything in one pass
       Or better: should do all typing first.
       Then compile.
    *)
    init := 
      List.map (translate_assertion (Newspeak.dummy_loc "TODO!")) 
	prog.user_specifications;
    List.iter translate_global prog.global_variables;
    List.iter translate_fundecl prog.function_declarations;
    (* TODO: optimization: could remove this phase if cir had a type 
       structure of name 
       and all the structures' type were in a hashtbl *)
    { C.globals = glbdecls; C.init = !init; C.fundecs = fundefs }

