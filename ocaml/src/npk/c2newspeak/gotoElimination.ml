(*
  C2Newspeak: compiles C code into Newspeak. Newspeak is a minimal language 
  well-suited for static analysis.
  Copyright (C) 2009, 2010  Sarah Zennou, Charles Hymans
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

  Sarah Zennou
  EADS Innovation Works - SE/IS
  12, rue Pasteur - BP 76 - 92152 Suresnes Cedex - France
  email: sarah (dot) zennou (at) eads (dot) net

  Charles Hymans
  EADS Innovation Works - SE/CS
  12, rue Pasteur - BP 76 - 92152 Suresnes Cedex - France
  email: charles.hymans@penjili.org
*)

open Csyntax
  
let fresh_lbl lbl = Temps.to_string 0 (Temps.Goto_label lbl)

let goto_lbl lbl g_offset = lbl ^ "." ^ g_offset

let del_goto_suffix lbl = 
  try 
    let i = String.index lbl '.' in String.sub lbl 0 i
  with Not_found -> lbl
 
let zero () = Cst (Cir.CInt Newspeak.Nat.zero, uint_typ ())
let one () = Cst (Cir.CInt (Newspeak.Nat.of_int 1), uint_typ ()) 
  
let dummy_cond () = one ()
 
let goto_equal lbl lbl' g_offset = compare lbl' (lbl^"."^ g_offset) = 0
    
let has_label stmts lbl =
  (* returns true if one of the statements is Label lbl *)
  let rec has stmts =
    match stmts with
	[] -> false
      | (stmt, _)::stmts -> 
	  match stmt with
	      Label lbl' when lbl' = lbl -> true
	    | Block blk -> (has blk)||(has stmts)
	    | _ -> has stmts
  in
    has stmts

let has_goto stmts lbl g_offset =
  (* returns true if one of the statement is the desired goto *)
  let rec has stmts = 
    match stmts with
	[] -> false 
      | (stmt, _)::stmts ->
	  match stmt with
	      If (_, [Goto lbl', _], []) when goto_equal lbl lbl' g_offset -> true
	    | Block blk -> (has blk)||(has stmts)
	    | _ -> has stmts
  in has stmts
      
type lblPos = No | In | Nested

let search_lbl stmts lbl =
 (* returns true if one of the statement is the label lbl or
     contains a stmt where the label is nested *)
  let rec search stmts =
  match stmts with
      [] -> false
    | (stmt, _)::stmts -> 
	match stmt with 
	    Label lbl' when lbl = lbl' -> true
	  | If(_, if_blk, else_blk) -> 
	      (search if_blk)||(search else_blk)||(search stmts)
		
	  | For(_,_,blk,_) -> (search blk)||(search stmts)
	
	  | DoWhile(blk, _) -> (search blk)||(search stmts)
	
	  | Block blk -> (search blk)||(search stmts)
	      
	  | CSwitch (_, cases, default) ->
	      (List.exists (fun (_, blk, _) -> search blk) cases) 
	     ||(search default)||(search stmts)
		
	  | _ -> search stmts
  in search stmts

let preprocessing lbls stmts =
  (* For every goto stmt:
     - adds conditional goto statement
     - adds the additional boolean variables 
     - fills the (label -> goto id, offset) table. 
*)
  let nth = ref 0 in
  let cond_addition stmts =
    let rec add stmts =
    match stmts with
	[] -> []
      | (stmt, l)::stmts ->
	  match stmt with
	      Goto lbl -> begin
		let o = string_of_int !nth in
		let lbl' = goto_lbl lbl o in
		  begin
		    try 
		      let (gotos, o') = Hashtbl.find lbls lbl in
			Hashtbl.replace lbls lbl ((o, l)::gotos, o');
		    with Not_found ->
		      Hashtbl.add lbls lbl ([o, l],  Newspeak.unknown_loc)
		  end;
		  nth := !nth + 1;
		  let if' = If(dummy_cond (), [Goto lbl', l], []) in
		    (if', l)::(add stmts)
	      end

	    | Label lbl -> begin
		try
		  let (gotos, _) = Hashtbl.find lbls lbl in
		    Hashtbl.replace lbls lbl (gotos, l)
		with
		    Not_found -> Hashtbl.add lbls lbl ([], l)
	      end;
		(stmt, l)::(add stmts)

	    | If(e, if_blk, else_blk) ->
		let if_blk' = add if_blk in
		let else_blk' = add else_blk in
		let stmts' = add stmts in
		  (If(e, if_blk', else_blk'), l)::stmts'
		    
	    | DoWhile(blk, e) ->
		let blk' = add blk in
		  (DoWhile(blk', e), l)::(add stmts)
		    
	    | Block blk -> 
		let blk' = add blk in
		  (Block blk', l)::(add stmts)
		    
	    | For(blk1, e, blk2, blk3) ->
		(* we suppose that only blk2 may contain goto stmts *)
		let blk2' = add blk2 in
		  (For (blk1, e, blk2', blk3), l)::(add stmts)
		    
	    | CSwitch(e, cases, default) ->
		let add_cases cases (e, blk, l) =
		  let blk' = add blk in
		    (e, blk', l)::cases
		in
		let cases' = List.rev (List.fold_left add_cases [] cases) in
		let default' = add default in
		  (CSwitch(e, cases', default'), l)::(add stmts)
		    
	    | _ -> (stmt, l)::(add stmts)
    in
      add stmts
  in
    if stmts = [] then ([], [])
    else begin
      let (_, l) = List.hd stmts in
      let decl lbl =
	let lbl' = fresh_lbl lbl in
	let init = Data (zero ()) in
	let d = 
	  {
	    t = uint_typ ();
	    is_static = false;
	    is_extern = false;
	    initialization = Some init
	  }
	in
	  (* TODO: try to factor VDecl creations *)
	let vdecl = LocalDecl (lbl', VDecl d) in
	  (vdecl, l)
      in
      let stmts' = cond_addition stmts in
      let lbl' = ref [] in
	Hashtbl.iter (fun lbl (gotos, _) -> 
			if gotos = [] then Hashtbl.remove lbls lbl 
			else lbl' := lbl::!lbl') lbls;
	let lbl' = List.rev !lbl' in
	let vdecls = List.map decl lbl' in
	  (vdecls, stmts')
    end
		         

		
exception Indirect
exception Direct
exception Sibling

let related stmts lbl g_offset =
  let rec goto_or_label previous =
    match previous with
	In -> raise Sibling
      | Nested -> raise Direct
      | No -> In
    and loops previous p stmts =
    match previous, p with
	Nested, In -> raise Indirect
      | Nested, Nested -> raise Indirect
      | Nested, No -> related previous stmts
      | In, In -> raise Direct
      | In, Nested -> raise Direct
      | In, No -> related previous stmts
      | No, p ->
	  let p = if p = In then Nested else p in 
	    related p stmts
    and related previous stmts =
    match stmts with
	[] -> previous
      | (stmt, _)::stmts -> 
	  match stmt with
	      If(_, [Goto lbl', _], []) when goto_equal lbl lbl' g_offset ->
		let p = goto_or_label previous in related p stmts
						    
	    | Label lbl' when lbl = lbl' -> 
		let p = goto_or_label previous in related p stmts
						    
	    | For(_, _, blk, _) -> 
		let p = related No blk in loops previous p stmts
					    
	    | DoWhile(blk, _) ->
		let p = related No blk in loops previous p stmts
					    
	    | Block blk -> 
		let p = related previous blk in related p stmts
	
	    | If(_, if_blk, else_blk) ->
		let p = related No if_blk in
		let p' = related No else_blk in
		if p = No then loops previous p' stmts
		else 
		  if p' = No then loops previous p stmts else raise Indirect
		  
	    | CSwitch (_, cases, default) ->
		let rec rel previous cases =
		  match cases with
		      [] -> previous
		    | (_, blk, _)::cases -> 
			let p = related No blk in 
			if p = No then rel previous cases 
			else let p' = loops previous p [] in rel p' cases
		in
		let p = rel No cases in
		let p' = related No default in
		  if p = No then loops previous p' stmts
		  else 
		    if p' = No then loops previous p stmts else raise Indirect

	    | _ -> related previous stmts
  in related No stmts 
       
let directly_related stmts lbl g_offset =
  (*returns true if the label and goto levels are directly related *)
  try 
    let _ = related stmts lbl g_offset in 
      invalid_arg "Goto_elimination.directly_related: goto and label not found"
  with 
      Direct -> true 
    | Indirect | Sibling -> false 
  
    
let indirectly_related stmts lbl g_offset =
  (* returns true if the goto and label stmts are indirectly related *)
  try 
    let _ = related stmts lbl g_offset in
      invalid_arg "Goto_elimination.indirectly_related: goto and label not found"
  with
      Indirect -> true
    | Direct | Sibling ->false

let avoid_break_continue_capture stmts lwhile l g_offset vdecls = 
  let rec add stmts l var skind =
    let stmts', vars = search stmts in
    let set = Exp (Set( (Var var), None, one ())) in
      (set, l)::((skind, l)::stmts'), (skind, var)::vars
  and search stmts =
    match stmts with 
	[] -> [], []
      | (stmt, l')::stmts ->
	  match stmt with
	      Break -> 
		let var = "break."^(Newspeak.string_of_loc l')^"."^g_offset in
		add stmts l' var Break
	
	    | Continue ->
		let var = "continue."^(Newspeak.string_of_loc l')^"."^g_offset in
		  add stmts l' var Continue

	    | If (e, if_blk, else_blk) ->
		let if_blk', if_vars = search if_blk in
		let else_blk', else_vars = search else_blk in
		  (If(e, if_blk', else_blk'), l')::stmts, (if_vars@else_vars)
		 
	    | Block blk ->
		let blk', blk_vars' = search blk in
		let stmts', vars' = search stmts in
		  (Block blk', l)::stmts', blk_vars'@vars'   
	    | _ -> 
		let stmts', vars = search stmts in (stmt, l)::stmts', vars
  in
  let stmts', vars = search stmts in
    if vars = [] then stmts', []
    else 
      let init = Data (zero ()) in
      let after = ref [] in 
      let add (skind, var) =
	(* TODO: factor VDecl creations *)
	let d = 
	  {
	    t = uint_typ ();
	    is_static = false;
	    is_extern = false;
	    initialization = Some init
	  }
	in
	let vdecl = LocalDecl (var, VDecl d) in
	let set = Exp (Set (Var var, None, zero ())) in
	let if_blk = (set, lwhile)::[skind, lwhile] in
	let if' = If (Var var, if_blk, []) in
	  vdecls := vdecl::!vdecls;
	  after := (if', lwhile)::!after
      in
	List.iter add vars;
	stmts', (List.rev !after)



  let rec extract_decls stmts =
    match stmts with
	[] -> [], []
      | (stmt, l)::stmts ->
	  let s_decls, stmts' = extract_decls stmts in
	    match stmt with
		LocalDecl _ -> 
		  let (decls, stmts') = extract_decls stmts in 
		    ((stmt, l)::decls, stmts')
	      | Block blk -> 
		  let b_decls, blk' = extract_decls blk in 
		    (b_decls@s_decls, (Block blk', l)::stmts')
	      | _ -> (s_decls, (stmt, l)::stmts')


exception Lbl
exception Gto 

let rec split_lbl stmts lbl = 
  match stmts with 
      [] -> [], []
    | (stmt, l)::stmts' ->
	match stmt with
	    Label lbl' when lbl = lbl' -> [], stmts
	  | Block blk -> 
	      if search_lbl blk lbl then 
		let before, blk' = split_lbl blk lbl in
		let before = if before = [] then [] else [Block before, l] in
		let blk' = if blk' = [] then [] else [Block blk', l] in 
		  before,  blk'@stmts'
	      else 
		let before, stmts' = split_lbl stmts' lbl in (stmt, l)::before, stmts'

	  | _ -> let before, stmts' = split_lbl stmts' lbl in (stmt, l)::before, stmts'

let extract_first_forward_goto lbl g_offset blk =
  let rec extract stmts =
    match stmts with
	[] -> raise Not_found
      | (stmt, l)::stmts -> 
	  match stmt with
	      If (_, [Goto lbl', _], []) when goto_equal lbl lbl' g_offset ->
		([], (stmt, l), stmts)
	    | Block blk -> begin
		try
		  let (prefix, goto_stmt, suffix) = extract blk in 
		    ((Block prefix, l)::[], goto_stmt, (Block suffix, l)::[])
		with
		    Not_found -> 
		      let (prefix, goto_stmt, suffix) = extract stmts in
			((stmt, l)::prefix, goto_stmt, suffix)
	      end
	    | _ -> 
		let (prefix, goto_stmt, suffix) = extract stmts in 
		  ((stmt, l)::prefix, goto_stmt, suffix)
  in
    extract blk

let sibling_elimination stmts lbl g_offset vdecls =
  let rec direction stmts =
    match stmts with
	[] -> raise Not_found
      | (stmt, _)::stmts ->
	  match stmt with
	      Label lbl' when lbl = lbl' -> raise Lbl
	    | If(_, [Goto lbl', _], []) when goto_equal lbl lbl' g_offset -> 
		raise Gto 
	    | Block blk -> begin
		try direction blk with Not_found -> 
		  direction stmts
	      end
	    | _ -> direction stmts
  in
  let rec b_delete_goto stmts =
    match stmts with
	[] -> raise Not_found
      | (stmt, l)::stmts ->
	  match stmt with
	      If(e, [Goto lbl', _], []) when goto_equal lbl lbl' g_offset -> 
		e, [], [], stmts
	    | Block blk -> begin
		try
		  let e, before, blk', after = b_delete_goto blk in
		  let decls, blk' = extract_decls blk' in
		  let blk' = blk' @ after in
		    if blk' = [] then e, before@decls, [], stmts
		    else
		      e, before@decls, [Block blk', l], stmts
		with
		    Not_found -> 
		      let e, before, blk, after = b_delete_goto stmts in
			e, before, (stmt, l)::blk, after
	      end
	    | LocalDecl _ ->
		let e, before, blk, after = b_delete_goto stmts in
		  e, (stmt, l)::before, blk, after 
	    | _ ->
		let e, before, blk, after = b_delete_goto stmts in
		  e, before, (stmt, l)::blk, after
  in
  let backward_wrap stmt l stmts =
    try
      let e, before, blk', after = b_delete_goto ((stmt,l)::stmts) in
      let l' = try snd (List.hd (List.rev blk')) with Failure _ -> l in
      let blk', after' = 
	avoid_break_continue_capture blk' l l' g_offset vdecls 
      in
	before@((DoWhile (blk', e), l)::(after'@after))
    with
	(* goto may have disappeared because of optimizations *)
	Not_found -> (stmt, l)::stmts
  in

  let rec backward stmts =
    match stmts with
	[] -> []
      | (stmt, l)::stmts ->
	  match stmt with
	      Label lbl' when lbl' = lbl -> backward_wrap stmt l stmts 
	    | Block blk when search_lbl blk lbl -> backward_wrap stmt l stmts
	    | _ -> (stmt, l)::(backward stmts)
  in
  
  let rec forward stmts = 
    match stmts with
	[] -> []
      | (stmt, l)::stmts ->
	  match stmt with
	      If (e, [Goto lbl', _], []) when goto_equal lbl lbl' g_offset -> 
		let before, after = split_lbl stmts lbl in
		let decls, before = extract_decls before in
		  if before = [] then decls@after
		  else begin
		    let if' = If (Unop(Not, e), before, []) in 
		      decls @ ((if', l)::after)
		  end
	    | Block blk -> begin
		try
		  let (prefix, goto_stmt, blk') = 
		    extract_first_forward_goto lbl g_offset blk 
		  in
		  let decls, blk' = extract_decls blk' in
		  let stmts' = [Block blk', l] in
		  let stmts' = goto_stmt::(decls @ stmts' @ stmts) in
		    prefix @ (forward stmts')
		with Not_found -> (stmt, l)::(forward stmts)
	      end
	    | _ -> (stmt, l)::(forward stmts)
  in

  let rec choose blk =
    match blk with
	[] -> ([], false)
      | stmt::blk -> choose_stmt stmt blk

  and choose_stmt (stmt, l) stmts =
    match stmt with
	If (_, [Goto lbl', _], []) when goto_equal lbl lbl' g_offset ->
	  forward ((stmt, l)::stmts), true
      | Label lbl' when lbl' = lbl -> 
	  let stmts' = (stmt, l)::stmts in 
	    backward stmts', true
      | Block blk -> begin
	  try direction blk with 
	      Gto -> forward ((stmt, l)::stmts), true 
	    | Lbl -> backward ((stmt, l)::stmts), true
	    | Not_found -> 
		let blk', b' = choose blk in 
		  if not b' then begin
		    let stmts', b' = choose stmts in 
		      (stmt, l)::stmts', b'
		  end else (Block blk', l)::stmts, true
	end
      | If (e, if_blk, else_blk) -> 
	  let if_blk', b = choose if_blk in 
	    if b then (If(e, if_blk', else_blk), l)::stmts, true
	    else begin
	      let else_blk', b' = choose else_blk in
		if b' then (If (e, if_blk, else_blk'), l)::stmts, true
		else begin
		  let stmts', b' = choose stmts in 
		    (stmt, l)::stmts', b'
		end
	    end
      | For (blk1, e, blk2, blk3) ->
	  let blk2', b = choose blk2 in 
	    if b then (For (blk1, e, blk2', blk3), l)::stmts, true
	    else begin
	      let stmts', b' = choose stmts in 
		(stmt, l)::stmts', b'
	    end
      | DoWhile (blk, e) ->
	  let blk', b = choose blk in 
	    if b then (DoWhile(blk', e), l)::stmts, true
	    else begin
	      let stmts', b' = choose stmts in 
		(stmt, l)::stmts', b'
	    end
      | CSwitch (e, cases, default) ->
	  let rec iter cases =
	    match cases with
		[] -> [], false
	      | (e, stmts, l)::cases -> 
		  let stmts', b = choose stmts in
		    if b then (e, stmts', l)::cases, true
		    else begin
		      let cases', b' = iter cases in 
			(e, stmts', l)::cases', b'
		    end
	  in
	  let cases', b' = iter cases in
	    if b' then (CSwitch(e, cases', default), l)::stmts, true
	    else begin
	      let default', b' = choose default in 
		if b' then (CSwitch(e, cases, default'), l)::stmts, true
		else begin
		  let stmts', b' = choose stmts in
		    (stmt, l)::stmts', b'
		end
	    end
      | _ -> 
	  let stmts', b' = choose stmts in 
	    (stmt, l)::stmts', b'
  in
    fst (choose stmts) 

let cond_equal cond e =
  match cond, e with
      Var v, Var v' when v = v' -> true
    | _, _ -> false

let out_if_else stmts lbl level g_offset =
  (* returns the stmt list whose 'goto lbl' stmt has been deleted and
     the condition if (fresh_lbl lbl) goto this fresh lbl has been
     added at the right position (see fig 5) *)
  let rec out stmts =
    match stmts with
	[] -> [], []	  
      | (stmt, l)::stmts ->
	  match stmt with
	      If (e, [Goto lbl', l'], []) when goto_equal lbl lbl' g_offset ->
		  let lbl = fresh_lbl lbl in 
		  let cond = Var lbl in
		  let n_cond = Unop(Not, cond) in
		  let stmt = 
		    if cond_equal cond e then [] else [Exp (Set (cond, None, e)), l] 
		  in
		  let if_goto = If(cond, [Goto lbl', l'], []) in
		    level := !level-1; 
		    if stmts = [] then
		      stmt, [if_goto, l]
		    else
		      stmt @ [(If(n_cond, stmts, []), l)], [if_goto, l]

	    | Block blk -> let blk', cond = out blk in 
		if cond = [] then 
		  let stmts', cond = out stmts in (Block blk, l)::stmts', cond
		else (Block blk', l)::stmts, cond

	    | _ -> let stmts', cond = out stmts in (stmt, l)::stmts', cond
  in out stmts
      
      
let out_switch_loop stmts lbl level g_offset =
  (* returns the stmt list whose 'goto lbl' stmt has been deleted
     and replaced by some stmt according to the algo of Figure 4
     (Moving a goto out of a switch) *)
  let rec out stmts =
    match stmts with 
	[] -> [], []
      | (stmt, l)::stmts ->
	  match stmt with
	      If (e, [Goto lbl', l'], []) ->
		if goto_equal lbl lbl' g_offset then begin
		  let f_lbl = fresh_lbl lbl in 
		  let f_lbl = Var f_lbl in
		  let stmt = 
		    if cond_equal f_lbl e then []
		    else [Exp (Set (f_lbl, None, e)), l] 
		  in
		  let if_goto_in = If(f_lbl, [Break, l'], []) in
		  let if_goto_out = If(f_lbl, [Goto lbl', l'], []) in
		  let stmts', cond = out stmts in
		    level := !level-1;
		    stmt @ ((if_goto_in, l)::stmts'), (if_goto_out, l)::cond
		end
		else
		  let stmts', cond = out stmts in (stmt, l)::stmts', cond
	    | Block blk ->
		let blk', cond = out blk in
		  if cond = [] then 
		    let stmts', cond = out stmts in (Block blk, l)::stmts', cond
		  else (Block blk', l)::stmts, cond    		      
	    | _ -> let stmts', cond = out stmts in (stmt, l)::stmts', cond
  in out stmts



let outward stmts lbl g_level g_offset =
  (* moves the goto stmt with label lbl at location o: 
     - either until the goto becomes direclty related to the label, 
     if they are in different stmts
     - or until the goto becomes directly related to an if or switch
     containing label lbl otherwise*)
  let rec out blk stmts f p =
    if has_goto blk lbl g_offset then
      if p blk lbl then blk, stmts, false
      else
	let blk', after = f blk lbl g_level g_offset in blk', (after @ stmts), true
    else 
      let blk', b = outward blk in blk', stmts, b

  and fold blk stmts f p =
    let blk', stmts', b = out blk stmts f p in
      if not b then 
	let stmts', b' = outward stmts in blk', stmts', b' 
      else 
	let blk', stmts', _ = fold blk' stmts' f p in blk', stmts', true
  
  and outward stmts =
    match stmts with
	[] -> [], false
      | (stmt, l)::stmts ->
	  match stmt with
	      For (blk1, e, blk2, blk3) ->  
		let blk2', stmts', b' = fold blk2 stmts out_switch_loop search_lbl in
		  (For(blk1, e, blk2', blk3), l)::stmts', b'
		    
	    | DoWhile (blk, e) -> 
		let blk', stmts', b' = fold blk stmts out_switch_loop search_lbl in
		  (DoWhile (blk', e), l)::stmts', b'
		    
	    | If (e, if_blk, else_blk) ->
		let rec if_fold if_blk stmts = 
		  let if_blk', stmts', b' = out if_blk stmts out_if_else search_lbl in
		    if not b' then 
		      let else_blk', stmts', b' = fold else_blk stmts out_if_else search_lbl in
		      if_blk', else_blk', stmts', b'
		    else 
		      let if_blk', else_blk', stmts', _ = if_fold if_blk' stmts' in
			if_blk', else_blk', stmts', true
		in
		let if_blk', else_blk', stmts', b' = if_fold if_blk stmts in
		    (If(e, if_blk', else_blk'), l)::stmts', b'
		  
	    | CSwitch(e, cases, default) ->
		let rec case_fold cases =
		  match cases with 
		      [] -> [], [], false
		    | (e, blk, l')::cases ->
			let blk', stmts, b' = fold blk stmts out_switch_loop has_label in
			  if not b' then 
			    let cases', stmts', b' = case_fold cases in
			      (e, blk, l')::cases', stmts', b'
			  else 
			    let cases' = (e, blk', l')::cases in
			      cases', stmts, true
		in
		let cases', stmts', b' = case_fold cases in
		  if not b' then 
		    let default', stmts', b' = fold default stmts out_switch_loop has_label in
			  (CSwitch(e, cases, default'), l)::stmts', b'
		  else
		    (CSwitch(e, cases', default), l)::stmts', true

	    | Block blk -> 
		let blk', b' = outward blk in 
		  if not b' then 
		    let stmts', b' = outward stmts in
		      (stmt, l)::stmts', b'
		  else
		    (Block blk', l)::stmts, b'

	    | _ -> let stmts', b' = outward stmts in (stmt, l)::stmts', b'	

 in fst (outward stmts)
      
      

	      
let rec if_else_in lbl l e before cond if_blk else_blk g_offset g_loc =
  let lbl' = Var (fresh_lbl lbl) in
  let lb = try snd (List.hd before) with Failure _ -> l in
  let set = if cond_equal lbl' e then [] else [Exp (Set (lbl', None, e)), lb] in
    if search_lbl if_blk lbl then 
      begin
	let cond = Csyntax.and_bexp (normalize_bexp lbl') cond in
	let l' = try snd (List.hd if_blk) with Failure _ -> l in
	let g_lbl = goto_lbl lbl g_offset in
	let if' = If (lbl', [Goto g_lbl, g_loc], []) in
	let if_blk' = (if', l')::if_blk in
	let if_blk' = inward lbl g_offset g_loc if_blk' in
	let if' = If (cond, if_blk', else_blk) in
	let decls, before = extract_decls before in
	  if before = [] then 
	    set @ decls @ [if', l']
	  else
	    let before' = If (Unop(Not, lbl'), before, []) in
	      set @ decls @ [(before', lb); (if', l')]
      end
    else 
      begin
	let cond = Csyntax.and_bexp (normalize_bexp (Unop(Not, lbl'))) cond in
	let l' = try snd (List.hd else_blk) with Failure _ -> l in
	let g_lbl = goto_lbl lbl g_offset in
	let if' = If (lbl', [Goto g_lbl, g_loc], []) in
	let else_blk' = (if', l')::else_blk in
	let else_blk' = inward lbl g_offset g_loc else_blk' in
	let if' = If (cond, if_blk, else_blk') in
	let decls, before = extract_decls before in
	  if before = [] then 
	    set @ decls @ [if', l']
	  else
	    let before' = If (Unop(Not, lbl'), before, []) in
	      set @ decls @ [(before', lb); (if', l')]
      end

and loop_in lbl l e before cond blk g_offset g_loc b =
  (* b is boolean param true when the expression to generate is for a
     While loop and false for a DoWhile loop *)
  let lbl' = Var (fresh_lbl lbl) in
  let rec search_and_add stmts =
    match stmts with
	[] -> []
      | (stmt, l)::stmts ->
	  match stmt with
	      Label lb when lb = lbl -> 
		let set = Exp (Set(lbl', None, zero ())) in
		  (stmt, l)::((set, l)::stmts)

	    | Block blk -> 
		let blk' = search_and_add blk in 
		  if blk = blk' then (stmt, l)::(search_and_add stmts) 
		  else (Block blk', l)::stmts

	    | _ -> (stmt, l)::(search_and_add stmts)
  in
  let lb = try snd (List.hd before) with Failure _ -> l in
  let set = 
    if cond_equal lbl' e then [] else [Exp (Set (lbl', None, e)), lb] 
  in
  let e = 
    if b then (* expression for While *) or_bexp (normalize_bexp lbl') cond 
    else (* expression for DoWhile *)  cond 
  in
  let g_lbl = goto_lbl lbl g_offset in
  let if' = If(lbl', [Goto g_lbl, g_loc], []) in
  let blk' = search_and_add blk in
  let l' = try snd (List.hd blk') with Failure _ -> l in
  let blk' = (if', l')::blk' in
  let blk' = inward lbl g_offset g_loc blk' in
  let decls, before = extract_decls before in
    if before = [] then 
      (* optimisation when there are no stmts before the loop *)
	set @ decls, blk', e
    else 
      let before' = If(Unop(Not, lbl'), before, []) in
	  set @ decls @ [before', lb], blk', e
  

and while_in lbl l e before cond blk1 blk2 blk3 g_offset g_loc=
  let stmts', blk2', e = loop_in lbl l e before cond blk2 g_offset g_loc true in
    stmts'@[For(blk1, e, blk2', blk3), l]

and dowhile_in lbl l e before cond blk g_offset g_loc =
  let stmts', blk', e = loop_in lbl l e before cond blk g_offset g_loc false in
    stmts'@[DoWhile(blk', e), l]

and cswitch_in lbl l e before cond cases default g_offset g_loc =
  let lbl' = Var (fresh_lbl lbl) in
  let tswitch = "switch."^(Newspeak.string_of_loc l)^"."^g_offset in
  let d = 
    { 
      t = uint_typ ();
      is_static = false;
      is_extern = false;
      initialization = None
    } 
  in
  let declr = LocalDecl (tswitch, VDecl d) in
  let tswitch = Var tswitch in
  let lb = try snd (List.hd before) with Failure _ -> l in
  let set = if cond_equal lbl' e then [] else [Exp (Set (lbl', None, e)), lb] in
  let set_if = Exp (Set(tswitch, None, cond)) in
  let last = try (snd (List.hd (List.rev before))) with Failure _ -> l in
  let before' = before @ [set_if, last] in
  let decls, before' = extract_decls before' in
  let g_lbl = goto_lbl lbl g_offset in
  let if' = If(lbl', [Goto g_lbl, g_loc], []) in
  let rec search_lbl cases =
    match cases with 
	[] -> raise Not_found
      | (e, stmts, l)::cases -> 
	  if has_label stmts lbl then 
	      let stmts' = (if', l)::stmts in
	      let stmts' = inward lbl g_offset g_loc stmts' in
		e, (e, stmts', l)::cases
	  else let exp, cases' = search_lbl cases in exp, (e, stmts, l)::cases'
  in
    try 
      let e_case, cases' = search_lbl cases in
      let set_else = Exp (Set(tswitch, None, e_case)) in
      let switch' = CSwitch(tswitch, cases', default) in
	if before' = [] then
	  set @ decls @[switch' ,l]
	else
	  let if' = If(Unop(Not, lbl'), before', [set_else, l]) in
	    set @ decls @ [(declr, lb) ; (if', lb) ; (switch', l)]
    with Not_found ->
      let conds = List.map (fun (e, _, _) -> e) cases in
      let build e e' = or_bexp e e' in
      let e_default = List.fold_left build (zero ()) conds in
      let e_default = Unop(Not, e_default) in
      let set_else = Exp (Set(tswitch, None, e_default)) in
      let default' = (if', l)::default in
      let default' = inward lbl g_offset g_loc default' in
      let switch' = CSwitch(tswitch, cases, default') in
	if before' = [] then
	  set @ decls @[switch', l]
	else
	  let if' = If(Unop(Not, lbl'), before', [set_else, l]) in
	    set @ decls @ [(declr, lb) ; (if', lb) ; (switch', l)]

and block_in lbl l e before blk g_offset g_loc =
  let lb = try snd (List.hd before) with Failure _ -> l in
  let blk' = (If(e, [Goto (goto_lbl lbl g_offset), g_loc], []), lb)::blk in
  let blk' = inward lbl g_offset g_loc blk' in
  let lbl' =  Var (fresh_lbl lbl) in
  let decls, before = extract_decls before in
    if before = [] then decls @ [Block blk', l]
    else 
      let if' = If(Unop(Not, lbl'), before, []) in
	decls @ [(if', lb) ; (Block blk', l)] 

and inward lbl g_offset g_loc stmts =
  let rec search_goto_cond before stmts =
    match stmts with
	[] -> raise Not_found
      | (stmt, l)::stmts ->
	  match stmt with
	      If(e, [Goto lbl', _], []) when goto_equal lbl lbl' g_offset -> (List.rev before), e, stmts
	    | Block blk -> begin
		try
		  let before', e, blk' = search_goto_cond before blk in
		    before', e, (Block blk', l)::stmts
		with 
		    Not_found -> let before' = (stmt, l)::before in search_goto_cond before' stmts
	      end
	    | _ -> let before' = (stmt, l)::before in search_goto_cond before' stmts
  in
  let rec inward before stmts = 
    match stmts with
	[] -> []
      | (stmt, l)::stmts ->
	  if has_label [stmt, l] lbl then
	    before@((stmt, l)::stmts)
	  else
	    if search_lbl [stmt, l] lbl then 
	      try
		let before', e, after' = search_goto_cond [] before in
		let stmts' =
		  match stmt with
		      If (ie, if_blk, else_blk) -> 
			if_else_in lbl l e after' ie if_blk else_blk g_offset g_loc
			  
		    | For (blk1, cond, blk2, blk3) -> 
			while_in lbl l e after' cond blk1 blk2 blk3 g_offset g_loc
			  
		    | DoWhile(blk, cond) ->
			dowhile_in lbl l e after' cond blk g_offset g_loc
			  
		    | CSwitch (ce, cases, default) -> 
			cswitch_in lbl l e after' ce cases default g_offset g_loc
			  
		    | Block blk -> 
			block_in lbl l e after' blk g_offset g_loc 
			  
		    | _ -> (stmt, l)::stmts 
		in
		  before'@stmts'@stmts
	      with
		  Not_found ->
		    match stmt with
			Block blk -> 
			  let blk' = inward [] blk in before@((Block blk', l)::stmts)
		      | _ -> invalid_arg ("Goto_elimination.inward: goto has to be in that stmt list")
	    else 
	      let before' = before@[stmt, l] in inward before' stmts
  in inward [] stmts
       

       
let lifting_and_inward stmts lbl l_level g_level g_offset g_loc vdecls =
  let rec split_goto stmts =
    match stmts with
	[] -> raise Not_found
      | (stmt, l)::stmts ->
	  match stmt with
	      If(e, [Goto lbl', _], _) when goto_equal lbl lbl' g_offset ->
		[], stmts, e
	    | Block blk -> begin
		try
		  let blk', after, e = split_goto blk in 
		    [Block blk', l], (Block after, l)::stmts, e
		with
		    Not_found -> 
		      let blk, after, e = split_goto stmts in
			(stmt, l)::blk, after, e
	      end
	    | _ ->
		let blk, after, e = split_goto stmts in
		  (stmt, l)::blk, after, e
		    
  in
  let rec lifting stmts =
    match stmts with
	[] -> []
      | (stmt, l)::stmts -> 
	  match stmt with
	      Block blk when search_lbl [stmt, l] lbl && has_goto [stmt, l] lbl g_offset ->
		    (Block (lifting blk), l)::stmts
	    | _ ->
		if search_lbl [stmt, l] lbl then 
		  let blk, after, e = split_goto stmts in
		  let g_lbl = goto_lbl lbl g_offset in
		  let lbl' = Var (fresh_lbl lbl) in
		  let if' = If(lbl', [Goto g_lbl, g_loc], []) in
		  let l_set = try snd (List.hd (List.rev blk)) with Failure _ -> l in
		  let set = if cond_equal lbl' e then [] else [Exp (Set (lbl', None, e)), l_set] in
		  let blk', after' = avoid_break_continue_capture blk l l_set g_offset vdecls in
		  let blk' = [(if', l) ; (stmt, l)] @ blk' @ set in
		    (* inward transformations on the blk chunk. We know that the
		       first stmt is the goto stmt and the second one contains
		       the label stmt *)
		  let blk' = inward lbl g_offset g_loc blk' in	   
		    (* do-while loop *)
		  let blk' = [DoWhile(blk', lbl'), l_set] in
		    blk' @ after @ after'
 		else 
		  let stmts' = lifting stmts in
		    (stmt, l)::stmts'
  in
  let rec lifting_and_inward stmts = 
    if has_goto stmts lbl g_offset then
      begin
	try 
	  (* lifting the backward goto above the label. If
	     the goto is forward then Not_found is raised and lifting is
	     skiped *)
	  let stmts' = lifting stmts in
	    g_level := !g_level + 1;
	    l_level := !l_level + 1;
	    stmts', true
	with 
	    (* goto is forward. Call to inward only*)
	    Not_found -> inward lbl g_offset g_loc stmts, true
      end
    else
      match stmts with
	  [] -> [], false
	| (stmt, l)::stmts -> 
	    match stmt with
		If(e, if_blk, else_blk) -> 
		  let if_blk', b' = lifting_and_inward if_blk in
		  let else_blk', b' =  if b' then else_blk, b' else lifting_and_inward else_blk in
		  let stmts', b' = if b' then stmts, b' else lifting_and_inward stmts in
		  let if' = If(e, if_blk', else_blk') in
		    (if', l)::stmts', b'
		      
	      | CSwitch (e, cases, blk) ->
		  let rec iter cases =
		    match cases with 
			[] -> [], false
		      | (e, blk, l)::cases ->
			  let blk', b = lifting_and_inward blk in 
			  let c = (e, blk', l) in
			  let cases', b' = if b then cases, b else iter cases in
			    c::cases', (b||b')
		  in 
		  let cases', b = iter cases in
		  let blk', b' = if b then blk, b else lifting_and_inward blk in
		  let stmts', b' = if b' then stmts, b' else lifting_and_inward stmts in
		    (CSwitch (e, cases', blk'), l)::stmts', b'
		      
	      | For(blk1, e, blk2, blk3) ->
		  let blk2', b' = lifting_and_inward blk2 in
		  let stmts', b' = if b' then stmts, b' else lifting_and_inward stmts in
		    (For(blk1, e, blk2', blk3), l)::stmts', b' 
		      
	      | DoWhile(blk, e) -> 
		  let blk', b' = lifting_and_inward blk in
		  let stmts', b' = if b' then stmts, b' else lifting_and_inward stmts in
		    (DoWhile(blk', e), l)::stmts', b'
		      
	      | Block blk ->
		  let blk', b = lifting_and_inward blk in
		  let stmt' = Block blk' in
		    if b then (stmt', l)::stmts, b
		    else
		      let stmts', b' = lifting_and_inward stmts in
			(stmt', l)::stmts', b'
			  
	      | _ -> let stmts', b = lifting_and_inward stmts in (stmt, l)::stmts', b
  in
    fst (lifting_and_inward stmts)


let compute_level stmts lbl id =
  let rec compute n stmts =
    match stmts with
	[] -> -1, -1
      | (stmt, _)::stmts' ->
	  let ll, lo = 
	    match stmt with
		Label lbl' when lbl = lbl' -> n, -1
	      | If (_, [Goto lbl', _], []) when goto_equal lbl lbl' id -> -1, n
	      | If (_, if_blk, else_blk) ->
		  let n' = n+1 in
		  let il, io = compute n' if_blk in
		    if il <> -1 && io <> -1 then
		      il, io
		    else
		      let el, eo = compute n' else_blk in
			max il el, max io eo
	      | Block blk -> compute n blk
	      | For(_,_,blk,_) -> compute (n+1) blk
	      | DoWhile(blk, _) -> compute (n+1) blk
	      | CSwitch (_, cases, default) ->
		  let n' = n+1 in
		  let il, io = List.fold_left (fun (ll, lo) (_, blk, _) -> 
				    (* optimize : exit as soon as ll, lo <> -1, -1 *)
				       let ll', lo' = compute n' blk in
					 max ll ll', max lo lo'
					      ) (-1, -1) cases
		  in
		    if il <> -1 && io <> -1 then
		      il, io
		    else
		      let el, eo = compute n' default in
			max il el, max io eo
	      | _ -> -1, -1
		  
	  in
	    if ll <> -1 && lo <> -1 then 
	      ll, lo 
	    else
	      let ll', lo' = compute n stmts' in
		max ll ll', max lo lo'
  in
    compute 0 stmts

let elimination stmts lbl gotos vdecls =
  (* moves all gotos of the given label lbl. lo is the pair
     (level, offset) of the label statement *)
  let stmts = ref stmts in
  let move goto =
    let id, o = goto in
    let l_level, l = compute_level !stmts lbl id in
    let l = ref l in
      (* force goto and label to be directly related *)
      if indirectly_related !stmts lbl id 
      then stmts := outward !stmts lbl l id;
      (* force goto and label to be siblings *)
      if directly_related !stmts lbl id then begin
	if !l > l_level then begin stmts := outward !stmts lbl l id
	end else begin 
	  let l_level = ref l_level in
	    stmts := lifting_and_inward !stmts lbl l_level l id o vdecls
	end
      end;
      (* goto and label are sibling; eliminate goto and label *) 
      stmts := sibling_elimination !stmts lbl id vdecls
  in
    List.iter move gotos;
    !stmts

let renaming_block_variables stmts =
  let names = Hashtbl.create 10 in
  let stack = ref [[]] in
    
  let rename s = 
    try 
      let n = Hashtbl.find names s in
	Hashtbl.replace names s (n+1);
	s^"."^(string_of_int n)
    with Not_found -> Hashtbl.add names s 0; s
  in

  let is_prefix prefix s = 
    let n = String.compare prefix s in
      if n = 0 then true
      else if n < 0 then
	let prefix' = prefix ^ "." in 
	let len = String.length prefix' in
	  try 
	    let s' = String.sub s 0 len in
	      String.compare prefix' s' = 0
	  with _ -> false
      else false
  in

  let find s =
    let rec find blocks =
      match blocks with
	  b::blocks -> 	begin
	    try List.find (is_prefix s) b
	    with Not_found -> find blocks
	  end
	| _ -> s 
	    (*this case matches non variable identifiers or undeclared
	      variables *)
    in
      find !stack
  in

  let rec replace_exp e =
    match e with
	Cst _ | RetVar | Sizeof _ | Offsetof _ | Str _ | FunName | BlkExp _ -> e
      | Var s -> Var (find s) 
      | Field(e, s) -> Field(replace_exp e, s)
      | Index(e1, e2) -> Index(replace_exp e1, replace_exp e2)
      | AddrOf e -> AddrOf (replace_exp e)
      | Unop (op, e) -> Unop(op, replace_exp e)
      | IfExp (e1, e2, e3) -> IfExp(replace_exp e1, replace_exp e2, replace_exp e3)
      | Binop (op, e1, e2) -> Binop(op, replace_exp e1, replace_exp e2)
      | Call (e, e_list) -> Call (replace_exp e, List.map replace_exp e_list)
      | SizeofE e -> SizeofE (replace_exp e)
      | Cast (e, t) -> Cast (replace_exp e, t)
      | Set (e1, op, e2) -> Set (replace_exp e1, op, replace_exp e2)
      | OpExp (op, e, b) -> OpExp (op, replace_exp e, b)
  in
  let replace_decl decl =
    let rec rinit init =
      match init with
	  Data e -> Data (replace_exp e)
	| Sequence s -> Sequence (List.map (fun (s, i) -> (s, rinit i)) s)
    in
      match decl with
	  VDecl d -> begin 
	    match d.initialization with 
		None -> decl
	      | Some init -> 
		  VDecl { d with initialization = Some (rinit init) }
	  end
	| EDecl e -> EDecl (replace_exp e)
	| _ -> decl
  in

  let replace_assert a =
    let replace a = 
      match a with
	  IdentToken s ->  IdentToken (find s) 
	| _ -> a
    in
      List.map replace a
  in

  let push_block () = 
    stack := []::!stack
      
  in
  let add_var s = 
    let b = List.hd !stack in
      stack := (s::b)::(List.tl !stack)
	
	
  in
  let pop_block () = 
    try stack := List.tl !stack
    with Failure _ ->
      invalid_arg "Goto_elimination.pop_block: the stack is empty"
  in
  let rec explore stmts =
    match stmts with
	[] -> []
      | (stmt, l)::stmts ->
	  let stmt' = 
	    match stmt with
		LocalDecl (s, decl) -> 
		  let s' = rename s in
		  let decl' = replace_decl decl in
		    add_var s';
		    LocalDecl(s', decl')

	      | Block blk ->
		  push_block();
		  let blk' = explore blk in
		    pop_block ();
		    Block blk'

	      | If(e, iblk, eblk) ->
		  let e' = replace_exp e in
		  let iblk' = explore iblk in
		  let eblk' = explore eblk in
		    If(e', iblk', eblk')

	      | Exp e -> Exp (replace_exp e)

	      | CSwitch(e, cases, default) ->
		  let apply (e, blk, l) =
		    let e' = replace_exp e in
		    let blk' = explore blk in
		      (e', blk', l)
		  in
		  let e' = replace_exp e in
		  let cases' = List.map apply cases in
		  let default' = explore default in
		    CSwitch (e', cases', default')

	      | For(blk1, e, blk2, blk3) ->
		  let e' = replace_exp e in
		  let blk1' = explore blk1 in
		  let blk2' = explore blk2 in
		  let blk3' = explore blk3 in
		    For(blk1', e', blk2', blk3') 

	      | DoWhile(blk, e) ->
		  let e' = replace_exp e in
		  let blk' = explore blk in
		    DoWhile(blk', e')

	      | UserSpec a -> UserSpec (replace_assert a)
	      | _ -> stmt
	  in
	    (stmt', l)::(explore stmts)
  in
    explore stmts


let rec deleting_goto_ids stmts =
  match stmts with
      [] -> []
    | (stmt, l)::stmts ->
	match stmt with
	    Goto lbl -> 
	      let lbl' = del_goto_suffix lbl in 
		(Goto lbl', l)::(deleting_goto_ids stmts) 
		  
	  | If(e, if_blk, else_blk) ->
	      let if_blk' = deleting_goto_ids if_blk in
	      let else_blk' = deleting_goto_ids else_blk in
		(If(e, if_blk', else_blk'), l)::(deleting_goto_ids stmts)

	  | Block blk -> 
	      let blk' = deleting_goto_ids blk in
		(Block blk', l)::(deleting_goto_ids stmts)

	  | For(blk1, e, blk2, blk3) ->
	      let blk1' = deleting_goto_ids blk1 in
	      let blk2' = deleting_goto_ids blk2 in
	      let blk3' = deleting_goto_ids blk3 in
		(For(blk1', e, blk2', blk3'), l)::(deleting_goto_ids stmts)

	  | CSwitch(e, cases, default) ->
	      let cases' = ref [] in
	      let add (e, blk, l) = 
		cases':= (e, deleting_goto_ids blk, l)::!cases'
	      in
		List.iter add cases; 
		let cases' = List.rev !cases' in
		let default' = deleting_goto_ids default in
		  (CSwitch(e, cases', default'), l)::(deleting_goto_ids stmts)

	  | DoWhile(blk, e) ->
	      let blk' = deleting_goto_ids blk in 
		(DoWhile(blk', e), l)::(deleting_goto_ids stmts)

	  | _ -> (stmt, l)::(deleting_goto_ids stmts)

let promoting_block_variables stmts =
  let rec promote stmts =
    match stmts with
	[] -> [], []
      | (stmt, l)::stmts' ->
	  let decl, stmts' = promote stmts' in
	    match stmt with
		LocalDecl _ -> (stmt, l)::decl, stmts'

	      | Block blk -> 
		  let bdecl, blk' = promote blk
		  in bdecl @ decl, (Block blk', l)::stmts'

	      | DoWhile(blk, e) ->
		  let ddecl, blk' = promote blk in
		    ddecl @ decl, (DoWhile(blk', e), l)::stmts'

	      | For(blk1, e, blk2, blk3) ->
		  let decl1, blk1' = promote blk1 in
		  let decl2, blk2' = promote blk2 in
		  let decl3, blk3' = promote blk3 in
		    decl1@decl2@decl3@decl, (For(blk1', e, blk2', blk3'), l)::stmts'

	      | If(e, iblk, eblk) -> 
		  let idecl, iblk' = promote iblk in
		  let edecl, eblk' = promote eblk in
		    idecl@edecl@decl, (If(e, iblk', eblk'), l)::stmts'

	      | CSwitch(e, cases, default) ->
		  let cdecl, cases' = List.fold_right (fun (e, blk, l) (decl, cases) -> 
							 let decl', blk' = promote blk in
							   decl'@decl, (e, blk', l)::cases) cases ([], [])
		  in
		  let ddecl, default' = promote default in
		    cdecl@ddecl@decl, (CSwitch(e, cases', default'), l)::stmts'

	      | _ -> decl, (stmt, l)::stmts'

  in
  let decl, stmts' = promote stmts in decl @ stmts'

let run prog =
  let elimination lbls stmts =
    let vars = ref [] in
    (* goto elimination *)
    let stmts = ref stmts in
    let move lbl (g, _) = stmts := elimination !stmts lbl g vars in
      Hashtbl.iter move lbls;
      (deleting_goto_ids !stmts, !vars)
  in
  let in_fun_elimination stmts =
    let lbls = Hashtbl.create 30 in
    (* adding a fresh boolean variable to each label stmt *)
    (* computing offset and level for each pair of goto/label statement *)
    (* making all goto stmt conditional *)
    let vdecls', stmts' = preprocessing lbls stmts in
      match vdecls' with
	  [] -> (* no goto found *) 
	    stmts'
	| (_, l)::_ -> 
	    (* processing goto elimination *)
	    let stmts' = vdecls'@stmts' in
	      (* replacing vars with the same name and making them to be
		 at function scope *)
	    let stmts' = renaming_block_variables stmts' in
	    let stmts' = promoting_block_variables stmts' in
	    let (stmts', vars) = elimination lbls stmts' in
	    let vars' = List.map (fun vdecl -> (vdecl, l)) vars in
	      vars'@stmts'
  in
  let process_function_definition (g, l) =
    let g =
      match g with
	  FunctionDef (s, t, b, stmts) ->
	    let stmts' = in_fun_elimination stmts in
	      FunctionDef (s, t, b, stmts')
	| _ -> g
    in
      (g, l)
  in
    List.map process_function_definition prog

