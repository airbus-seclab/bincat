(*
  C2Newspeak: compiles C code into Newspeak. Newspeak is a minimal language 
  well-suited for static analysis.
  Copyright (C) 2007, 2010, 2011  Charles Hymans, Etienne Millon, Sarah Zennou
  
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

  Etienne Millon
  etienne.millon@eads.net

  Sarah Zennou
  sarah(dot)zennou(at)eads(dot)net
*)

open Newspeak

module L = Lowspeak

let tmp_var = Temps.to_string 0 (Temps.Misc "npk2lpk")

let new_id =
  let c = ref 0 in
  fun _ ->
    incr c;
    !c

let scalar_of_typ t =
  match t with
      Scalar t -> t
    | _ -> 
        Npkcontext.report_error "Npk2lpk.scalar_of_typ" "scalar type expected"

let default_args_ids fid n = 
  let rec create_args i =
    if i > n then []
    else (fid^".arg"^(string_of_int i))::(create_args (i+1))
  in
    create_args 1

class normalize_ptr_shift =
object
  inherit L.builder
  method process_exp e =
    let rec process_exp e = 
      match e with
	| L.UnOp (IntToPtr i, L.UnOp ((Coerce r), L.BinOp (PlusI, e1, e2))) -> begin
	    match e1, e2 with
		L.UnOp ((PtrToInt (Signed, _)), L.Lval (lv, Ptr)), L.Const (CInt c) ->
		      let ptr_sz = size_of_scalar !Conf.size_of_ptr Ptr in
		      let d = domain_of_typ (Signed, ptr_sz) in
			if contains d r then 
			  let e1 = L.Lval (lv, Ptr) in
			  let c = Nat.mul c "8" in
			  let e2 = L.Const (CInt c) in
			    L.BinOp (PlusPI, e1, e2)
			else e 
	      | L.Const (CInt _), L.UnOp ((PtrToInt (Signed, _)), L.Lval (_, Ptr)) ->
		  let e = L.UnOp (IntToPtr i, L.UnOp ((Coerce r), L.BinOp (PlusI, e2, e1))) in
		    process_exp e
	      | L.UnOp ((PtrToInt (Signed, _)), L.Lval (lv, Ptr)), L.Lval (_, (Int _)) ->
		      let ptr_sz = size_of_scalar !Conf.size_of_ptr Ptr in
		      let d = domain_of_typ (Signed, ptr_sz) in
			if contains d r then 
			  let e1 = L.Lval (lv, Ptr) in
			    L.BinOp (PlusPI, e1, e2)
			else e 
	      |  L.Lval (_, (Int _)), L.UnOp ((PtrToInt (Signed, _)), L.Lval (_, Ptr)) ->
		   let e = L.UnOp (IntToPtr i, L.UnOp ((Coerce r), L.BinOp (PlusI, e2, e1))) in
		    process_exp e
	      | _ -> e
	  end	  
	| _ -> e
    in
      process_exp e
end

let normalize_ptr_shift prog =
  let builder = new normalize_ptr_shift in
    L.build builder prog

let translate prog = 
  
  let fundecs = Hashtbl.create 100 in
  let globals = Hashtbl.create 100 in

  let env = Hashtbl.create 100 in
  let stack_height = ref 0 in
  let push id =
    incr stack_height;
    Hashtbl.add env id !stack_height
  in
  let pop id =
    decr stack_height;
    Hashtbl.remove env id
  in

  let rec translate_exp e =
    match e with
        Const c -> L.Const c
      | Lval (lv, t) -> L.Lval (translate_lval lv, scalar_of_typ t)
      | AddrOf lv -> L.AddrOf (translate_lval lv)
      | AddrOfFun (f, ft) -> L.AddrOfFun (f, ft)
      | UnOp (op, e) -> L.UnOp (op, translate_exp e)
      | BinOp (op, e1, e2) -> L.BinOp (op, translate_exp e1, translate_exp e2)

  and translate_lval lv =
    match lv with
        Local v -> 
          let x = 
            try Hashtbl.find env v
            with Not_found -> 
              Npkcontext.report_error "Hpk2npk.translate_lval"
                ("unknown local variable "^v)
          in
            L.Local (!stack_height - x)
      | Global x -> L.Global x
      | Deref (e, sz) -> L.Deref (translate_exp e, sz)
      | Shift (lv, e) -> L.Shift (translate_lval lv, translate_exp e)
  in

  let translate_set (lv, e, t) =
    match (t, e) with
	(Scalar t, _) -> 
	  let tr_lv = translate_lval lv in
	  let tr_ex = translate_exp e in
	    (*cast introduce for cast arguments => cast back
	      let tr_ex_cast = 
	      L.UnOp (---, translate_exp etr_ex)
	    *)
	  
	    L.Set (tr_lv, tr_ex , t)
	    
	    
      | (Region (_, n), Lval (lv', _)) -> 
	  L.Copy (translate_lval lv, translate_lval lv', n)
      | _ -> 
	  Npkcontext.report_error "Hpk2npk.translate_set" 
	    "translate_set not implemented yet"
  in

  let translate_fn x ft =
    match x with
        FunId f -> L.FunId f
      | FunDeref e -> L.FunDeref (translate_exp e, ft)
  in
    
  let translate_token x =
    match x with
        SymbolToken c -> L.SymbolToken c
      | IdentToken s -> L.IdentToken s
      | LvalToken (lv, t) -> L.LvalToken (translate_lval lv, t)
      | CstToken c -> L.CstToken c
  in

  let translate_assertion x = List.map translate_token x in

 
  let prefix_args loc f args args_ids ft =
    let rec add args =
      match args with
	  ((e, t)::args, x::args_ids) ->
	    push tmp_var;
	    let set = translate_set (Local tmp_var, e, t) in
	    let call = add (args, args_ids) in
	      pop tmp_var;
	      let full_call = (set, loc)::(call, loc)::[] in
		L.Decl (x, t, full_call)

	| ([], _) -> L.Call (translate_fn f ft)
	| _ -> raise Not_found	    
    in
      add (args, args_ids)
  in

  let suffix_rets fid loc f (args, ret_vars) args_ids ft =
    let rec add rets =
      match rets with
          (lv, t)::titi -> 
            push tmp_var;
            let e = Lval (Local tmp_var, t) in

	    (* TO DO:  Cast back for ADA in translate_set *)
	    let set = translate_set (lv, e, t) in  

	    let call = add titi in 

            let x = Temps.to_string (new_id ()) (Temps.Value_of fid) in
              pop tmp_var;
	      L.Decl (x, t, (call, loc)::(set, loc)::[])
        | [] -> prefix_args loc f args args_ids ft
	    
    in
    let add_fst rets =
      match rets with
          (Local v, _)::[] when Hashtbl.find env v = !stack_height -> begin
	    try 
	      prefix_args loc f args args_ids ft 

	    with _ -> 
	      (*Not_found due to the mix btw 
		returned_val et Out param Ada*)
	      add rets 
	  end
	    
        | _ ->  add rets
    in
      add_fst ret_vars
  in

  let rec translate_blk x = List.map translate_stmt x 
  
  and translate_stmt (x, loc) = (translate_stmtkind loc x, loc)

  and translate_stmtkind loc x = 
    match x with
        Call (args, f, ret_vars) ->
          let (fid, args_ids) = 
            match f with
                FunId fid ->
                  let args_ids = 
                    try
                      let fundec = Hashtbl.find prog.fundecs fid in
                        List.map fst fundec.args
                    with Not_found -> 
		      default_args_ids fid (List.length args) 
                  in 
		    (fid, args_ids)
	      | FunDeref _ -> 
                  let fid = "fptr_call" in
                    (fid, default_args_ids fid (List.length args))
          in
	  let ft = (List.map snd args, List.map snd ret_vars) in
          suffix_rets fid loc f (args, ret_vars) args_ids ft

      | DoWith (body, lbl) -> L.DoWith (translate_blk body, lbl)
      | Goto lbl -> L.Goto lbl
      | Decl (x, t, body) -> 
          push x;
          let body = translate_blk body in
            pop x;
            L.Decl (x, t, body)
      | Set (lv, e, t) -> 
	  translate_set (lv, e, Scalar t)
      | Copy (dst, src, sz) -> 
	  L.Copy (translate_lval dst, translate_lval src, sz)
      | Select (body1, body2) -> 
          let body1 = translate_blk body1 in
          let body2 = translate_blk body2 in
            L.Select (body1, body2)
      | Guard e -> L.Guard (translate_exp e)
      | InfLoop body -> 
          let body = translate_blk body in
            L.InfLoop body
      | UserSpec x -> L.UserSpec (translate_assertion x) 
  in

  let translate_fundec f fd =
    let ret_ids = 
      match fd.rets with
	| [] -> []
	| (v, _)::[] -> [v]
(* TODO: remove this case *)
	| _ -> 
	    Npkcontext.report_error "Npk2lpk.translate_fundec" 
	      "case not handled yet"
    in
    let ret_t =
      match fd.rets with
	  [] -> []
	| (_, t)::[] -> t::[]
	| _ -> 
	    Npkcontext.report_error "Npk2lpk.translate_fundec" 
	      "case not handled yet"
    in
    let arg_ids = List.map fst fd.args in
    let ft = (List.map snd fd.args, ret_t) in
    List.iter push ret_ids;
    List.iter push arg_ids;
    let body = translate_blk fd.body in
    List.iter pop arg_ids;
    List.iter pop ret_ids;
    let declaration = 
      { L.position = fd.position; L.ftyp = ft; L.body = body } 
    in
      Hashtbl.add fundecs f declaration
  in

  let translate_global x t = 
    Hashtbl.add globals x t in
    let init = translate_blk prog.init in
    Hashtbl.iter translate_fundec prog.fundecs;
    Hashtbl.iter translate_global prog.globals;

    let p = { 
      L.globals = globals;
      L.init = init;
      L.fundecs = fundecs;
      L.ptr_sz = prog.ptr_sz;
      L.src_lang = prog.src_lang;
      L.abi = prog.abi;
    }
    in normalize_ptr_shift p

