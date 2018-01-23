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

  Olivier Levillain
  email: olivier.levillain@penjili.org

  Sarah Zennou
  email: sarah(dot)zennou(at)eads(dot)net
*)

open Npkil

module Nat = Newspeak.Nat

module N = Newspeak

exception GenerateTmpNatExn

(*--------------*)
(* Linking time *)
(*--------------*)

(* TODO: should make these globals, local to linking, here they eat memory. *)
(* Association table global -> Newspeak.typ *)
let globals = Hashtbl.create 100
let cstr_init = ref []

let get_glob_typ name =
  try
    Hashtbl.find globals name
  with Not_found ->
    Npkcontext.report_error "Npklink.get_glob_typ" 
      ("type for global variable "^name^" not found")

let rec generate_typ t =
  match t with
      Scalar x -> Newspeak.Scalar x
    | Array (t, Some l) -> Newspeak.Array (generate_typ t, l)
    | Array (_, None) -> 
        Npkcontext.report_error "Link.generate_typ" "unknown array length"
    | Region (fields, sz) -> 
        Newspeak.Region (List.map generate_field fields, sz)

and generate_field (offs, t) = (offs, generate_typ t)

and generate_ftyp (args, rets) =
    (List.map generate_typ args, List.map generate_typ rets)

and generate_lv lv =
  match lv with
    | Global name -> N.Global name
    | Deref (e, sz) -> N.Deref (generate_exp e, sz)
    | Shift (lv', e) -> N.Shift (generate_lv lv', generate_exp e)
    | Local v -> N.Local v
    | Str str -> add_glb_cstr str
 
(* TODO: put in newspeak? *)
and exp_of_char c = N.Const (N.CInt (Nat.of_int (Char.code c)))
(* TODO: put in newspeak? *)
and exp_of_int x = N.Const (N.CInt (Nat.of_int x))

and add_glb_cstr str =
  let name = Temps.to_string 0 (Temps.Cstr str) in
    if not (Hashtbl.mem globals name) then begin
      let loc = Npkcontext.get_loc () in
      let len = String.length str in	  
      let t = N.Array (N.Scalar (N.char_typ ()), len + 1) in
	Hashtbl.add globals name t;
	(* TODO: think about it, this code is 
	   redundant with initialization in typedC2Cir *)
	let offset = ref 0 in
	let size = !Conf.size_of_char in
	  for i = 0 to len - 1 do
	    let e = exp_of_char str.[i] in
(* TODO: factor creation of lv *)
	    let lv = N.Shift (N.Global name, exp_of_int !offset) in
	      cstr_init := (N.Set (lv, e, N.char_typ ()), loc)::!cstr_init;
	      offset := !offset + size
	  done;
	  let lv = N.Shift (N.Global name, exp_of_int !offset) in
	    cstr_init := 
	      (N.Set (lv, exp_of_char '\x00', N.char_typ ()), loc)::!cstr_init
    end;
    N.Global name
    
and generate_exp e =
  match e with
    | Lval (lv, t) -> N.Lval (generate_lv lv, generate_typ t)
    | Const c -> N.Const c 
    | AddrOfFun (fid, ft) -> N.AddrOfFun (fid, generate_ftyp ft)
    | AddrOf (lv, sz) -> begin
        try 
	  generate_addr_of lv (Nat.to_int (generate_tmp_nat sz))
        with 
	    GenerateTmpNatExn -> N.AddrOf (generate_lv lv)
      end
    | UnOp (o, e) -> N.UnOp (generate_unop o, generate_exp e)
    | BinOp (o, e1, e2) -> N.BinOp (o, generate_exp e1, generate_exp e2)

(* TODO:
   Avoid redefinition of unop and binop. Use the same for npkil and newspeak
   just add a belongs_tmp to npkil !!! *)
and generate_unop o =
  match o with
      Belongs_tmp (l, u) -> 
        let u = Nat.sub (generate_tmp_nat u) Nat.one in
          Newspeak.Belongs (l, u)
    | Coerce r -> Newspeak.Coerce r
    | Not -> Newspeak.Not
    | BNot r -> Newspeak.BNot r
    | PtrToInt k -> Newspeak.PtrToInt k
    | IntToPtr k -> Newspeak.IntToPtr k
    | Cast (t1, t2) -> Newspeak.Cast (t1, t2)

and generate_tmp_nat x =
  match x with
      Unknown -> raise GenerateTmpNatExn
    | Known i -> i
    | Length name -> begin
        match get_glob_typ name with
            Newspeak.Array (_, len) -> Nat.of_int len
          | _ -> 
              Npkcontext.report_error "Npklink.generate_tmp_nat" 
                "array type expected"
      end
    | Mult (v, n) -> 
        let i = generate_tmp_nat v in
          Nat.mul_int n i

and generate_addr_of lv sz =
  if (sz > !Conf.max_sizeof) then begin
    Npkcontext.report_error "Link.generate_exp" 
      ("size too large: maximum allowed is "
       ^(string_of_int !Conf.max_sizeof)^" bits")
  end;
  N.UnOp (N.Focus sz, N.AddrOf (generate_lv lv))
	    
let generate_global name declaration =
  if declaration.is_used || (not !Npkcontext.remove_temp) then begin
      let t = generate_typ declaration.global_type in
	Hashtbl.add globals name t;
	match declaration.storage with
            Extern -> 
              Npkcontext.report_accept_warning "Link.generate_global" 
		("extern global variable "^name) Npkcontext.ExternGlobal
          | _ -> ()
    end;
    Npkcontext.print_debug ("Global linked: "^name)

let translate_set (lv, e, t) =
  match (t, e) with
      (Scalar t, _) -> N.Set (generate_lv lv, generate_exp e, t)
    | (Region (_, n), Lval (lv', _)) -> 
        N.Copy (generate_lv lv, generate_lv lv', n)
    | (Array ( _, Some size_t),  Lval (lv', _)) ->
	N.Copy ( generate_lv lv, generate_lv lv', size_t)
    | _ -> 
        Npkcontext.report_error "Linker.translate_set" 
          "translate_set not implemented yet"

let rec generate_stmt (sk, loc) =
  Npkcontext.set_loc loc;
  let new_sk = 
    match sk with
        Set (lv, e, t) -> translate_set (lv, e, t)
      | Decl (name, t, b) -> 
          N.Decl (name, generate_typ t, List.map generate_stmt b)
      | Guard cond -> N.Guard (generate_exp cond)
      | Select (body1, body2) ->
          N.Select (generate_blk body1, generate_blk body2)
      | InfLoop b -> N.InfLoop (List.map generate_stmt b)
      | Call (in_vars, (in_t, out_t), fn, out_vars) ->
	  (* TODO: push this code up into previous phase *)
	  let in_vars = generate_args in_vars in_t in
          let fn = generate_fn fn in
	  let out_vars = generate_rets out_vars out_t in
            N.Call (in_vars, fn, out_vars)
      | Goto lbl -> N.Goto lbl
      | DoWith (body, lbl) ->
          let body = List.map generate_stmt body in
            N.DoWith (body, lbl)
      | UserSpec x -> N.UserSpec (List.map generate_token x)
  in 
    (new_sk, loc)

(* TODO: cleanup push this up in previous phase *)
and generate_rets out_vars out_t =
  match (out_vars, out_t) with
      (lv::out_vars, t::out_t) -> 
	(generate_lv lv, generate_typ t)::(
	   generate_rets out_vars out_t)

    | ([], []) -> []
    | _ -> 
	(* TODO: clean code up so that this case doesn't need 
	   to be => change type of Call in npkil *)
	Npkcontext.report_error "Npklink.generate_rets" 
	  "return variables: invalid case"

and generate_args in_vars in_t =
  match (in_vars, in_t) with
      (e::in_vars, t::in_t) -> 
	(generate_exp e, generate_typ t)::(generate_args in_vars in_t)
    | ([], []) -> []
    | _ -> 
        Npkcontext.report_error "Npklink.generate_args" 
          "unexpected case when generating arguments"

and generate_token x =
  match x with
      SymbolToken c -> N.SymbolToken c
    | IdentToken x -> N.IdentToken x
    | LvalToken (lv, t) -> N.LvalToken (generate_lv lv, generate_typ t)
    | CstToken c -> N.CstToken c

and generate_blk x = List.map generate_stmt x
    
and generate_fn fn =
  match fn with
    | FunId f -> N.FunId f
    | FunDeref e -> N.FunDeref (generate_exp e)

and generate_body body = List.map generate_stmt body

let generate_fundecs fundecs =
  let funspecs = Hashtbl.create 100 in
  let add_fundec (name, declaration) =
    let body = generate_body declaration.body in
    let ftyp = generate_ftyp declaration.function_type in
    let ret_t = 
      match snd ftyp with
	  [] -> []
	| t::[] -> ("!return", t)::[]
(* TODO: handle this case *)
	| _ -> Npkcontext.report_error "Linker.generate_fundecs" 
	    "case not handled yet"
    in      
      if Hashtbl.mem funspecs name then begin
        Npkcontext.report_error "Npklink.generate_funspecs" 
          ("function "^name^" declared twice")
      end;
      Hashtbl.add funspecs name
        {
          N.rets = ret_t;
          N.args = List.combine declaration.arg_identifiers (fst ftyp);
          N.body = body;
	  N.position = declaration.position;
        };
      Npkcontext.forget_loc ();
      Npkcontext.print_debug ("Function linked: "^name)
  in
    List.iter add_fundec fundecs;
    funspecs      

let merge_types name prev_t t =
  try
    if (Npkil.is_mp_typ t prev_t) then t else prev_t
  with Npkil.Uncomparable -> 
    (* TODO: add the respective locations *)
    Npkcontext.report_error "Npklink.update_glob_link"
      ("different types for "^name^": '"
       ^(Npkil.string_of_typ prev_t)^"' and '"
       ^(Npkil.string_of_typ t)^"'")


let merge_storages name prev_loc prev_storage storage =
  match (storage, prev_storage) with
      (Extern, Declared _) -> prev_storage
    | (Declared _, Extern) -> storage
    | (Extern, Extern) -> prev_storage
    | (Declared true, Declared true) -> 
        Npkcontext.report_error "Npklink.update_glob_link" 
          ("multiple declaration of "^name)
    | _ ->
	let loc = Npkcontext.get_loc () in
        let info = 
          if prev_loc = loc then begin
            let (file, _, _) = loc in
              ", in file "^file^" variable "
              ^name^" should probably be extern"
            end 
	  else begin
            " (previous definition: "
            ^(Newspeak.string_of_loc prev_loc)^")"
          end
        in
          Npkcontext.report_accept_warning "Npklink.update_glob_link"
            ("multiple definitions of global variable "^name^info) 
            Npkcontext.MultipleDef;             
          prev_storage

(* TODO: optimization, this is probably not efficient to read the whole
   program and then again a second time!!! reprogram Npkil.read and write *)
let merge npkos =
  let src_lang = ref N.C in
  let glb_decls = Hashtbl.create 100 in
  let init = ref [] in
  let fundefs = ref [] in

  let add_fundef f body = fundefs := (f, body)::!fundefs in

  let add_global name declaration =
    Npkcontext.set_loc declaration.global_position;
    try
      let previous_declaration = Hashtbl.find glb_decls name in
      let t = 
	merge_types name previous_declaration.global_type 
	  declaration.global_type 
      in
      let prev_loc = previous_declaration.global_position in
      let storage = 
	merge_storages name prev_loc 
	  previous_declaration.storage declaration.storage
      in
      let loc = 
	if storage = declaration.storage then
	  declaration.global_position
	else
	  prev_loc
      in
      let used = declaration.is_used || previous_declaration.is_used in
      let declaration = 
	{
	  global_type = t;
	  global_position = loc;
	  storage = storage;
	  is_used = used;
	}
      in
        Hashtbl.replace glb_decls name declaration
          
    with Not_found -> Hashtbl.add glb_decls name declaration
  in

  let merge npko =
    let prog = Npkil.read npko in
      Hashtbl.iter add_global prog.globals;
      init := prog.init@(!init);
      Hashtbl.iter add_fundef prog.fundecs;
      src_lang := prog.src_lang
  in
    List.iter merge npkos;
    (glb_decls, !fundefs, !src_lang, !init)

let reject_backward_gotos prog =
  let defined_lbls = ref [] in

  let rec reject_blk x = List.iter reject_stmt x

  and reject_stmt (x, _) =
    match x with
	N.Decl (_, _, blk) | N.InfLoop blk -> reject_blk blk
      | N.Select (blk1, blk2) -> 
	  reject_blk blk1;
	  reject_blk blk2
      | N.DoWith (blk, lbl) -> 
	  let backup = !defined_lbls in
	    defined_lbls := lbl::!defined_lbls;
	    reject_blk blk;
	    defined_lbls := backup
      | N.Goto lbl when not (List.mem lbl !defined_lbls) -> 
	  Npkcontext.report_error "Linker.reject_backward_gotos" 
	    "backward goto not accepted"
      | _ -> ()
  in

    reject_blk prog.N.init;
    Hashtbl.iter (fun _ fundec -> reject_blk fundec.N.body) prog.N.fundecs

let make_abi () = {
  N.endianness =
    if !Conf.is_little_endian then
      N.LittleEndian
    else
      N.BigEndian;

  N.arithmetic_in_structs_allowed = !Conf.arithmetic_in_structs_allowed;
  N.unaligned_ptr_deref_allowed = !Conf.unaligned_ptr_deref_allowed;
  N.max_sizeof = !Conf.max_sizeof;
  N.max_array_length = !Conf.max_array_length;
  N.types = {
    N.char_signedness =
      if !Conf.is_char_type_signed then
        N.Signed
      else
        N.Unsigned;
    N.size_of_byte = !Conf.size_of_byte;
    N.sa_void       = {N.size = !Conf.size_of_void      ; N.align = !Conf.align_of_void      };
    N.sa_char       = {N.size = !Conf.size_of_char      ; N.align = !Conf.align_of_char      };
    N.sa_ptr        = {N.size = !Conf.size_of_ptr       ; N.align = !Conf.align_of_ptr       };
    N.sa_short      = {N.size = !Conf.size_of_short     ; N.align = !Conf.align_of_short     };
    N.sa_int        = {N.size = !Conf.size_of_int       ; N.align = !Conf.align_of_int       };
    N.sa_long       = {N.size = !Conf.size_of_long      ; N.align = !Conf.align_of_long      };
    N.sa_longlong   = {N.size = !Conf.size_of_longlong  ; N.align = !Conf.align_of_longlong  };
    N.sa_float      = {N.size = !Conf.size_of_float     ; N.align = !Conf.align_of_float     };
    N.sa_double     = {N.size = !Conf.size_of_double    ; N.align = !Conf.align_of_double    };
    N.sa_longdouble = {N.size = !Conf.size_of_longdouble; N.align = !Conf.align_of_longdouble};

  }
}


let link npkos =
  Npkcontext.forget_loc ();
    
  Npkcontext.print_debug "Linking files...";
  let (glb_decls, fun_decls, src_lang, init) = merge npkos in
    
    Npkcontext.print_debug "Globals...";
    Hashtbl.iter generate_global glb_decls;
    Npkcontext.forget_loc ();
    
    Npkcontext.print_debug "Functions...";
    let init = generate_blk init in
    let fundecs = generate_fundecs fun_decls in
(* TODO: think about it: a bit inefficient *)
    let init = (List.rev !cstr_init)@init in
        
    let prog = { 
      N.globals = globals;
      N.init = init;
      N.fundecs = fundecs;
      N.ptr_sz = !Conf.size_of_ptr;
      N.src_lang = src_lang;
      N.abi = make_abi ();
    } 
    in
      
      Npkcontext.print_debug "File linked.";
      reject_backward_gotos prog;
      let prog_simpl = 
        if !Npkcontext.no_opt then prog
        else Newspeak.simplify !Npkcontext.opt_checks prog
      in
	Newspeak.write !Npkcontext.output_file prog_simpl;
	if !Npkcontext.verb_newspeak then begin
          print_endline "Newspeak output";
          print_endline "---------------";
          Newspeak.dump prog_simpl;
          print_newline ()
	end;
	if !Npkcontext.verb_lowspeak then begin
	  print_endline "Lowspeak output";
	  print_endline "---------------";
	  Lowspeak.dump (Npk2lpk.translate prog_simpl);
	  print_newline ()
	end


