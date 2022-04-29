(*
  C2Newspea: compiles C code into Newspeak. Newspeak is a minimal language 
  well-suited for static analysis.
  Copyright (C) 2007-2022  Charles Hymans, Olivier Levillain, Sarah Zennou, 
  Etienne Millon
  
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
  EADS Innovation Works - SE/IS
  12, rue Pasteur - BP 76 - 92152 Suresnes Cedex - France
  email: sarah.zennou@eads.net

  Etienne Millon
  EADS Innovation Works - SE/IS
  12, rue Pasteur - BP 76 - 92152 Suresnes Cedex - France
  email: etienne.millon@eads.net
*)

module N = Newspeak

(*-------*)
(* Types *)
(*-------*)

type t = {
  globals: N.globals;
  init: blk;
  fundecs: (N.fid, fundec) Hashtbl.t;
  ptr_sz: N.size_t;
  src_lang: N.src_lang;
  abi: N.abi_t;
}

and fundec = {
  position: Newspeak.location;
  ftyp: N.ftyp;
  body: blk;
}

and assertion = spec_token list

and spec_token =
  | SymbolToken of char
  | IdentToken of string
  | LvalToken of (lval * N.typ)
  | CstToken of N.cst

and stmtkind =
    Set of (lval * exp * N.scalar_t)
  | Copy of (lval * lval * N.size_t)
  | Guard of exp
  | Decl of (string * N.typ * blk)
  | Select of (blk * blk)
  | InfLoop of blk
  | DoWith of (blk * N.lbl)
  | Goto of N.lbl
  | Call of funexp
  | UserSpec of assertion

and stmt = stmtkind * N.location

and blk = stmt list

and funexp =
    FunId of N.fid
  | FunDeref of (exp * N.ftyp)

and lval =
    Local of N.vid
  | Global of string
  | Deref of (exp * N.size_t)
  | Shift of (lval * exp)

and exp =
    Const of N.cst
  | Lval of (lval * N.scalar_t)
  | AddrOf of lval
  | AddrOfFun of (N.fid * N.ftyp)
  | UnOp of (N.unop * exp)
  | BinOp of (N.binop * exp * exp)


  
let exp_of_int x = Const (N.CInt (N.Nat.of_int x))

(***************************************************)

module StringMap = 
  Map.Make (struct type t = string let compare = Stdlib.compare end)

let rec seq sep f l =
  match l with
    | [] -> ""
    | [e] -> f e
    | e::r -> (f e)^sep^(seq sep f r)


(* Types *)

let string_of_size_t = string_of_int

let string_of_sign_t sg =
  match sg with
      N.Unsigned -> "u"
    | N.Signed -> ""

let string_of_scalar s =
  match s with
      N.Int (sg, sz) -> (string_of_sign_t sg)^"int"^(string_of_size_t sz)
    | N.Float sz -> "float" ^ (string_of_size_t sz)
    | N.Ptr -> "ptr"
    | N.FunPtr -> "fptr"

let rec string_of_typ t =
  match t with
      N.Scalar s -> string_of_scalar s
    | N.Array (t, sz) -> (string_of_typ t)^"["^(string_of_size_t sz)^"]"
    | N.Region (lst, sz) ->
        let res = ref "{ " in
        let string_of_elt (off, t) = 
          res := !res^(string_of_typ t)^" "^(string_of_size_t off)^"; "
        in
          List.iter string_of_elt lst;
          !res^"}"^(string_of_size_t sz)

let string_of_args_t args =
  match args with
      hd::[] -> string_of_typ hd
    | hd::tl -> 
        let res = ref (string_of_typ hd) in
          List.iter (fun x -> res := !res^", "^(string_of_typ x)) tl;
          !res
    | [] -> "void"

let string_of_ret_t ret = string_of_args_t ret

let string_of_loc (fname, line, carac) = 
  if (fname = "") 
  then Npkcontext.report_error "Newspeak.string_of_loc" "unknown location";
  if (line < 0) || (carac < 0) then fname
  else (fname^":"^(string_of_int line)^"#"^(string_of_int carac))

(* Expressions *)
let string_of_cst c =
  match c with
      N.CInt c -> N.Nat.to_string c
    | N.CFloat (_, s) -> s
    | N.Nil -> "nil"
        
let string_of_bounds (l, u) = "["^(N.Nat.to_string l)^","^(N.Nat.to_string u)^"]"

let string_of_unop op =
  match op with
      N.Belongs r -> "belongs"^(string_of_bounds r)
    | N.Coerce r -> "coerce"^(string_of_bounds r)
    | N.Focus sz -> "focus"^(string_of_size_t sz)
    | N.Cast (typ, typ') ->
        "("^(string_of_scalar typ')^" <= "^(string_of_scalar typ)^")"
    | N.Not -> "!"
    | N.BNot _ -> "~"
    | N.PtrToInt i -> "("^(string_of_scalar (N.Int i))^")"
    | N.IntToPtr _ -> "(ptr)"
          
let string_of_binop op =
  match op with
    | N.Gt _ -> ">"
    | N.Eq t -> "==_"^(string_of_scalar t)
    | N.PlusI -> "+"
    | N.MinusI -> "-"
    | N.MultI -> "*"
    | N.Mod -> "%"
    | N.DivI -> "/"
    | N.PlusF _ -> "+."
    | N.MinusF _ -> "-."
    | N.MultF _ -> "*."
    | N.DivF _ -> "/."
    | N.BAnd _ -> "&"
    | N.BOr _ -> "|"
    | N.BXor _ -> "^"
    | N.Shiftlt -> "<<"
    | N.Shiftrt -> ">>"
    | N.PlusPI -> "+"
    | N.MinusPP -> "-"

let rec string_of_lval lv =
  match lv with
      Local vid -> (string_of_int vid) ^ "-"
    | Global name -> name
    | Deref (e, sz) -> "["^(string_of_exp e)^"]"^(string_of_size_t sz)
    | Shift (lv, sh) -> (string_of_lval lv)^" + "^(string_of_exp sh)

and string_of_exp e =
  match e with
      Const c -> string_of_cst c
    | Lval (lv, t) -> (string_of_lval lv)^"_"^(string_of_scalar t)
    | AddrOf lv -> "&("^(string_of_lval lv)^")"
    | AddrOfFun (fid, ft) -> "&_{"^(N.string_of_ftyp ft)^"}("^fid^")"
    | BinOp (op, e1, e2) ->
        "("^(string_of_exp e1)^" "^(string_of_binop op)^
          " "^(string_of_exp e2)^")"

    | UnOp (op, exp) -> (string_of_unop op)^" "^(string_of_exp exp)

          
let string_of_funexp f =
  match f with
      FunId fid -> fid^"()"
    | FunDeref (exp, (args_t, [ret_t])) ->
        "["^(string_of_exp exp)^"]("^
          (seq ", " string_of_typ args_t)^") -> "^(string_of_typ ret_t)
    | FunDeref (exp, (args_t, _)) ->
        "["^(string_of_exp exp)^"]("^(seq ", " string_of_typ args_t)^")"


(* Actual dump *)
let string_of_lbl l = "lbl"^(string_of_int l)


let dump_gdecl name t = print_endline (string_of_typ t^" "^name^";")

let string_of_token x =
  match x with
      SymbolToken x -> String.make 1 x
    | IdentToken x -> x
    | LvalToken (x, _) -> "'"^(string_of_lval x)^"'"
    | CstToken c -> string_of_cst c

let string_of_assertion x =
  let res = ref "" in
  let append_token x = res := !res^(string_of_token x)^" " in
    List.iter append_token x;
    !res

let string_of_blk offset x =
  let buf = Buffer.create 80 in
  let offset = ref offset in
  let incr_margin () = offset := !offset + 2 in
  let decr_margin () = offset := !offset - 2 in
  let dump_line str = 
    let margin = String.make !offset ' ' in
      Buffer.add_string buf (margin^str^"\n") 
  in
  let dump_line_at loc str =
    let loc = if loc = N.unknown_loc then "" else "("^(string_of_loc loc)^")^" in
    let margin = String.make !offset ' ' in
      Buffer.add_string buf (margin^loc^str^"\n") 
  in

  let rec dump_stmt only (sk, loc) =
    match sk with
        Set (lv, e, sc) -> 
          dump_line_at loc ((string_of_lval lv)^" =("^(string_of_scalar sc)^
                        ") "^(string_of_exp e)^";")
      | Guard b -> dump_line_at loc ("guard("^(string_of_exp b)^");")
      | Copy (lv1, lv2, sz) ->
          dump_line_at loc ((string_of_lval lv1)^" ="^(string_of_size_t sz)^
                        " "^(string_of_lval lv2)^";")
            
      | Decl (x, t, body) ->
          if only then begin
            dump_line_at loc ((string_of_typ t)^" "^x^";");
            dump_blk body
          end else begin
            dump_line_at loc "{";
            incr_margin ();
            dump_line ((string_of_typ t)^" "^x^";");
            dump_blk body;
            decr_margin ();
            dump_line "}"
          end
            
      | DoWith (body, lbl) ->
          dump_line_at loc "do {";
          incr_margin ();
          dump_blk body;
          decr_margin ();
          dump_line ("} with lbl"^(string_of_int lbl)^":")

      | Goto l -> dump_line_at loc ("goto "^(string_of_lbl l)^";")
          
      | Call f -> dump_line_at loc ((string_of_funexp f)^";")
          
      | Select (body1, body2) ->
          dump_line_at loc "choose {";
          dump_line " -->";
          incr_margin ();
          dump_blk body1;
          decr_margin ();
          dump_line " -->";
          incr_margin ();
          dump_blk body2;
          decr_margin ();
          dump_line "}"

      | InfLoop body -> 
          dump_line_at loc "while (1) {";
          incr_margin ();
          dump_blk body;
          decr_margin ();
          dump_line "}"

      | UserSpec x -> dump_line_at loc (string_of_assertion x)

  and dump_blk b =
    match b with
      | hd::[] -> dump_stmt true hd
      | hd::r ->
          dump_stmt false hd;
          List.iter (dump_stmt false) r
      | [] -> ()
  in
    
    dump_blk x;
    Buffer.contents buf
  
let dump_fundec name declaration =
  let (args_t, ret_t) = declaration.ftyp in
  let args_t = string_of_args_t args_t in
  let ret_t = string_of_ret_t ret_t in
    print_endline (ret_t^" "^name^"("^args_t^") {");
    print_string (string_of_blk 2 declaration.body);
    print_endline "}";
    print_newline ()


let dump_globals gdecls = 
  (* TODO: Clean this mess... StringMap *)
  let glbs = ref (StringMap.empty) in
    Hashtbl.iter 
      (fun name info -> glbs := (StringMap.add name info !glbs)) 
      gdecls;
    StringMap.iter dump_gdecl !glbs
      
(* Exported print functions *)
let dump prog =
  (* TODO: Clean this mess... StringMap *)
  let funs = ref (StringMap.empty) in
  let collect_funbody name body =
    funs := StringMap.add name body !funs
  in
  let init = string_of_blk 0 prog.init in
    Hashtbl.iter collect_funbody prog.fundecs;
    StringMap.iter dump_fundec !funs;
    dump_globals prog.globals;
    print_string init

let string_of_blk x = string_of_blk 0 x

let string_of_stmt x = string_of_blk (x::[])

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

let visit_nop =
  let f2true _ _ = true in
  let f1unit _ = () in
  let f1true _ = true in
  { loc        = Newspeak.unknown_loc
  ; gdecl      = f2true
  ; func       = f2true
  ; func_after = f1unit
  ; stmt       = f1true
  ; funexp     = f1true
  ; exp        = f2true
  ; bexp       = f1unit
  ; lval       = f1true
  ; unop       = f1unit
  ; binop      = f1unit
  ; size_t     = f1unit
  ; length     = f1unit
  ; typ        = f1unit
  }

class visitor =
object 
  val mutable cur_loc = N.unknown_loc
  method set_loc loc = cur_loc <- loc
  method get_loc = cur_loc

  method process_gdecl (_: string) (_: N.typ) = true
  method process_fun (_: N.fid) (_: fundec) = true
  method process_fun_after () = ()
  method process_stmt (_: stmt) = true
  method process_funexp (_: funexp) = true
  method process_exp (_: exp) = true
  method process_bexp (_: exp) = ()
  method process_lval (_: lval) = true
  method process_unop (_: N.unop) = ()
  method process_binop (_: N.binop) = ()
  method process_size_t (_: N.size_t) = ()
  method process_length (_: N.length) = ()
  method process_typ (_: N.typ) = ()

  method raise_error msg = 
    let (file, line, _) = cur_loc in
    let pos = 
      if cur_loc = N.unknown_loc then ""
      else " in "^file^" line "^(string_of_int line)
    in
      (StandardApplication.report_error (msg^pos) : unit)

  method print_warning msg = 
    let (file, line, _) = cur_loc in
    let pos = 
      if cur_loc = N.unknown_loc then ""
      else " in "^file^" line "^(string_of_int line)
    in
      print_endline ("Warning: "^msg^pos)
end

let visit_scalar_t visitor t =
  match t with
      N.Int k -> visitor.size_t (snd k)
    | N.Float sz -> visitor.size_t sz
    | N.Ptr -> ()
    | N.FunPtr -> ()

let visit_typ visitor t = 
  visitor.typ t;
  let rec visit_typ t =
    match t with
        N.Scalar t -> visit_scalar_t visitor t
      | N.Array (t, n) -> 
          visit_typ t;
          visitor.length n
      | N.Region (fields, sz) ->
          List.iter (fun (_, t) -> visit_typ t) fields;
          visitor.size_t sz
  in
    visit_typ t

let visit_ftyp visitor (args, ret) =
  List.iter (visit_typ visitor) args;
  List.iter (visit_typ visitor) ret

let rec visit_lval visitor x =
  let continue = visitor.lval x in
    match x with
        Deref (e, sz) when continue -> 
          visit_exp visitor e;
          visitor.size_t sz
      | Shift (lv, e) when continue ->
          visit_lval visitor lv;
          visit_exp visitor e
      | _ -> ()
  
and visit_exp visitor x =
  let continue = visitor.exp visitor.loc x in
    if continue then begin
      match x with
          Lval (lv, _) -> visit_lval visitor lv
        | AddrOf lv -> visit_lval visitor lv
        | UnOp (op, e) ->
            visitor.unop op;
            visit_exp visitor e
        | BinOp (bop, e1, e2) ->
            visitor.binop bop;
            visit_binop visitor bop;
            visit_exp visitor e1;
            visit_exp visitor e2
        | _ -> ()
    end

and visit_binop visitor op =
  match op with
    | N.PlusF  sz
    | N.MinusF sz
    | N.MultF  sz
    | N.DivF   sz -> visitor.size_t sz
    | _ -> ()

let visit_funexp visitor x =
  let continue = visitor.funexp x in
    match x with
        FunDeref (e, t) when continue -> 
          visit_exp visitor e;
          visit_ftyp visitor t
      | _ -> ()

let rec visit_blk visitor x = List.iter (visit_stmt visitor) x
    
and visit_stmt visitor (x, loc) =
  visitor.loc <- loc;
  let continue = visitor.stmt (x, loc) in
    if continue then begin
      match x with
          Set (lv, e, _) -> 
            visit_lval visitor lv;
            visit_exp visitor e
        | Copy (lv1, lv2, sz) ->
            visit_lval visitor lv1;
            visit_lval visitor lv2;
            visitor.size_t sz
        | Guard b -> 
            visitor.bexp b;
            visit_exp visitor b
        | Decl (_, t, body) -> 
            visit_typ visitor t;
            visit_blk visitor body
        | Call fn -> visit_funexp visitor fn
        | Select (body1, body2) -> 
            visitor.loc <- loc;
            visit_blk visitor body1;
            visitor.loc <- loc;
            visit_blk visitor body2
        | InfLoop x -> visit_blk visitor x
        | DoWith (body, _) -> visit_blk visitor body
        | Goto _ -> ()
        | UserSpec assertion -> List.iter (visit_token visitor) assertion
    end else ()

and visit_token builder x =
  match x with
      LvalToken (lv, t) -> 
        visit_lval builder lv;
        visit_typ builder t
    | _ -> ()

let visit_fun visitor fid declaration =
  let continue = visitor.func fid declaration in
  if continue then begin
    visit_ftyp visitor declaration.ftyp;
    visit_blk visitor declaration.body;
    visitor.func_after ()
  end

let visit_glb visitor id t =
  let continue = visitor.gdecl id t in
    if continue then visit_typ visitor t

let visit visitor prog =
  Hashtbl.iter (visit_glb visitor) prog.globals;
  visit_blk visitor prog.init;
  Hashtbl.iter (visit_fun visitor) prog.fundecs

let collect_fid_addrof prog =
  let fid_list = ref [] in
  let fid_addrof_visitor =
    { visit_nop with exp = fun _ -> function
        | AddrOfFun (id, _) when not (List.mem id !fid_list) ->
            fid_list := id::!fid_list; true
        | _ -> true
    } in
  visit fid_addrof_visitor prog;
  !fid_list

let rec negate exp =
  match exp with
    | UnOp (N.Not, BinOp (N.Eq t, e2, e1)) -> BinOp (N.Eq t, e1, e2)
    | UnOp (N.Not, e) -> e
    | BinOp (N.Gt t, e1, e2) -> UnOp (N.Not, BinOp (N.Gt t, e1, e2))
    | BinOp (N.Eq t, e1, e2) -> UnOp (N.Not, BinOp (N.Eq t, e1, e2))
    | UnOp (N.Coerce i, e) -> UnOp (N.Coerce i, negate e)
    | _ -> StandardApplication.report_error "Newspeak.negate"

let zero = Const (N.CInt N.Nat.zero)
let one  = Const (N.CInt N.Nat.one)

class builder =
object
  val mutable curloc = N.unknown_loc
  method set_curloc loc = curloc <- loc
  method curloc = curloc
  method process_global (_: string) (x: N.typ) = x
  method process_lval (x: lval) = x
  method process_exp (x: exp) = x
  method process_blk (x: blk) = x
  method enter_stmtkind (_: stmtkind) = ()
  method process_stmtkind (x: stmtkind) = x
  method process_size_t (x: N.size_t) = x
  method process_offset (x: N.offset) = x
end


class simplify_coerce =
object 
  inherit builder

(* TODO: put these theorems in Newspeak semantics paper *)
  method process_exp e =
    match e with
        (* Coerce [a;b] Coerce [c;d] e 
           -> Coerce [c;d] if [a;b] contains [c;d] *)
      | UnOp (N.Coerce r1, UnOp (N.Coerce r2, e)) when N.contains r1 r2 -> 
          UnOp (N.Coerce r2, e)
          
      (* Coerce [a;b] Coerce [c;d] e -> Coerce [a;b] if [c;d] contains [a;b] *)
      | UnOp (N.Coerce r1, UnOp (N.Coerce r2, e)) when N.contains r2 r1 -> 
          UnOp (N.Coerce r1, e)

      (* Coerce/Belongs [a;b] Const c -> Const c if c in [a;b] *)
      | UnOp ((N.Coerce r | N.Belongs r), Const (N.CInt c))
          when N.belongs c r -> Const (N.CInt c)

      (* Coerce/Belongs [a;b] Lval (lv, t) -> Lval (lv, t)
         if [a; b] contains dom(t) *)
      | UnOp ((N.Coerce r | N.Belongs r), (Lval (_, N.Int k) as lv))
          when N.contains r (N.domain_of_typ k) -> lv

(* TODO: could do this after a sanity checks that checks the largest and 
   smallest integer ever computed in expressions!! *)
      | UnOp (N.Coerce r, 
             (BinOp (N.MultI, UnOp (N.Belongs (l, u), _), Const N.CInt x) as e')) -> 
          let l = N.Nat.mul l x in
          let u = N.Nat.mul u x in
            if N.contains r (l, u) then e' else e

      | _ -> e
end

class simplify_choose =
object
  inherit builder

  method process_blk x =
    match x with
(* This rule is incorrect when body is blocking !!!
        (Select (body, []), _)::tl | (Select ([], body), _)::tl -> 
          (self#process_blk body)@tl*)
      |  (Select (body, (Guard Const N.CInt i, _)::_), _)::tl
          when N.Nat.compare i N.Nat.zero = 0 -> body@tl
      | (Select ((Guard Const N.CInt i, _)::_, body), _)::tl
          when N.Nat.compare i N.Nat.zero = 0 -> body@tl
      | (Guard Const N.CInt i, _)::tl when N.Nat.compare i N.Nat.one = 0 -> tl
      | _ -> x
end

let rec addr_of_deref lv = 
  match lv with
      Deref (e, _) -> e
    | Shift (lv, i) -> BinOp (N.PlusPI, addr_of_deref lv, i)
    | _ -> raise Not_found

class simplify_ptr =
object
  inherit builder

  method process_lval lv =
    match lv with
        Deref (UnOp (N.Focus n, AddrOf lv), n') when n' <= n -> lv
      | _ -> lv

  method process_exp e = 
    match e with
        AddrOf lv -> begin
          try addr_of_deref lv
          with Not_found -> e
        end
      | _ -> e

end

class simplify_arith =
object (self)
  inherit builder
    
  method process_lval x =
    match x with
        Shift (lv, Const N.CInt c) when N.Nat.compare c N.Nat.zero = 0 -> lv
      | Shift (Shift (lv, Const N.CInt c1), Const N.CInt c2) ->
          let c = N.Nat.add c1 c2 in
          let lv = Shift (lv, Const (N.CInt c)) in
            self#process_lval lv
      | _ -> x

  (* TODO: generatlization of all this: do the operations with bignums
     and then come back to Int64 *)
  (* TODO: should use string to representer constants, not Int64, since 
     not all unsigned long long can be represented *)
  method process_exp e =
    match e with
        BinOp (N.MultI|N.PlusI|N.MinusI as op, Const N.CInt x, Const N.CInt y) ->
          let nat_op = function
              | N.PlusI  -> N.Nat.add
              | N.MinusI -> N.Nat.sub
              | N.MultI  -> N.Nat.mul
              | _ -> 
		  Npkcontext.report_error "Newspeak.big_int_op" 
		    "unexpected operator"
          in
          let z = nat_op op x y in
            Const (N.CInt z)

      | BinOp (N.PlusPI, e, Const N.CInt x) when (N.Nat.compare x N.Nat.zero = 0) -> e

      | BinOp (N.PlusPI, BinOp (N.PlusPI, e, Const N.CInt y), Const N.CInt x) 
          when (N.Nat.compare x N.Nat.zero >= 0) 
            && (N.Nat.compare y N.Nat.zero >= 0) -> 
          BinOp (N.PlusPI, e, Const (N.CInt (N.Nat.add x y)))

      | BinOp (N.DivI, Const N.CInt i1, Const N.CInt i2) 
          when N.Nat.compare i2 N.Nat.zero <> 0 ->
          Const (N.CInt (N.Nat.div i1 i2))

      | UnOp (N.Not, Const N.CInt i) when N.Nat.compare i N.Nat.zero = 0 -> 
          exp_of_int 1
      | UnOp (N.Not, Const N.CInt i) when N.Nat.compare i N.Nat.zero <> 0 -> 
          exp_of_int 0
      | _ -> e
end

module Lbl = 
struct
  type t = N.lbl
  let compare = compare
end

module LblSet = Set.Make(Lbl)

let simplify_gotos blk =
  let current_lbl = ref (-1) in
  let stack = ref [] in
  let used_lbls = ref LblSet.empty in
  let new_lbl () = incr current_lbl; !current_lbl in
  let find lbl = 
    let lbl' = List.assoc lbl !stack in
      used_lbls := LblSet.add lbl' !used_lbls;
      lbl'
  in
  let push lbl1 lbl2 = stack := (lbl1, lbl2)::(!stack) in
  let pop () = 
    match !stack with
        (_, lbl)::tl -> 
          used_lbls := LblSet.remove lbl !used_lbls;
          stack := tl
      | [] -> 
	  Npkcontext.report_error "Newspeak.simplify_gotos" 
	    "unexpected empty stack"
  in

  let rec simplify_blk x =
    match x with
        hd::tl -> 
          let hd = simplify_stmt hd in
          let tl = simplify_blk tl in
            hd@tl
      | [] -> []
    
  and simplify_stmt (x, loc) =
    match x with
        DoWith (body, lbl) -> 
          let lbl' = new_lbl () in
            push lbl lbl';
            simplify_dowith_goto loc (body, lbl')

      | _ -> (simplify_stmtkind x, loc)::[]

  and simplify_stmtkind x =
    match x with
      | Goto lbl -> Goto (find lbl)
      | Decl (name, t, body) -> 
          let body = simplify_blk body in
            Decl (name, t, body)

      | Select (body1, body2) -> Select (simplify_blk body1, simplify_blk body2)

      | InfLoop body -> 
          let body = simplify_blk body in
            InfLoop body

      | _ -> x

  and remove_final_goto lbl blk =
    let rec remove blk =
      match blk with
          (Goto lbl', _)::[] when List.assoc lbl' !stack = lbl -> []
        | hd::tl -> hd::(remove tl)
        | [] -> []
    in
      try remove blk
      with Not_found -> blk

  and simplify_dowith loc (body, lbl) =
    match body with
        (DoWith (body, lbl'), _)::[] ->
          push lbl' lbl;
          let x = simplify_dowith_goto loc (body, lbl) in
            pop ();
            x
      | hd::tl -> 
          let hd = simplify_stmt hd in
            if LblSet.mem lbl !used_lbls then begin
              let tl = simplify_blk tl in
              let body = hd@tl in
                pop ();
                (DoWith (body, lbl), loc)::[] 
            end else hd@(simplify_dowith loc (tl, lbl))
      | [] -> 
          pop ();
          []
            
  and simplify_dowith_goto loc (body, lbl) =
    simplify_dowith loc (remove_final_goto lbl body, lbl)
  in
    
  let blk = simplify_blk blk in
    if not (LblSet.is_empty !used_lbls) 
    then begin
      Npkcontext.report_error "Newspeak.simplify_gotos" 
	"unexpected goto without label"
    end;
    blk

let rec simplify_stmt actions (x, loc) =
  List.iter (fun a -> a#enter_stmtkind x) actions;
  let x =
    match x with
      | Set (lv, e, sca) -> 
          Set (simplify_lval actions lv, simplify_exp actions e, sca)
      | Copy (lv1, lv2, sz) ->
          let lv1 = simplify_lval actions lv1 in
          let lv2 = simplify_lval actions lv2 in
            Copy (lv1, lv2, sz)
      | Guard b -> Guard (simplify_exp actions b)
      | Call (FunDeref (e, t)) -> Call (FunDeref (simplify_exp actions e, t))
      | Decl (name, t, body) -> Decl (name, t, simplify_blk actions body)
      | Select (body1, body2) -> 
          Select (simplify_blk actions body1, simplify_blk actions body2)
      | InfLoop body ->
          let body = simplify_blk actions body in
            InfLoop body
      | DoWith (body, l) -> DoWith (simplify_blk actions body, l)
      | _ -> x
  in
  let stmt = ref x in
    List.iter (fun x -> stmt := x#process_stmtkind !stmt) actions;
    (!stmt, loc)
      
and simplify_exp actions e =
  let e = 
    match e with
        Lval (lv, sca) -> Lval (simplify_lval actions lv, sca)
      | AddrOf lv -> AddrOf (simplify_lval actions lv)
      | UnOp (o, e) -> UnOp (o, simplify_exp actions e)
      | BinOp (o, e1, e2) -> 
          BinOp (o, simplify_exp actions e1, simplify_exp actions e2)
      | _ -> e
  in
  let e = ref e in
    List.iter (fun x -> e := x#process_exp !e) actions;
    !e

and simplify_lval actions lv =
  let lv =
    match lv with
      | Deref (e, sz) -> Deref (simplify_exp actions e, sz)
      | Shift (l, e) -> Shift (simplify_lval actions l, simplify_exp actions e)
      | _ -> lv
  in
  let lv = ref lv in
    List.iter (fun x -> lv := x#process_lval !lv) actions;
    !lv
        
and simplify_blk actions blk = 
  match blk with
      hd::tl -> 
        let hd = simplify_stmt actions hd in
        let tl = simplify_blk actions tl in
        let blk = ref (hd::tl) in
          List.iter (fun x -> blk := x#process_blk !blk) actions;
          !blk
    | [] -> []

let simplify_blk opt_checks b = 
  let simplifications = if opt_checks then (new simplify_coerce)::[] else [] in
  let simplifications = 
    (new simplify_choose)::(new simplify_ptr)
    ::(new simplify_arith)::simplifications
  in
    simplify_gotos (simplify_blk simplifications b)


let simplify opt_checks prog =
  let fundecs = Hashtbl.create 100 in
  let globals = Hashtbl.create 100 in
  let simplify_global x info = Hashtbl.add globals x info in
  let simplify_fundec f declaration =
    let body = simplify_blk opt_checks declaration.body in
    let declaration = { declaration with body = body } in
      Hashtbl.add fundecs f declaration
  in
  let init = simplify_blk opt_checks prog.init in
    Hashtbl.iter simplify_global prog.globals;
    Hashtbl.iter simplify_fundec prog.fundecs;
    { prog with globals = globals; init = init; fundecs = fundecs }



let rec belongs_of_exp x =
  match x with
      Lval (lv, _) | AddrOf lv -> belongs_of_lval lv
    | UnOp (N.Belongs b, e)    -> (b, e)::(belongs_of_exp e)
    | UnOp (_, e)              -> belongs_of_exp e 
    | BinOp (_, e1, e2)        -> (belongs_of_exp e1)@(belongs_of_exp e2)
    | _                        -> []

and belongs_of_lval x =
  match x with
      Deref (e, _)  -> belongs_of_exp e
    | Shift (lv, e) -> (belongs_of_lval lv)@(belongs_of_exp e)
    | _             -> []

let belongs_of_funexp x =
  match x with
      FunDeref (e, _) -> belongs_of_exp e
    | _               -> []

let rec build builder prog = 
  let globals' = Hashtbl.create 100 in
  let fundecs' = Hashtbl.create 100 in
  let build_global x gdecl = 
    let gdecl = build_gdecl builder gdecl      in
    let gdecl = builder#process_global x gdecl in
      Hashtbl.add globals' x gdecl
  in
  let build_fundec f fundec =
    builder#set_curloc N.unknown_loc;
    let fundec = build_fundec builder fundec in
      Hashtbl.add fundecs' f fundec
  in
    Hashtbl.iter build_global prog.globals;
    Hashtbl.iter build_fundec prog.fundecs;
    { prog with globals = globals'; fundecs = fundecs' }

and build_gdecl builder t =
  build_typ builder t

and build_fundec builder declaration = 
  let ftyp = build_ftyp builder declaration.ftyp in
  let body = build_blk builder declaration.body in
    { declaration with ftyp = ftyp; body = body }

and build_typ builder t =
  match t with
      N.Scalar t            -> N.Scalar (build_scalar_t builder t)
    | N.Array (t, n)        ->
        let t = build_typ builder t in
          N.Array (t, n)
    | N.Region (fields, sz) ->
        let fields = List.map (build_field builder) fields in
        let sz = build_size_t builder sz                   in
          N.Region (fields, sz)

and build_scalar_t builder t =
  match t with
      N.Int k    ->
        let k = build_ikind builder k in
          N.Int k
    | N.Float sz ->
        let sz = build_size_t builder sz in
          N.Float sz
    | N.Ptr      -> t
    | N.FunPtr   -> t

and build_field builder (o, t) =
  let o = build_offset builder o in
  let t = build_typ builder t    in
    (o, t)

and build_ikind builder (sign, sz) =
  let sz = build_size_t builder sz in
    (sign, sz)

and build_ftyp builder (args, ret) =
  let args = List.map (build_typ builder) args in
  let ret = List.map (build_typ builder) ret in
    (args, ret)

and build_offset builder o = builder#process_offset o

and build_size_t builder sz = builder#process_size_t sz

and build_blk builder blk = 
  let blk =
    match blk with
        hd::tl -> 
          let hd = build_stmt builder hd in
          let tl = build_blk builder tl  in
            hd::tl
      | []     -> []
  in
    builder#process_blk blk

and build_stmt builder (x, loc) =
  builder#set_curloc loc;
  let x = build_stmtkind builder x in
    (x, loc)

and build_stmtkind builder x =
  builder#enter_stmtkind x; 
  let x = 
    match x with
        Set (lv, e, t)       ->
          let lv = build_lval builder lv   in
          let e = build_exp builder e      in
          let t = build_scalar_t builder t in
            Set (lv, e, t)
              
      | Copy (lv1, lv2, n)   ->
          let lv1 = build_lval builder lv1 in
          let lv2 = build_lval builder lv2 in
          let n = build_size_t builder n   in
            Copy (lv1, lv2, n)
              
      | Guard b               -> 
	  Guard (build_exp builder b)

      | Decl (x, t, body)     ->
          let t = build_typ builder t       in
          let body = build_blk builder body in
            Decl (x, t, body)
              
      | Select (body1, body2) -> 
          Select (build_blk builder body1, build_blk builder body2)
              
      | InfLoop body ->
          let body = build_blk builder body in
            InfLoop body
              
      | DoWith (body, lbl) -> DoWith (build_blk builder body, lbl)
              
      | Goto lbl -> Goto lbl
          
      | Call fn -> 
          let fn = build_funexp builder fn in
            Call fn

      | UserSpec assertion -> 
          let assertion = List.map (build_token builder) assertion in
            UserSpec assertion
  in
    builder#process_stmtkind x

and build_token builder x =
  match x with
      LvalToken (lv, t) -> LvalToken ((build_lval builder lv), t)
    | _ -> x

and build_funexp builder fn =
  match fn with
      FunId f -> FunId f
    | FunDeref (e, ft) ->
        let e = build_exp builder e in
        let ft = build_ftyp builder ft in
          FunDeref (e, ft)

and build_lval builder lv =
  let lv =
    match lv with
        Local x -> Local x
      | Global str -> Global str
      | Deref (e, sz) -> 
          let e = build_exp builder e in
          let sz = build_size_t builder sz in
            Deref (e, sz)
      | Shift (lv, e) ->
          let lv = build_lval builder lv in
          let e = build_exp builder e in
            Shift (lv, e)
  in
    builder#process_lval lv

and build_exp builder e =
  let e =
    match e with
        Const c -> Const c
      | Lval (lv, t) ->
          let lv = build_lval builder lv in
          let t = build_scalar_t builder t in
            Lval (lv, t)
      | AddrOf lv -> 
          let lv = build_lval builder lv in
            AddrOf lv
      | AddrOfFun f -> AddrOfFun f
      | UnOp (op, e) ->
          let op = build_unop builder op in
          let e = build_exp builder e in
            UnOp (op, e)
      | BinOp (op, e1, e2) ->
          let op = build_binop builder op in
          let e1 = build_exp builder e1 in
          let e2 = build_exp builder e2 in
            BinOp (op, e1, e2)
  in
    builder#process_exp e

and build_unop builder op =
  match op with
      N.PtrToInt k ->
        let k = build_ikind builder k in
          N.PtrToInt k
    | N.IntToPtr k ->
        let k = build_ikind builder k in
          N.IntToPtr k
    | N.Cast (t1, t2) ->
        let t1 = build_scalar_t builder t1 in
        let t2 = build_scalar_t builder t2 in
          N.Cast (t1, t2)
    | N.Focus sz -> N.Focus (build_size_t builder sz)
    | N.Belongs _ | N.Coerce _ | N.Not | N.BNot _-> op

and build_binop builder op =
  match op with
      N.PlusF  sz -> N.PlusF (build_size_t builder sz)
    | N.MinusF sz -> N.MinusF (build_size_t builder sz)
    | N.MultF  sz -> N.MultF (build_size_t builder sz)
    | N.DivF   sz -> N.DivF (build_size_t builder sz)
    | N.MinusPP -> N.MinusPP
    | N.Gt t -> N.Gt (build_scalar_t builder t)
    | N.Eq t -> N.Eq (build_scalar_t builder t)
    | N.PlusI | N.MinusI | N.MultI | N.DivI | N.Mod
    | N.BOr _ | N.BAnd _ | N.BXor _ | N.Shiftlt | N.Shiftrt | N.PlusPI -> op
