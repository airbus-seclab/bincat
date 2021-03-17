(*
  C2Newspeak: compiles C code into Newspeak. Newspeak is a minimal language 
  well-suited for static analysis.
  Copyright (C) 2007-2021  Charles Hymans, Sarah Zennou
  
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
 email: charles.hymans@penjili.org

  Sarah Zennou
  EADS Innovation Works - SE/IT
  12, rue Pasteur - BP 76 - 92152 Suresnes Cedex - France
  email: sarah(dot)zennou(at)eads(dot)net
*)

module Nat =
struct
  type t = string
      
  let zero = "0"
  let one = "1"
  let of_z = Z.to_string
  let to_z = Z.of_string
  let of_int x = string_of_int x
  let to_int x = 
    let i = to_z x in
    if not (Big_int_Z.is_int_big_int i) 
    then invalid_arg "Newspeak.Nat.to_int";
    Big_int_Z.int_of_big_int i

  let apply_big_int_op op x y =
    let x = Big_int_Z.big_int_of_string x in
    let y = Big_int_Z.big_int_of_string y in
    let z = op x y in
      Big_int_Z.string_of_big_int z

  let add = apply_big_int_op Big_int_Z.add_big_int

  let sub = apply_big_int_op Big_int_Z.sub_big_int

  let mul = apply_big_int_op Big_int_Z.mult_big_int

  let div = apply_big_int_op Big_int_Z.div_big_int

  let neg x = 
    let x = Big_int_Z.big_int_of_string x in
    let y = Big_int_Z.minus_big_int x in
      Big_int_Z.string_of_big_int y

  let add_int i x = 
    let x = Big_int_Z.big_int_of_string x in
    let y = Big_int_Z.add_int_big_int i x in
      Big_int_Z.string_of_big_int y

  let mul_int i x = 
    let x = Big_int_Z.big_int_of_string x in
    let y = Big_int_Z.mult_int_big_int i x in
      Big_int_Z.string_of_big_int y

  let shift_left x n =
    let x = Big_int_Z.big_int_of_string x in
    let y = Big_int_Z.power_int_positive_int 2 n in
    let z = Big_int_Z.mult_big_int x y in
      Big_int_Z.string_of_big_int z

  let compare x y = 
    let x = Big_int_Z.big_int_of_string x in
    let y = Big_int_Z.big_int_of_string y in
      Big_int_Z.compare_big_int x y

  let to_string x = x
  let of_string x = x
end

(* The type of a program: file names, global variable declarations,
    function definitions and the size of pointers. *)

type t = {
  globals: globals;
  init: blk;
  fundecs: (fid, fundec) Hashtbl.t; (** table of all declared functions *)
  ptr_sz: size_t;                   (** size of pointers in number of bits *)
  src_lang: src_lang;
  abi: abi_t;
}

and fundec = {
  args : (string * typ) list;
  rets : (string * typ) list;
  body : blk;
  position: location;         (** position of the start of the function *)
}

and globals = (string, typ) Hashtbl.t

and src_lang = C | ADA

and stmtkind =
    Set	     of (lval * exp * scalar_t)
  | Copy     of (lval * lval * size_t)
  | Guard    of exp
  | Decl     of (string * typ * blk)
  | Select   of (blk * blk)
  | InfLoop  of blk
  | DoWith   of (blk * lbl)
  | Goto     of lbl
(* arguments, type, function, return values *)
  | Call     of ((exp * typ) list * funexp * (lval * typ) list )
  | UserSpec of assertion

and specs = assertion list

and assertion = spec_token list

and spec_token =
  | SymbolToken of char
  | IdentToken  of string
  | LvalToken   of (lval * typ)
  | CstToken    of cst

and stmt = stmtkind * location

and blk = stmt list

and lval =
    Local  of string
  | Global of string
  | Deref  of (exp * size_t)
  | Shift  of (lval * exp)

and exp =
    Const     of cst
  | Lval      of (lval * typ)
  | AddrOf    of lval
  | AddrOfFun of (fid * ftyp)
  | UnOp      of (unop * exp)
  | BinOp     of (binop * exp * exp)

and cst = 
    CInt of Nat.t
  | CFloat of (float * string)
  | Nil

(* TODO: remove this type *)
and ftyp = typ list * typ list

and typ =
    Scalar of scalar_t
  | Array of (typ * length)
  | Region of (field list * size_t)

and scalar_t =
    Int of ikind
  | Float of size_t
  | Ptr
  | FunPtr

and field = offset * typ

and funexp =
    FunId of fid
  | FunDeref of exp

and unop =
    Belongs of bounds
  | Coerce of bounds
  | Focus of size_t
  | Not
  | BNot of bounds
  | PtrToInt of ikind
  | IntToPtr of ikind
  | Cast of (scalar_t * scalar_t) (** source type => dest type *)

and binop =
(* Integer operations *)
  | PlusI | MinusI | MultI | DivI | Mod
(* floating point operations *)
  | PlusF of size_t | MinusF of size_t | MultF of size_t | DivF of size_t
(* bitwise operations *)
  | BOr of bounds | BAnd of bounds | BXor of bounds
  | Shiftlt | Shiftrt
(* pointer operations *)
  | PlusPI | MinusPP
(* comparisons *)
  | Gt of scalar_t | Eq of scalar_t

and lbl = int
and vid = int
and fid = string
and file = string

and ikind = sign_t * size_t
and sign_t = Signed | Unsigned
and size_t = int
and offset = int
and length = int
and bounds = (Nat.t * Nat.t)

and location = string * int * int

and abi_t = {
  endianness: endianness;
  arithmetic_in_structs_allowed: bool;
  unaligned_ptr_deref_allowed: bool;
  types: type_conf;
  max_sizeof: int; (* in bits *)
  max_array_length: int; (* in bytes *)
}

and endianness =
  | BigEndian
  | LittleEndian

and type_conf = {
  char_signedness: sign_t;
  size_of_byte: int;

  sa_ptr:        size_align;

  sa_char:       size_align;
  sa_short:      size_align;
  sa_int:        size_align;
  sa_long:       size_align;
  sa_longlong:   size_align;

  sa_float:      size_align;
  sa_double:     size_align;
  sa_longdouble: size_align;

  sa_void:       size_align; (* for arithmetic on void* *)
}

and size_align = {
  size: int;  (* in bits *)
  align: int; (* in bits *)
}

let belongs c (l, u) = (Nat.compare l c <= 0) && (Nat.compare c u <= 0)

let contains (l1, u1) (l2, u2) = 
  (Nat.compare l1 l2 <= 0) && (Nat.compare u2 u1 <= 0)

(*-----------*)
(* Constants *)
(*-----------*)

let zero = Const (CInt Nat.zero)
let one = Const (CInt Nat.one)
let zero_f = Const (CFloat (0., "0."))

(*----------------------------------*)
(* Manipulation and Simplifications *)
(*----------------------------------*)
        
let size_of_scalar ptr_sz t = 
  match t with
      Int (_, n) -> n
    | Float n -> n
    | Ptr -> ptr_sz
    | FunPtr -> ptr_sz

let size_of ptr_sz t =
  let rec size_of t =
    match t with
      | Scalar t -> size_of_scalar ptr_sz t
      | Array (t, n) -> (size_of t) * n
      | Region (_, n) -> n
  in
    size_of t

let domain_of_typ (sign, size) =
    match (sign, size) with
      (Unsigned, 8) 		-> (Nat.zero, Nat.of_string "255")
    | (Signed, 8) 		-> (Nat.of_string "-128", Nat.of_string "127")
    | (Unsigned, 16) 		-> (Nat.zero, Nat.of_string "65535")
    | (Signed, 16) 		-> (Nat.of_string "-32768", Nat.of_string "32767")
    | (Unsigned, 32) 		-> (Nat.zero, Nat.of_string "4294967295")
    | (Signed, 32) 		-> (Nat.of_string "-2147483648", Nat.of_string "2147483647")
    | (Signed, 64) 		-> 
        (Nat.of_string "-9223372036854775808", 
        Nat.of_string "9223372036854775807")
    | (Unsigned, 64) 		-> (Nat.zero, Nat.of_string "18446744073709551615")
(* For bitfields *)
    | (Signed, n) when n < 64 	->
        let x = Int64.shift_left Int64.one (n-1) in
        let l = Int64.to_string (Int64.neg x) in
        let u = Int64.to_string (Int64.pred x) in
          (Nat.of_string l, Nat.of_string u)
    | (Unsigned, n) when n < 64 ->
        let x = Int64.pred (Int64.shift_left Int64.one n) in
          (Nat.zero, Nat.of_string (Int64.to_string x))
    | _ 			-> invalid_arg "Newspeak.domain_of_typ"

let rec negate exp =
  match exp with
    | UnOp (Not, BinOp (Eq t, e2, e1)) -> BinOp (Eq t, e1, e2)
    | UnOp (Not, e) -> e
    | BinOp (Gt t, e1, e2) -> UnOp (Not, BinOp (Gt t, e1, e2))
    | BinOp (Eq t, e1, e2) -> UnOp (Not, BinOp (Eq t, e1, e2))
    | UnOp (Coerce i, e) -> UnOp (Coerce i, negate e)
    | _ -> invalid_arg "Newspeak.negate"

(*---------*)
(* Display *)
(*---------*)

module StringMap = Map.Make(String)

(* Types *)

let string_of_size_t = string_of_int

let string_of_sign_t sg =
  match sg with
      Unsigned -> "u"
    | Signed   -> ""

let string_of_scalar s =
  match s with
      Int (sg, sz) -> (string_of_sign_t sg)^"int"^(string_of_size_t sz)
    | Float sz 	   -> "float" ^ (string_of_size_t sz)
    | Ptr 	   -> "ptr"
    | FunPtr 	   -> "fptr"

let rec string_of_typ t =
  match t with
      Scalar s -> string_of_scalar s
    | Array (t, sz) -> (string_of_typ t)^"["^(string_of_size_t sz)^"]"
    | Region (lst, sz) ->
        let res = ref "{ " in
        let string_of_elt (off, t) = 
          res := !res^(string_of_typ t)^" "^(string_of_size_t off)^"; "
        in
          List.iter string_of_elt lst;
          !res^"}"^(string_of_size_t sz)

let string_of_list print l =
  "(" ^ (String.concat ", " (List.map print l)) ^ ")"

let string_of_formal_arg (arg_name, typ) =
  string_of_typ typ ^ " " ^ arg_name

let string_of_ret ret =
  match ret with
      [] -> "void"
    | l -> String.concat ", " (List.map (fun (_, t) -> string_of_typ t) l)

let string_of_formal_args args = 
  match args with
      [] -> "(void)"
    | l -> string_of_list string_of_formal_arg l
(* TODO: uniformize/cleanup outputs functions *)
let string_of_typ_list = function
  | []  -> "void"
  | args -> string_of_list string_of_typ args

let string_of_ret_list = function
  | []  -> "void"
  | args -> String.concat ", " (List.map string_of_typ args)

let string_of_ftyp (args, ret) = 
  string_of_typ_list args ^ " -> " ^ string_of_ret_list ret

let string_of_loc (fname, line, carac) = 
  if (fname = "") then invalid_arg "Newspeak.string_of_loc: unknown location";
  if (line < 0) || (carac < 0) then fname
  else (fname^":"^(string_of_int line)^"#"^(string_of_int carac))
  
let dummy_loc fname = 
  if fname = "" 
  then invalid_arg "Newspeak.dummy_loc: invalid function name for location";
  (fname, -1, -1)

let unknown_loc = ("", -1, -1)

(* Expressions *)
let string_of_cst c =
  match c with
      CInt c -> Nat.to_string c
    | CFloat (_, s) -> s
    | Nil -> "nil"
        
let string_of_bounds (l, u) = "["^(Nat.to_string l)^","^(Nat.to_string u)^"]"

let string_of_unop op =
  match op with
      Belongs r        -> "belongs"^(string_of_bounds r)
    | Coerce r 	       -> "coerce"^(string_of_bounds r)
    | Focus sz 	       -> "focus"^(string_of_size_t sz)
    | Cast (typ, typ') ->
        "("^(string_of_scalar typ')^" <= "^(string_of_scalar typ)^")"
    | Not 	       -> "!"
    | BNot _ 	       -> "~"
    | PtrToInt i       -> "("^(string_of_scalar (Int i))^")"
    | IntToPtr _       -> "(ptr)"
          
let string_of_binop op =
  match op with
    | Gt _     -> ">"
    | Eq t     -> "==_"^(string_of_scalar t)
    | PlusI    -> "+"
    | MinusI   -> "-"
    | MultI    -> "*"
    | Mod      -> "%"
    | DivI     -> "/"
    | PlusF _  -> "+."
    | MinusF _ -> "-."
    | MultF _  -> "*."
    | DivF _   -> "/."
    | BAnd _   -> "&"
    | BOr _    -> "|"
    | BXor _   -> "^"
    | Shiftlt  -> "<<"
    | Shiftrt  -> ">>"
    | PlusPI   -> "+"
    | MinusPP  -> "-"

let rec string_of_lval lv =
  match lv with
    | Local name     -> name
    | Global name    -> name
    | Deref (e, sz)  -> "["^(string_of_exp e)^"]"^(string_of_size_t sz)
    | Shift (lv, sh) -> (string_of_lval lv)^" + "^(string_of_exp sh)

and string_of_args args = string_of_list string_of_exp args

and string_of_exp e =
  match e with
      Const c 		  -> string_of_cst c
    | Lval (lv, t) 	  -> (string_of_lval lv)^"_"^(string_of_typ t)
    | AddrOf lv 	  -> "&("^(string_of_lval lv)^")"
    | AddrOfFun (fid, ft) -> "&_{"^(string_of_ftyp ft)^"}("^fid^")"
    | BinOp (op, e1, e2)  ->
        "("^(string_of_exp e1)^" "^(string_of_binop op)^
          " "^(string_of_exp e2)^")"

    | UnOp (op, exp) -> (string_of_unop op)^" "^(string_of_exp exp)

let string_of_funexp f =
  match f with
      FunId fid -> fid
    | FunDeref exp -> "["^(string_of_exp exp)^"]"

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

let string_of_loc_as_prefix loc = 
  if loc = unknown_loc then "" else "("^(string_of_loc loc)^")^"

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
    let loc = string_of_loc_as_prefix loc in
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
      | Call (args, fn, ret_vars) ->  
	  let string_of_args (x, t) = string_of_exp x^": "^string_of_typ t in
	  let string_of_rets (x, t) = string_of_lval x^": "^string_of_typ t in
	  let args = List.map string_of_args args in
	  let rets = List.map string_of_rets ret_vars in
          
	  let ret_str = 
	    match rets with
	      | [] -> ""
	      | r::[] -> r ^ " <- "
	      | _ -> (string_of_list (fun x -> x) rets) ^ " <- "
          in
	  let arg_str = string_of_list (fun x -> x) args in
          let result = 
	    ret_str ^ (string_of_funexp fn) ^ arg_str ^ ";" 
	  in
            dump_line_at loc result
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
  
let string_of_fundec name declaration =
  let str_args = string_of_formal_args declaration.args in
  let str_ret  = string_of_ret declaration.rets in
  let position = string_of_loc_as_prefix declaration.position in
  let result   = str_ret ^ " " ^ position ^ name ^ str_args ^ " {\n" in
  let result   = result^string_of_blk 2 declaration.body^"}\n" in
    result

let dump_fundec name declaration = 
  print_endline (string_of_fundec name declaration)

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

(* Input/output functions *)
let write name prog =
  let cout = open_out_bin name in
    Marshal.to_channel cout "NPK!" [];
    Marshal.to_channel cout Version.newspeak_hash [];
    Marshal.to_channel cout prog [];
    close_out cout

let read name = 
  try
    let cin = open_in_bin name in
    let str = Marshal.from_channel cin in
      if str <> "NPK!" 
      then invalid_arg ("Newspeak.read: "^name^" is not an .npk file");
      let version = Marshal.from_channel cin in
        if (version <> Version.newspeak_hash) then begin
          invalid_arg ("Newspeak.read: this file was generated with a "
                       ^"different version of c2newspeak. "
                       ^"Please regenerate your file or install the latest "
                       ^"version of newspeak."^
                       " Operation aborted.")
        end;
        Marshal.from_channel cin
  with Failure _error ->
    invalid_arg ("Newspeak.read: "^name^" could not be read")

class builder =
object
  val mutable curloc = unknown_loc
  method set_curloc loc = curloc <- loc
  method curloc = curloc
  method process_global (_: string) (x: typ) = x
  method process_lval (x: lval) = x
  method process_exp (x: exp) = x
  method process_blk (x: blk) = x
  method enter_stmtkind (_: stmtkind) = ()
  method process_stmtkind (x: stmtkind) = x
  method process_size_t (x: size_t) = x
  method process_offset (x: offset) = x
end


class simplify_coerce =
object 
  inherit builder

  method process_exp e =
    match e with
        (* Coerce [a;b] Coerce [c;d] e
           -> Coerce [c;d] if [a;b] contains [c;d] *)
      | UnOp (Coerce r1, UnOp (Coerce r2, e)) when contains r1 r2 -> 
          UnOp (Coerce r2, e)
          
      (* Coerce [a;b] Coerce [c;d] e -> Coerce [a;b] if [c;d] contains [a;b] *)
      | UnOp (Coerce r1, UnOp (Coerce r2, e)) when contains r2 r1 -> 
          UnOp (Coerce r1, e)

      (* Coerce/Belongs [a;b] Const c -> Const c if c in [a;b] *)
      | UnOp (Coerce r, Const (CInt c)) 
      | UnOp (Belongs r, Const (CInt c)) when belongs c r ->
          Const (CInt c)

      (* Coerce/Belongs [a;b] Lval (lv, t) -> Lval (lv, t)
         if [a; b] contains dom(t) *)
      | UnOp ((Coerce r | Belongs r), (Lval (_, Scalar (Int k)) as lv))
          when contains r (domain_of_typ k) -> lv

(* TODO: could do this after a sanity checks that checks the largest and 
   smallest integer ever computed in expressions!! *)
      | UnOp (Coerce r, 
             (BinOp (MultI, UnOp (Belongs (l, u), _), Const CInt x) as e')) -> 
          let l = Nat.mul l x in
          let u = Nat.mul u x in
            if contains r (l, u) then e' else e

      | _ -> e
end

let rec addr_of_deref lv = 
  match lv with
      Deref (e, _) -> e
    | Shift (lv, i) -> BinOp (PlusPI, addr_of_deref lv, i)
    | _ -> raise Not_found

class simplify_ptr =
object
  inherit builder

  method process_lval lv =
    match lv with
        Deref (UnOp (Focus n, AddrOf lv), n') when n' <= n -> lv
      | _ -> lv

  method process_exp e = 
    match e with
        AddrOf (lv) -> begin
          try addr_of_deref lv
          with Not_found -> e
        end
      | _ -> e

end

let nat_op op =
  match op with
      PlusI -> Nat.add
    | MinusI -> Nat.sub
    | MultI -> Nat.mul
    | _ -> invalid_arg "Newspeak.big_int_op: unexpected operator"

class simplify_arith =
object (self)
  inherit builder
    
  method process_lval x =
    match x with
        Shift (lv, Const CInt c) when Nat.compare c Nat.zero = 0 -> lv
      | Shift (Shift (lv, Const CInt c1), Const CInt c2) ->
          let c = Nat.add c1 c2 in
          let lv = Shift (lv, Const (CInt c)) in
            self#process_lval lv
      | _ -> x

  (* TODO: generatlization of all this: do the operations with bignums
     and then come back to Int64 *)
  (* TODO: should use string to representer constants, not Int64, since 
     not all unsigned long long can be represented *)
  method process_exp e =
    match e with
        BinOp (MultI|PlusI|MinusI as op, Const CInt x, Const CInt y) ->
          let z = (nat_op op) x y in
            Const (CInt z)

      | BinOp (PlusPI, e, Const CInt x) when (Nat.compare x Nat.zero = 0) -> e

      | BinOp (PlusPI, BinOp (PlusPI, e, Const CInt y), Const CInt x) 
          when (Nat.compare x Nat.zero >= 0) 
            && (Nat.compare y Nat.zero >= 0) -> 
          BinOp (PlusPI, e, Const (CInt (Nat.add x y)))

      | BinOp (DivI, Const CInt i1, Const CInt i2) 
          when Nat.compare i2 Nat.zero <> 0 ->
          Const (CInt (Nat.div i1 i2))

      | UnOp (Not, Const CInt i) when Nat.compare i Nat.zero = 0 -> 
          Const (CInt (Nat.of_int 1))
      | UnOp (Not, Const CInt i) when Nat.compare i Nat.zero <> 0 -> 
          Const (CInt (Nat.of_int 0))
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
      | (Select (body, (Guard Const CInt i, _)::_), _)::tl
          when Nat.compare i Nat.zero = 0 -> body@tl
      | (Select ((Guard Const CInt i, _)::_, body), _)::tl
          when Nat.compare i Nat.zero = 0 -> body@tl
      | (Guard Const CInt i, _)::tl when Nat.compare i Nat.one = 0 -> tl
      | _ -> x
end

module Lbl = 
struct
  type t = lbl
  let compare = compare
end

module LblSet = Set.Make(Lbl)
(* TODO: try to implement it with a builder
   or propose a different kind of builder? *)
let simplify_gotos blk =
  let current_lbl = ref (-1) in
  let stack = ref [] in
  let used_lbls = ref LblSet.empty in
  let new_lbl () = incr current_lbl; !current_lbl in
  let find lbl = 
    try
      let lbl' = List.assoc lbl !stack in
	used_lbls := LblSet.add lbl' !used_lbls;
	lbl'
    with Not_found -> lbl
  in
  let push lbl1 lbl2 = stack := (lbl1, lbl2)::(!stack) in
  let pop () = 
    match !stack with
        (_, lbl)::tl -> 
          used_lbls := LblSet.remove lbl !used_lbls;
          stack := tl
      | [] -> invalid_arg "Newspeak.simplify_gotos: unexpected empty stack"
  in

  let has_no_guard_with_goto blk =
    let rec last_is_goto blk =
      match blk with
	  [] -> false
	| [Goto _, _] -> true
	| [DoWith (body, _), _] -> last_is_goto body
	| _::tl -> last_is_goto tl
    in
    let rec has_no_guard blk =
      match blk with
	  []         -> true
	| (s, _)::tl ->
	    let b = 
	      match s with
		  Guard _           -> false
		| Select _          -> false
		| Decl (_, _, body) -> has_no_guard body
		| InfLoop blk       -> has_no_guard blk
		| DoWith (blk, _)   -> has_no_guard blk
		| _                 -> true
	    in
	      b && (has_no_guard tl)
    in
      if has_no_guard blk then last_is_goto blk
      else false
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
          (Goto lbl', _)::[] when List.assoc lbl' !stack = lbl           -> []
	| (InfLoop body, _)::[] when has_no_guard_with_goto body         -> remove body
        | hd::tl                                                         -> hd::(remove tl)
        | []                                                             -> []
    in
      try remove blk
      with Not_found -> blk

  and simplify_dowith loc (body, lbl) =
    match body with
        (DoWith (body, lbl'), _)::[] -> 
          push lbl' lbl;
	  let loc' =
	    match body with
		[] -> loc
	      | (_, loc')::_ -> loc'
	  in
          let x = simplify_dowith_goto loc' (body, lbl) in
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
    let body = remove_final_goto lbl body in
      simplify_dowith loc (body, lbl)
  in

  let blk = simplify_blk blk in
    if not (LblSet.is_empty !used_lbls) 
    then invalid_arg "Newspeak.simplify_gotos: unexpected goto without label";
    blk

let rec simplify_stmt actions (x, loc) =
  let simplify_funexp actions f =
    match f with
      | FunId s -> FunId s
      | FunDeref e -> FunDeref (simplify_exp actions e)
  in
  List.iter (fun a -> a#enter_stmtkind x) actions;
  let x =
    match x with
      | Set (lv, e, sca) 	 -> 
          Set (simplify_lval actions lv, simplify_exp actions e, sca)
      | Copy (lv1, lv2, sz) 	 ->
          let lv1 = simplify_lval actions lv1 in
          let lv2 = simplify_lval actions lv2 in
            Copy (lv1, lv2, sz)
      | Guard b 		 -> Guard (simplify_exp actions b)
      | Call (args, f, ret_vars) ->
          let f' = simplify_funexp actions f in
	  let args = 
	    List.map (fun (x, t) -> (simplify_exp actions x, t)) args 
	  in
	  let ret_vars = 
	    List.map (fun (x, t) -> (simplify_lval actions x, t)) ret_vars 
	  in
            Call (args, f', ret_vars)
      | Decl (name, t, body) 	 -> Decl (name, t, simplify_blk actions body)
      | Select (body1, body2) 	 -> 
          Select (simplify_blk actions body1, simplify_blk actions body2)
      | InfLoop body 		 ->
          let body = simplify_blk actions body in
            InfLoop body
      | DoWith (body, l) 	 -> 
          let body = simplify_blk actions body in
            DoWith (body, l)
      | _ 			 -> x
  in
  let stmt = ref x in
    List.iter (fun x -> stmt := x#process_stmtkind !stmt) actions;
    (!stmt, loc)
      
and simplify_exp actions e =
  let e = 
    match e with
        Lval (lv, sca) 	  -> Lval (simplify_lval actions lv, sca)
      | AddrOf lv 	  -> AddrOf (simplify_lval actions lv)
      | UnOp (o, e) 	  -> UnOp (o, simplify_exp actions e)
      | BinOp (o, e1, e2) -> 
          BinOp (o, simplify_exp actions e1, simplify_exp actions e2)
      | _ 		  -> e
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
        let hd 	= simplify_stmt actions hd in
        let tl 	= simplify_blk actions tl in
        let blk = ref (hd::tl) in
          List.iter (fun x -> blk := x#process_blk !blk) actions;
          !blk
    | [] -> []

let has_goto lbl x =
  let rec blk_has_goto x = List.exists has_goto x

  and has_goto (x, _) =
  match x with
      Decl (_, _, body) | InfLoop body | DoWith (body, _) -> blk_has_goto body
    | Select (body1, body2) 				  -> 
	(blk_has_goto body1) || (blk_has_goto body2)
    | Goto lbl' 	    				  -> lbl = lbl'
    | _ 		    				  -> false
  in
    has_goto x

let split_loop lbl body =
  let rec split x =
    match x with
        hd::tl when not (has_goto lbl hd) -> 
          let (prefix, suffix) = split tl in
            (hd::prefix, suffix)
      | _ -> ([], x)
  in
    split body

let rec normalize_loop blk =
  match blk with
      (DoWith ([InfLoop body, loc], lbl), loc')::tl ->
        let (prefix, suffix) = split_loop lbl body in
        let body 	     = prefix@[InfLoop (suffix@prefix), loc] in
          (DoWith (body, lbl), loc')::(normalize_loop tl)
    | hd::tl -> hd::(normalize_loop tl)
    | [] -> []

class simplify_loops =
object 
  inherit builder

  method process_blk x = normalize_loop x
end

let normalize_loops b = simplify_blk [new simplify_loops] b

let rec build builder prog = 
  let globals' = Hashtbl.create 100 in
  let fundecs' = Hashtbl.create 100 in
  let build_global x gdecl = 
    let gdecl = build_gdecl builder gdecl in
    let gdecl = builder#process_global x gdecl in
      Hashtbl.add globals' x gdecl
  in
  let build_fundec f fundec =
    builder#set_curloc unknown_loc;
    let fundec = build_fundec builder fundec in
      Hashtbl.add fundecs' f fundec
  in
    Hashtbl.iter build_global prog.globals;
    Hashtbl.iter build_fundec prog.fundecs;
    { prog with globals = globals'; fundecs = fundecs' }

and build_gdecl builder t =
  build_typ builder t

and build_fundec builder fd = 
  let (args_t, ret_t) = build_formal_ftyp builder (fd.args, fd.rets) in
    { args = args_t;
      rets = ret_t;
      body = build_blk builder fd.body;
      position = fd.position;
    }

and build_typ builder t =
  match t with
      Scalar t 		  -> Scalar (build_scalar_t builder t)
    | Array (t, n) 	  ->
        let t = build_typ builder t in
          Array (t, n)
    | Region (fields, sz) ->
        let fields = List.map (build_field builder) fields in
        let sz = build_size_t builder sz in
          Region (fields, sz)

and build_scalar_t builder t =
  match t with
      Int k ->
        let k = build_ikind builder k in
          Int k
    | Float sz ->
        let sz = build_size_t builder sz in
          Float sz
    | Ptr -> t
    | FunPtr -> t

and build_field builder (o, t) =
  let o = build_offset builder o in
  let t = build_typ builder t in
    (o, t)

and build_ikind builder (sign, sz) =
  let sz = build_size_t builder sz in
    (sign, sz)

and build_formal_ftyp builder (args, ret) =
  let build_arg (x, t) = (x, build_typ builder t) in
  let args 	       = List.map build_arg args in
  let ret 	       = List.map build_arg ret in
    (args, ret)

and build_offset builder o = builder#process_offset o

and build_size_t builder sz = builder#process_size_t sz

and build_blk builder blk = 
  let blk =
    match blk with
        hd::tl -> 
          let hd = build_stmt builder hd in
          let tl = build_blk builder tl in
            hd::tl
      | [] -> []
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
        Set (lv, e, t) ->
          let lv = build_lval builder lv in
          let e = build_exp builder e in
          let t = build_scalar_t builder t in
            Set (lv, e, t)
              
      | Copy (lv1, lv2, n) ->
          let lv1 = build_lval builder lv1 in
          let lv2 = build_lval builder lv2 in
          let n = build_size_t builder n in
            Copy (lv1, lv2, n)
              
      | Guard b -> Guard (build_exp builder b)

      | Decl (x, t, body) ->
          let t = build_typ builder t in
          let body = build_blk builder body in
            Decl (x, t, body)
              
      | Select (body1, body2) -> 
          Select (build_blk builder body1, build_blk builder body2)
              
      | InfLoop body -> InfLoop (build_blk builder body)
              
      | DoWith (body, lbl) -> DoWith (build_blk builder body, lbl)
              
      | Goto lbl -> Goto lbl
          
      | Call (args, fn, ret_vars) -> 
          let args' = List.map (fun (x, t) -> (build_exp builder x, t)) args in
	  let ret_vars = 
	    List.map (fun (x, t) -> (build_lval builder x, t)) ret_vars 
	  in
          let fn' = build_funexp builder fn in
            Call (args', fn', ret_vars)

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
    | FunDeref e -> FunDeref (build_exp builder e)

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
      | Lval (lv, s) ->
          let lv' = build_lval builder lv in
          let s' = build_typ builder s in
            Lval (lv', s')
      | AddrOf lv -> 
          let lv' = build_lval builder lv in
            AddrOf lv'
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
      PtrToInt k ->
        let k = build_ikind builder k in
          PtrToInt k
    | IntToPtr k ->
        let k = build_ikind builder k in
          IntToPtr k
    | Cast (t1, t2) ->
        let t1 = build_scalar_t builder t1 in
        let t2 = build_scalar_t builder t2 in
          Cast (t1, t2)
    | Focus sz -> Focus (build_size_t builder sz)
    | Belongs _ | Coerce _ | Not | BNot _-> op

and build_binop builder op =
  match op with
      PlusF sz -> PlusF (build_size_t builder sz)
    | MinusF sz -> MinusF (build_size_t builder sz)
    | MultF sz -> MultF (build_size_t builder sz)
    | DivF sz -> DivF (build_size_t builder sz)
    | MinusPP -> MinusPP
    | Gt t -> Gt (build_scalar_t builder t)
    | Eq t -> Eq (build_scalar_t builder t)
    | PlusI | MinusI | MultI | DivI | Mod
    | BOr _ | BAnd _ | BXor _ | Shiftlt | Shiftrt | PlusPI -> op

(* Visitor *)
(* TODO: simplify visitor by not needing the boolean to continue exploration
   possible ?
*)
class visitor =
object 
  val mutable cur_loc = unknown_loc
  method set_loc loc = cur_loc <- loc
  method get_loc = cur_loc

  method process_gdecl (_: string) (_: typ) = true
  method process_fun (_: fid) (_: fundec) = true
  method process_fun_after () = ()
  method process_stmt (_: stmt) = true
  method process_funexp (_: funexp) = true
  method process_exp (_: exp) = true
  method process_bexp (_: exp) = ()
  method process_lval (_: lval) = true
  method process_unop (_: unop) = ()
  method process_binop (_: binop) = ()
  method process_size_t (_: size_t) = ()
  method process_length (_: length) = ()
  method process_typ (_: typ) = ()

  method raise_error msg = 
    let (file, line, _) = cur_loc in
    let pos = 
      if cur_loc = unknown_loc then ""
      else " in "^file^" line "^(string_of_int line)
    in
      (invalid_arg (msg^pos) : unit)

  method print_warning msg = 
    let (file, line, _) = cur_loc in
    let pos = 
      if cur_loc = unknown_loc then ""
      else " in "^file^" line "^(string_of_int line)
    in
      print_endline ("Warning: "^msg^pos)
end

let visit_size_t visitor x = visitor#process_size_t x

let visit_length visitor x = visitor#process_length x

let visit_ikind visitor (_, sz) = visit_size_t visitor sz

let visit_scalar_t visitor t =
  match t with
      Int k -> visit_ikind visitor k
    | Float sz -> visit_size_t visitor sz
    | Ptr -> ()
    | FunPtr -> ()

let visit_typ visitor t = 
  visitor#process_typ t;
  let rec visit_typ t =
    match t with
        Scalar t -> visit_scalar_t visitor t
      | Array (t, n) -> 
          visit_typ t;
          visit_length visitor n
      | Region (fields, sz) ->
          List.iter (fun (_, t) -> visit_typ t) fields;
          visit_size_t visitor sz
  in
    visit_typ t

let visit_ftyp visitor (args, ret) =
  List.iter (visit_typ visitor) args;
  List.iter (visit_typ visitor) ret

let rec visit_lval visitor x =
  let continue = visitor#process_lval x in
    match x with
        Deref (e, sz) when continue -> 
          visit_exp visitor e;
          visit_size_t visitor sz
      | Shift (lv, e) when continue ->
          visit_lval visitor lv;
          visit_exp visitor e
      | _ -> ()
  
and visit_exp visitor x =
  let continue = visitor#process_exp x in
    if continue then begin
      match x with
          Lval (lv, _) -> visit_lval visitor lv
        | AddrOf lv -> visit_lval visitor lv
        | UnOp (op, e) -> 
            visitor#process_unop op;
            visit_exp visitor e
        | BinOp (bop, e1, e2) ->
            visitor#process_binop bop;
            visit_binop visitor bop;
            visit_exp visitor e1;
            visit_exp visitor e2
        | _ -> ()
    end

and visit_binop visitor op =
  match op with
      PlusF sz | MinusF sz | MultF sz | DivF sz -> visit_size_t visitor sz
    | _ -> ()

let visit_funexp visitor x =
  let continue = visitor#process_funexp x in
    match x with
        FunDeref e when continue -> visit_exp visitor e
      | _ -> ()

let rec visit_blk visitor x = List.iter (visit_stmt visitor) x
    
and visit_stmt visitor (x, loc) =
  visitor#set_loc loc;
  let continue = visitor#process_stmt (x, loc) in
    if continue then begin
      match x with
          Set (lv, e, _) -> 
            visit_lval visitor lv;
            visit_exp visitor e
        | Copy (lv1, lv2, sz) ->
            visit_lval visitor lv1;
            visit_lval visitor lv2;
            visit_size_t visitor sz
        | Guard b -> 
            visitor#process_bexp b;
            visit_exp visitor b
        | Decl (_, t, body) -> 
            visit_typ visitor t;
            visit_blk visitor body
        | Call (args, fn, ret_vars) ->
	    let visit_arg (x, t) = 
	      visit_exp visitor x;
	      visit_typ visitor t
	    in
	    let visit_ret (x, t) =
	      visit_lval visitor x;
	      visit_typ visitor t
	    in
              List.iter visit_arg args;
	      List.iter visit_ret ret_vars;
              visit_funexp visitor fn
        | Select (body1, body2) -> 
            visitor#set_loc loc;
            visit_blk visitor body1;
            visitor#set_loc loc;
            visit_blk visitor body2
        | InfLoop x -> visit_blk visitor x
        | DoWith (body, _) -> visit_blk visitor body
        | Goto _ -> ()
        | UserSpec assertion -> visit_assertion visitor assertion
    end else ()

and visit_assertion visitor x = List.iter (visit_token visitor) x

and visit_token builder x =
  match x with
      LvalToken (lv, t) -> 
        visit_lval builder lv;
        visit_typ builder t
    | _ -> ()

let visit_fun visitor fid ft =
  let continue = visitor#process_fun fid ft in
  if continue then begin
    visit_ftyp visitor ((List.map snd ft.args), List.map snd ft.rets);
    visit_blk visitor ft.body;
    visitor#process_fun_after ()
  end

let visit_glb visitor id t =
  let continue = visitor#process_gdecl id t in
    if continue then visit_typ visitor t

let visit visitor prog =
  Hashtbl.iter (visit_glb visitor) prog.globals;
  visit_blk visitor prog.init;
  Hashtbl.iter (visit_fun visitor) prog.fundecs

let max_ikind = max

class fid_addrof_visitor =
object 
  inherit visitor
  val mutable fid_list = []

  method get_fid_list () = fid_list

  method process_exp e = 
    begin match e with
        AddrOfFun (id, _) when not (List.mem id fid_list) ->
          fid_list <- id::fid_list
      | _ -> ()
    end;
    true
end


let collect_fid_addrof prog =
  let collector = new fid_addrof_visitor in
    visit collector prog;
    collector#get_fid_list ()

let rec equal_stmt (x1, _) (x2, _) =
  match (x1, x2) with
      (Decl (_, t1, body1), Decl (_, t2, body2)) -> 
        t1 = t2 && equal_blk body1 body2
    | (Select (bl1, br1), Select (bl2, br2)) ->
         (equal_blk bl1 bl2) && (equal_blk br1 br2)
    | (InfLoop body1, InfLoop body2) -> equal_blk body1 body2
    | (DoWith (body1, lbl1), DoWith (body2, lbl2)) ->
        equal_blk body1 body2 && lbl1 = lbl2
    | _ -> x1 = x2
  
and equal_blk x1 x2 = List.for_all2 equal_stmt x1 x2

(* TODO: do this in one tree traversal, instead of 2 *)
(* TODO: code optimization, this could be optimized, 
   maybe using inheritance ?? *)
(* TODO: once simplify choose is applied, there are opportunities for 
   simplify_gotos
   Fixpoint ??? *)
let simplify_blk opt_checks b = 
  let simplifications = if opt_checks then (new simplify_coerce)::[] else [] in
  let simplifications = 
    (new simplify_choose)::(new simplify_ptr)
    ::(new simplify_arith)::simplifications
  in
    simplify_gotos (simplify_blk simplifications b)

let simplify_exp opt_checks e =
  let simplifications = if opt_checks then (new simplify_coerce)::[] else [] in
  let simplifications = 
    (new simplify_ptr)::(new simplify_arith)::simplifications
  in
  simplify_exp simplifications e

let simplify opt_checks prog =
  let fundecs = Hashtbl.create 100 in
  let globals = Hashtbl.create 100 in
  let simplify_global x info = Hashtbl.add globals x info in
  let simplify_fundec f fd =
    let body = simplify_blk opt_checks fd.body in
      Hashtbl.add fundecs f { fd with body = body }
  in
  let init = simplify_blk opt_checks prog.init in
    Hashtbl.iter simplify_global prog.globals;
    Hashtbl.iter simplify_fundec prog.fundecs;
    { prog with globals = globals; init = init; fundecs = fundecs }

let rec belongs_of_exp x =
  match x with
      Lval (lv, _) | AddrOf lv -> belongs_of_lval lv
    | UnOp (Belongs b, e)      -> (b, e)::(belongs_of_exp e)
    | UnOp (_, e) 	       -> belongs_of_exp e 
    | BinOp (_, e1, e2)        -> (belongs_of_exp e1)@(belongs_of_exp e2)
    | _ 		       -> []

and belongs_of_lval x =
  match x with
      Deref (e, _) -> belongs_of_exp e
    | Shift (lv, e) -> (belongs_of_lval lv)@(belongs_of_exp e)
    | _ -> []

let belongs_of_funexp x =
  match x with
      FunDeref e -> belongs_of_exp e
    | _ -> []

let exp_of_int x = Const (CInt (Nat.of_int x))

let return_value = Temps.return_value

let char_kind () =
  let char_signedness =
   if !Conf.is_char_type_signed then Signed else Unsigned
  in
    (char_signedness, !Conf.size_of_char)

let char_typ () = Int (char_kind ())
  
let is_generic_temp name = Temps.is_generic_temp name
