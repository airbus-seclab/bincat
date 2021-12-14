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
  EADS Innovation Works - SE/CS
  12, rue Pasteur - BP 76 - 92152 Suresnes Cedex - France
  email: charles.hymans@penjili.org

  Sarah Zennou
  EADS Innovation Works - SE/IS
  12, rue Pasteur - BP 76 - 92152 Suresnes Cedex - France
  email: sarah(dot)zennou(at)eads(dot)net
*)

(** Newspeak is a language designed for the purpose of static analysis. 
    It was designed with these features in mind:
    - precise: its semantics is precisely defined, 
    (see {e Newspeak, Doubleplussimple Minilang for Goodthinkful Static 
    Analysis of C} for a thorough and formal description. Available from
    {{:http://www.penjili.org}www.penjili.org})
    - simple: its primitives are as few, as standard and as concise as 
    possible,
    - minimal: no language primitive or fragment of primitive should be 
    expressible as a combination of other primitives,
    - explicit: primitives are context-free, i.e. all semantic information
    needed to execute it are readily available,
    - analysis-friendly: annotations useless for execution are added to allow
    a static analysis tool to perform correctness checks,
    - architecture-independent: all architecture or compiler dependent features
    (size of types, offsets of structure fields, order of executions, ...)
    are made explicit byt the translation to Newspeak,
    - expressive: it should be possible to translate most C programs into 
    Newspeak.

    Newspeak can be seen as a kind of high-level assembly language with 
    annotations for analysis.
    The type of Newspeak programs, types, statements and expressions are 
    described in this module.
    Additionnally, some functions to create, manipulate, export and display 
    Newspeak programs are provided. 
*)

(** {2 Types} *)

module Nat: sig 
  type t = string
  val zero: t
  val one: t
  val of_string: string -> t
  val to_string: t -> string
  val of_int: int -> t

  (** [to_int x] returns the integer representation of [x], when possible.
      @raise Invalid_argument "Newspeak.Nat.to_int" otherwise. *)
  val to_int: t -> int

  val of_z: Z.t -> t
  val to_z: t -> Z.t

  val add: t -> t -> t
  val mul: t -> t -> t
  val sub: t -> t -> t
  val div: t -> t -> t

  val neg: t -> t

  val add_int: int -> t -> t
  val mul_int: int -> t -> t

  (** [shift_left x n] multiplies [x] by 2 to the power [n]. *)
  val shift_left: t -> int -> t

  val compare: t -> t -> int
end

(* The type of a program: file names, global variable declarations,
    function definitions and the size of pointers. *)

type t = {
  globals: globals;                 (** table of all declared global 
					variables *)
  init: blk;                        (** initialization block for globals *)
  fundecs: (fid, fundec) Hashtbl.t; (** table of all declared functions *)
  ptr_sz: size_t;                   (** size of pointers in number of bits *)
  src_lang: src_lang;
                                    (** source language from the program 
					was compiled *)
  abi: abi_t;                       (** ABI the program was compiled with *)
}

and fundec = {
  args : (string * typ) list; (** formal argument names and types *)
  rets : (string * typ) list; (** formal return values names and types *)
  body : blk;                 (** function body *)
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
(* TODO: maybe should use a record rather than a tuple? *)
(* arguments, function type, function expression, return left values *)
  | Call     of ((exp * typ) list * funexp * (lval * typ) list  )
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

(* TODO: try to remove ftyp?? maybe not, it comes in handy *)
and ftyp = typ list * typ list

and typ =
    Scalar of scalar_t
  | Array  of (typ * length)
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
    Belongs  of bounds
  | Coerce   of bounds
  | Focus    of size_t
  | Not
  | BNot     of bounds
  | PtrToInt of ikind
  | IntToPtr of ikind
  | Cast     of (scalar_t * scalar_t) (** source type => dest type *)

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

val unknown_loc: location
val dummy_loc: string -> location

(* {1 Constants} *)

val zero: exp
val one: exp
val zero_f: exp

(* {1 Manipulation and Simplifications} *)
val char_kind : unit -> ikind
val char_typ  : unit -> scalar_t

(* Given the characteristics of an integer type, [domain_of_typ]
    returns the bounds of the type. *)
val domain_of_typ : sign_t * size_t -> bounds

val belongs: Nat.t -> bounds -> bool

val contains: bounds -> bounds -> bool

(* Negation of a boolean condition. *)
val negate : exp -> exp

(* Deletion of useless Gotos and Labels. *)
val simplify_gotos : blk -> blk

(* Normalization of loops *)
val normalize_loops : blk -> blk

(* Run all simplifications. *)
(* true to remove checks when possible *)
val simplify_blk: bool -> blk -> blk
(* true to remove checks when possible *)
val simplify_exp: bool -> exp -> exp

val simplify: bool -> t -> t



(** {1 Display} *)

(** @raise Invalid_argument "Newspeak.string_of_loc: unknown location" 
    if the file name is unknown
*)
val string_of_loc : location -> string

val string_of_unop: unop -> string

val string_of_args: exp list -> string

(** [string_of_bounds r] returns the string representation of range [r]. *)
val string_of_bounds : bounds -> string

(** [string_of_cst c] returns the string representation of constant [c]. *)
val string_of_cst : cst -> string
val string_of_sign_t: sign_t -> string
val string_of_scalar : scalar_t -> string
val string_of_typ : typ -> string
val string_of_ftyp : ftyp -> string
val string_of_funexp: funexp -> string
val string_of_exp : exp -> string
val string_of_lval : lval -> string

val string_of_stmt: stmt -> string

val string_of_fundec: fid -> fundec -> string

(** [string_of_block blk] returns the string representation of block [blk]. *)
val string_of_blk: blk -> string

val string_of_binop: binop -> string

val string_of_formal_args: (string * typ) list -> string
val string_of_ret: (string * typ) list -> string
val string_of_size_t: size_t -> string
val string_of_lbl: lbl -> string
val string_of_assertion: assertion -> string

(* Visitor *)
class visitor:
object
  method process_gdecl: string -> typ -> bool
  method process_fun: fid -> fundec -> bool
  method process_fun_after: unit -> unit
  method process_stmt: stmt -> bool
  method process_funexp: funexp -> bool
  method process_exp: exp -> bool
(* called on expressions that are used as guards of choices *)
  method process_bexp: exp -> unit
  method process_lval: lval -> bool
  method process_unop: unop -> unit
  method process_binop: binop -> unit
  method process_size_t: size_t -> unit
  method process_length: length -> unit
  method process_typ: typ -> unit

  (* Sets current location *)
  method set_loc: location -> unit
  (* Gets current location *)
  method get_loc: location
  method print_warning: string -> unit
  (* Throws an Invalid_argument in a standard way, with the file and line
     number *)
  method raise_error: string -> unit
end

val visit_assertion: visitor -> assertion -> unit
val visit_exp: visitor -> exp -> unit
val visit_blk: visitor -> blk -> unit
val visit_fun: visitor -> fid -> fundec -> unit
val visit_glb: visitor -> string -> typ -> unit
val visit: visitor -> t -> unit

class builder:
object
  method set_curloc: location -> unit
  method curloc: location
  method process_global: string -> typ -> typ
  method process_lval: lval -> lval
  method process_exp: exp -> exp
  method process_blk: blk -> blk
  method enter_stmtkind: stmtkind -> unit
  method process_stmtkind: stmtkind -> stmtkind
  method process_size_t: size_t -> size_t
  method process_offset: offset -> offset
end

val build : builder -> t -> t

val build_gdecl: builder -> typ -> typ

(** [write name prog] write the program prog *)
val write : string -> t -> unit

(** [read name] retrieves the list of file names, program and size of
    pointers from a .npk file.
    @param name file name of the .npk file to read
    @raise Invalid_argument if the input file is not a valid .npk file, or its
    newspeak version is not the same as this file's.
*)
val read : string -> t 

val size_of_scalar : size_t -> scalar_t -> size_t

(* 
    Type of the size_of function.
    [size_of t] returns the size of any value of type t.
*)
val size_of : size_t -> typ -> size_t

val max_ikind: ikind -> ikind -> ikind

(** returns the list of all function identifiers that are stored as function
    pointers in the program. *)
val collect_fid_addrof: t -> fid list

val equal_blk: blk -> blk -> bool

val belongs_of_exp: exp -> (bounds * exp) list

val belongs_of_lval: lval -> (bounds * exp) list

val belongs_of_funexp: funexp -> (bounds * exp) list

val dump : t -> unit

val exp_of_int : int -> exp

(** returns the name of local variable introduced to store the result
of the functions *)
val return_value: string

(** returns true whenever the parameter is a name of variable
introduced by Newspeak *)
val is_generic_temp: string -> bool
