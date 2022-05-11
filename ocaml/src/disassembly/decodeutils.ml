open Data
open Asm

(************************************************************************)
(* Generic Helpers *)
(************************************************************************)

(** [const c sz] builds the asm constant of size _sz_ from int _c_ *)
let const c sz = Const (Word.of_int (Z.of_int c) sz)

(** [zconst c sz] builds the asm constant of size _sz_ from Z.t _c_ *)
let zconst c sz = Const (Word.of_int c sz)
               
(** [sconst c isz sz] builds the signed asm constant of size _sz_ by
    sign extending  _c_ seen as a signed int of _isz_ bits *)
let sconst c isz sz = Const (Word.of_int (Z.signed_extract (Z.of_int c) 0 isz) sz)

(** [const_of_Z z sz] builds the asm constant of size _sz_ from Z _z_ *)
let const_of_Z z sz = Const (Word.of_int z sz)

(** [one8] an asm Const of 8 bits with value 1 *)
let one8 = Const (Word.one 8)

(** [const1 sz] builds an Asm constant 1 of size _sz_  *)
let const1 sz = Const (Word.one sz)

(** [const0 sz] builds an Asm constant 0 of size _sz_  *)
let const0 sz = Const (Word.zero sz)

let z_mask_ff bits = Z.sub (Z.shift_left Z.one bits) Z.one

let const_mask n sz = Const (Word.of_int (z_mask_ff n) sz)

(** zero extend to 33 bits *)
let to33bits x = UnOp(ZeroExt 33, x)

(** sign extend to 33 bits *)
let to33bits_s x = UnOp(SignExt 33, x)

                 
(** sign extension of a Z.int _i_ of _sz_ bits on _nb_ bits *)
let sign_extension i sz nb =
  if sz = nb then
    i
  else
    if Z.testbit i (sz-1) then
      let ff = (Z.sub (Z.shift_left (Z.one) nb) Z.one) in
      (* ffff00.. mask *)
      let ff00 = (Z.logxor ff ((Z.sub (Z.shift_left (Z.one) sz) Z.one))) in
      Z.logor ff00 i
    else
      i

(** [msb_expr expr sz] expression to get the MSB of _expr_ (size _sz_) *)
let msb_expr reg sz =
    let sz_min_one = const (sz-1) sz in
    BinOp(And, (const1 sz), BinOp(Shr, reg, sz_min_one))

(** [msb reg] expression to get the MSB of _reg_ *)
let msb_reg reg =
  let sz = Register.size reg in
  let sz_min_one = const (sz-1) sz in
  BinOp(Shr, Lval (V (T reg)), sz_min_one)


(** [carry_stmts sz op1 op op2] produces the statement to compute the carry flag
    according to operation _op_ whose operands are _op1_ and _op2_,
    returns a value of ONE bit *)
let carry_stmts sz op1 op op2 =
  (* carry is 1 if the sz+1 bit of the result is 1 *)
  let sz_p1 = sz+1 in
  let zext = ZeroExt (sz_p1)      in
  let op1' = UnOp (zext, op1)     in
  let op2' = UnOp (zext, op2)     in
  let res = BinOp (op, op1', op2') in
  let msb = msb_expr res sz_p1 in
  TernOp(Cmp (EQ, msb, const1 sz_p1), const1 1, const0 1)

(** [carry_stmts_3 sz op1 op op2] produces the statement to compute the carry flag
    according to operation _op_ whose operands are _op1_, _op2_ and _op3_
    returns a value of ONE bit *)
let carry_stmts_3 sz op1 op op2 op3 =
  (* carry is 1 if the sz+1 bit of the result is 1 *)
  let sz_p1 = sz+1 in
  let zext = ZeroExt (sz_p1)      in
  let op1' = UnOp (zext, op1)     in
  let op2' = UnOp (zext, op2)     in
  let op3' = UnOp (zext, op3)     in
  let res = BinOp(op, BinOp (op, op1', op2'), op3') in
  let msb = msb_expr res sz_p1 in
  TernOp(Cmp (EQ, msb, const1 sz_p1), const1 1, const0 1)

(** [overflow_stmts sz res op1 op op2] produces the statement to compute the overflow flag according to
    operation _op_ whose operands are _op1_ and _op2_ and result is _res_
    returns a value of ONE bit *)
let overflow_stmts sz res op1 op op2 =
  (* flag is set if both op1 and op2 have the same nth bit and the hightest bit of res differs *)
  let sign_res  = msb_expr res sz in
  let sign_op1  = msb_expr op1 sz in
  let sign_op2  = msb_expr op2 sz in
  let cmp_op =
    match op with
    | Add -> EQ
    | Sub -> NEQ
    | _ -> raise (Invalid_argument "unexpected operation in overflow flag computation") in
  let c1          = Cmp (cmp_op, sign_op1, sign_op2)          in
  let c2          = Cmp (NEQ, sign_res, sign_op1)         in
  TernOp (BBinOp (LogAnd, c1, c2), const1 1, const0 1)

(** returns the char list of the given string **)
let string_to_char_list str =
    let len = String.length str in
    let rec process i =
      if i < len then
        (String.get str i)::(process (i+1))
      else
        []
    in
    List.rev (process 0)
