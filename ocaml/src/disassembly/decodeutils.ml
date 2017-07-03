open Data
open Asm

(************************************************************************)
(* Generic Helpers *)
(************************************************************************)

(** [const c sz] builds the asm constant of size _sz_ from int _c_ *)
let const c sz = Const (Word.of_int (Z.of_int c) sz)

(** [const_of_Z z sz] builds the asm constant of size _sz_ from Z _z_ *)
let const_of_Z z sz = Const (Word.of_int z sz)

(** sign extension of a Z.int _i_ of _sz_ bits on _nb_ bits *)
let sign_extension i sz nb =
if Z.testbit i (sz-1) then
  let ff = (Z.sub (Z.shift_left (Z.one) nb) Z.one) in
  (* ffff00.. mask *)
  let ff00 = (Z.logxor ff ((Z.sub (Z.shift_left (Z.one) sz) Z.one))) in
  Z.logor ff00 i
else
  i

