(** Composition of abstract domains *)
module Make(D1: Domain.T)(D2: Domain.T with module Asm = D1.Asm): Domain.T
