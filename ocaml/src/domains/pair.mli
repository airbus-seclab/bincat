(** Composition of abstract domains *)
module Make(D1: Domain.T)(D2: Domain.T): Domain.T
