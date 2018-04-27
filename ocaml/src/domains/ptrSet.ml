(* set of pointers *)
module Make (V: Vector.T) =
  (struct
    module Ptr = Pointer.Make(V)
    module PtrSet = Set.Make(module type t = Ptr.t let compare = Ptr.total_order end)
    type t = PtrSet.t
   end: Unrel.T)
