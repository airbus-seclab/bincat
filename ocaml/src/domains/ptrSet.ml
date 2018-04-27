(* set of pointers *)
module Make (V: Vector.T) =
  (struct
      type ptr = Pointer.Make(V)
   end: Unrel.T)
