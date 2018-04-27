(* set of pointers *)
module Make (V: Vector.T) =
  (struct
    module Ptr = Pointer.Make(V)
    module PtrSet = Set.Make(struct type t = Ptr.t let compare = Ptr.total_order end)
    type t =
      | Val of PtrSet.t 
      | BOT

    let normalize e =
      match e with
      | BOT -> BOT
      | Val e' ->
         if PtrSet.cardinal > !Config.kset_bound then
           Val (PtrSet.fold (fun v e -> V.join v e) e' V.bot)
         else
           e
             
   end: Unrel.T)
