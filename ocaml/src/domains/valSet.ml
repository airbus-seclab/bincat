(* set of Unrel.T values *)
module Make (V: Unrel.T) =
  (struct
    module Ptr = Pointer.Make(V)
      
    module PtrSet = Set.Make(struct type t = Ptr.t let compare = V.total_order end)

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

    let bot = BOT

    let is_bot e = e = BOT

    let forget = VSet.map V.forget

    let taint_sources e =
      match e with
      | BOT -> Taint.BOT
      | Val e' -> VSet.fold (fun e t -> Taint.logor (V.taint_sources e) t) e' Taint.U 
         
   end: Unrel.T)
