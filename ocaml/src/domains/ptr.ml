(******************************************************************************)
(* Functor generating the unrelational abstract domain of pointer             *)
(******************************************************************************)
module Make(D: Data.T) =
  struct
    type t' = (D.Address.t * D.Offset.t) option (* a pointeur is a base address plus an offset on that base ; None is top *)
    let top = None
    let to_string p =
      match p with
	Some (b, o) -> "(" ^ (D.Address.to_string b) ^ ", " ^ (D.Offset.to_string o) ^ ")"
      | None 	    -> "?"
    let name = "Pointer"
    let eval_exp _e 	  = raise (Alarm.E (Alarm.Concretization name))
    let combine _ _ _ _ = universe()
    let mem_to_addresses (_m: A.memory) (_sz) _ctx = raise (Alarm.E (Alarm.Concretization name))
    let exp_to_addresses _e _ctx = raise (Alarm.E (Alarm.Concretization name))
    let taint_memory _r = None (* None means that the module does not implement this functionality *)
    let taint_register _m = None (* None means that the module does not implement this functionality *)
    let widen _m1 _m2 = failwith "Ptr.widen: to implement"
  end

