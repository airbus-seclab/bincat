module Make(D: Data.T) =
  struct
    include D
    let t' = Address.t * Offset.t
    let top 		  = universe ()
    let to_string b 	  = to_string b
    let name 		  = "Pointer"
    let eval_exp _e 	  = raise (Alarm.E (Alarm.Concretization name))
    let combine _ _ _ _ = universe()
    let mem_to_addresses (_m: A.memory) (_sz) _ctx = raise (Alarm.E (Alarm.Concretization name))
    let exp_to_addresses _e _ctx = raise (Alarm.E (Alarm.Concretization name))
    let taint_memory _r = None
    let taint_register _m = None
    let widen _m1 _m2 = failwith "Ptr.widen: to implement"
  end

