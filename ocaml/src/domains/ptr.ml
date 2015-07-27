(******************************************************************************)
(* Functor generating the unrelational abstract domain of pointer             *)
(******************************************************************************)

module Make(D: Asm.T) =
  struct
    include D
    type t' = Address.t option * Offset.t option (* a pointeur is a base address plus an offset on that base ; None is top *)
    let top = None, None

    let to_string p =
      match p with
	Some b, Some o -> "(" ^ (Address.to_string b) ^ ", " ^ (Offset.to_string o) ^ ")"
      | None, _ -> "?"
      | Some b, _ -> "("^ (Address.to_string b) ^ ", ?)"
    let name = "Pointer"

    let eval_exp _e 	  = raise (Alarm.E (Alarm.Concretization name))
    let combine _ _ _ _ = top

    let mem_to_addresses (_m: exp) (_sz) _ctx = raise (Alarm.E (Alarm.Concretization name))
    let exp_to_addresses _e _ctx = raise (Alarm.E (Alarm.Concretization name))
					 
    let taint_memory _r = None (* None means that the module does not implement this functionality *)
    let taint_register _m = None (* None means that the module does not implement this functionality *)

    let equal p1 p2 =
      match p1, p2 with
	(Some b1, Some o1), (Some b2, Some o2) ->
	if Address.compare b1 b2 = 0 && Offset.compare o1 o2 = 0 then
	  true
	else
	  false
      | _, _ 				       -> false   

    let join p1 p2 =
      if equal p1 p2 then p1
      else
	top
	  
    let widen p1 p2 =
      match p1, p2 with
	(Some b1, Some o1), (Some b2, Some o2) ->
	if Address.compare b1 b2 = 0 && Offset.compare o1 o2 = 0 then
	  Some b1, Some o1
	else
	  Some b1, None
      | _, _ 				       -> top

    let contains p1 p2 =
      match p1, p2 with
	(Some b1, Some o1), (Some b2, Some o2) ->
	if Address.compare b1 b2 = 0 && Offset.compare o1 o2 = 0 then
	  true
	else
	  false
      | (Some _, _), _ 			       -> false
      | _, _ 				       -> true
  end

