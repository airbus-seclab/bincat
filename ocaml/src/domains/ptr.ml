(******************************************************************************)
(* Functor generating the unrelational abstract domain of pointer             *)
(******************************************************************************)

module Make(Asm: Asm.T) =
  struct
    module Asm = Asm

    type t =
      I of Asm.Address.t option * Asm.Offset.t option (* a pointeur is a base address plus an offset on that base ; None is top *)
      | Bot (* bottom *)
	  
    let bot _sz = Bot
			   
    let top = I (None, None)

    let is_top v =
      match v with
      |	I (None, _) | I (_, None) -> true
      | _ 		  -> false
		     
    let to_string p =
      match p with
	I (Some b, Some o) -> "(" ^ (Asm.Address.to_string b) ^ ", " ^ (Asm.Offset.to_string o) ^ ")"
      | I (None, _) 	   -> "T"
      | I (Some b, _) 	   -> "("^ (Asm.Address.to_string b) ^ ", ?)"
      | Bot 		   -> "_|_"
		 
    let name = "Pointer"

    let eval_exp _e 	  = raise (Alarm.E (Alarm.Concretization name))
    let combine _ _ _ _ = top

    let mem_to_addresses (_m: Asm.exp) (_sz) _ctx = raise (Alarm.E (Alarm.Concretization name))
    let exp_to_addresses _e _ctx = raise (Alarm.E (Alarm.Concretization name))
					 
    let taint_memory _r = None (* None means that the module does not implement this functionality *)
    let taint_register _m = None (* None means that the module does not implement this functionality *)

    let equal p1 p2 =
      match p1, p2 with
	I (Some b1, Some o1), I (Some b2, Some o2) ->
	if Asm.Address.compare b1 b2 = 0 && Asm.Offset.compare o1 o2 = 0 then
	  true
	else
	  false
      | _, _ -> false   

    let join p1 p2 =
      if equal p1 p2 then p1
      else
	top
	  

    let contains p1 p2 =
      match p1, p2 with
	I (Some b1, Some o1), I (Some b2, Some o2) ->
	if Asm.Address.compare b1 b2 = 0 && Asm.Offset.compare o1 o2 = 0 then
	  true
	else
	  false
      | I (Some _, _), _ 		       -> false
      | _, _ 				       -> true
  end

