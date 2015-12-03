(******************************************************************************)
(* Functor generating the unrelational abstract domain of pointer             *)
(******************************************************************************)

module Make(Asm: Asm.T) =
  struct
    module Asm = Asm

    type t =
      | I of Asm.Address.t * Asm.Offset.t (* a pointer is a base address plus an offset on that base *)
      | BOT (* bottom *)
      | TOP (* top *)
	  
    let bot _sz = BOT
			   
    let to_string p =
      match p with
	I (b, o) -> Printf.sprintf "(%s, %s)"  (Asm.Address.to_string b)  (Asm.Offset.to_string o)
      | TOP 	 -> "T"
      | BOT 	 -> "_|_"
		 
    let name = "Pointer"

    let eval_exp _e = raise (Alarm.E (Alarm.Concretization name))
    let combine _ _ _ _ = TOP

    let mem_to_addresses (_m: Asm.exp) (_sz) _ctx = raise (Alarm.E (Alarm.Concretization name))
    let exp_to_addresses _e _ctx = raise (Alarm.E (Alarm.Concretization name))
					 
    let taint_from_config _r = None (* None means that the module does not implement this functionality *)

    let equal p1 p2 =
      match p1, p2 with
      | BOT, BOT | TOP, TOP -> true
      | I (b1, o1), I (b2, o2) ->
	if Asm.Address.compare b1 b2 = 0 && Asm.Offset.compare o1 o2 = 0 then
	  true
	else
	  false
      | _, _ -> false   

    let subset = equal
		   
    let join p1 p2 =
      if equal p1 p2 then p1
      else
	TOP
	  
    let of_config b sz = I (Asm.Address.of_string b sz, Asm.Offset.zero)

  end

