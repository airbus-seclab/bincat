(******************************************************************************)
(* abstract domain of concrete pointer                                        *)
(******************************************************************************)


type region =
  | Global (** abstract base address of global variables and code *)
  | Stack (** abstract base address of the stack *)
  | Heap (** abstract base address of a dynamically allocated memory block *)


type offset = Z.t (** offset from a region-based value *)
		
type t =
  | I of region * offset
  | BOT (* bottom *)
  | TOP (* top *)
      
let name = "Pointer"

let bot _sz = BOT
	    
let equal p1 p2 =
  match p1, p2 with
  | BOT, BOT | TOP, TOP -> true
  | I (r1, o1), I (r2, o2) -> r1 = r2 && Z.equal o1 o2
  | _, _ -> false   
	      
let subset = equal

let string_of_region r =
  match r with
  | Global -> "global"
  | Stack  -> "stack"
  | Heap   -> "heap"

let string_of_offset o =
  let s   = String.escaped "0x%"   in
  let fmt = Printf.sprintf "%sx" s in
  Printf.sprintf "0x%s" (Z.format fmt o)
		 
let to_string p =
  match p with
  | I (r, o) -> Printf.sprintf "(%s, %s)" (string_of_region r)  (string_of_offset o)
  | TOP      -> "?"
  | BOT      -> "_"
		      
let of_config c = I (Global, c)
		       
let eval_exp _e = raise (Alarm.E (Alarm.Concretization name))
			
			
let mem_to_addresses (_m: Asm.exp) (_sz) _ctx = raise (Alarm.E (Alarm.Concretization name))
let exp_to_addresses _e _ctx = raise (Alarm.E (Alarm.Concretization name))
				     
let taint_of_config _c = BOT
			   
let join p1 p2 =
  if equal p1 p2 then p1
  else
    TOP
      
let combine _ _ _ _ = TOP
			
let enter_fun _fun _ctx = [], []
let leave_fun _ctx = [], []
			   
			   


