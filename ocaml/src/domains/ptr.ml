(******************************************************************************)
(* abstract domain of concrete pointer                                        *)
(******************************************************************************)

open Data
       
type t =
  | I of Address.t
  | BOT (* bottom *)
  | TOP (* top *)
      
let name = "Pointer"

let bot _sz = BOT
	    
let equal p1 p2 =
  match p1, p2 with
  | BOT, BOT | TOP, TOP -> true
  | I a1, I a2 		-> Address.equal a1 a2
  | _, _ 		-> false   
	      
let subset = equal



let string_of_offset o =
  let s   = String.escaped "0x%"   in
  let fmt = Printf.sprintf "%sx" s in
  Printf.sprintf "0x%s" (Z.format fmt o)
		 
let to_string p =
  match p with
  | I a -> Address.to_string a
  | TOP -> "?"
  | BOT -> "_"
		      
let of_config r c sz = I (Address.of_string r c sz)
		       
let eval_exp _e = raise (Exceptions.Enum_failure (name, "eval_exp"))
			
			
let mem_to_addresses (_m: Asm.exp) (_sz) _ctx = raise (Exceptions.Enum_failure (name, "mem_to_addresses"))
				     
let taint_of_config _c = BOT
			   
let join p1 p2 =
  if equal p1 p2 then p1
  else
    TOP
      
let combine _ _ _ _ = TOP
			
let enter_fun _fun _ctx = [], []
let leave_fun _ctx = [], []
			   
			   


