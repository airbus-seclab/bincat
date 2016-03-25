(******************************************************************************)
(* abstract domain of concrete pointer                                        *)
(******************************************************************************)


module Address = Data.Address

       
type t =
  | Val of Address.t
  | BOT (* bottom *)
  | TOP (* top *)
      
let name = "Pointer"

let bot = BOT
let top = TOP
	    
let equal p1 p2 =
  match p1, p2 with
  | BOT, BOT | TOP, TOP -> true
  | Val a1, Val a2 		-> Address.equal a1 a2
  | _, _ 		-> false   
	      
let subset = equal

let to_value v =
  match v with
  | BOT | TOP -> raise Exceptions.Concretization
  | Val a     -> Address.to_int a

let string_of_offset o =
  let s   = String.escaped "0x%"   in
  let fmt = Printf.sprintf "%sx" s in
  Printf.sprintf "0x%s" (Z.format fmt o)
		 
let to_string p =
  match p with
  | Val a -> Address.to_string a
  | TOP -> "?"
  | BOT -> "_"

let of_word c = Val (Address.of_word c)
		      
let of_config r c sz = Val (Address.of_int r c sz)
			   
(** [shift sh v1 v2] shift v1 by v2 in the direction given by sh *)
let shift sh v1 v2 = sh v1 (Z.to_int v2)


(** [binary sh v1 v2] computes v1 sh v2 *)
let binary op v1 v2 =
  let op' = 
    match op with
    | Asm.Add -> Z.add
    | Asm.Sub -> Z.sub
    | Asm.Mul -> Z.mul
    | Asm.Div -> Z.div
    | Asm.Shl -> shift Z.shift_left
    | Asm.Shr -> shift Z.shift_right
    | Asm.Mod -> (fun w1 w2 -> Z.sub w1 (Z.div w1 w2))
    | Asm.And -> Z.logand
    | Asm.Or  -> Z.logor
    | Asm.Xor -> Z.logxor
  in
  match v1, v2 with
  | BOT, _ | _, BOT  -> BOT
  | _, TOP | TOP, _  -> TOP
  | Val v1', Val v2' ->
    try
      Val (Address.binary op' v1' v2')
    with _ -> TOP
		
let unary _op v =
  match v with
  | BOT -> BOT
  | TOP -> TOP
  | Val _v' -> TOP (* sound but could be more precise *)

			
let to_addresses v =
  match v with
  | BOT   -> raise Exceptions.Enum_failure
  | TOP   -> raise Exceptions.Enum_failure
  | Val a -> Address.Set.singleton a
  
				     
let taint_of_config _c = BOT
			   
let join p1 p2 =
  if equal p1 p2 then p1
  else
    TOP

let meet p1 p2 =
  if equal p1 p2 then p1
  else
    BOT
      
let combine _ _ _ _ = TOP
			
let enter_fun _fun _ctx = [], []
let leave_fun _ctx = [], []
			   
let extract _ _ _ = TOP
let compare _ _ _ = Log.error "Ptr.compare"


