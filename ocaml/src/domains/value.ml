(** data type *)
type t =
  | BOT (** bottom (undef) *)
  | ZERO   (** zero *)
  | ONE   (** one *)
  | TOP (** top *)
      
let bot = BOT
let is_bot v = v = BOT
 		     
let join b1 b2 =
  match b1, b2 with
  | ZERO, ZERO 	    	  -> ZERO
  | ONE, ONE 	    	  -> ONE
  | BOT, v | v, BOT 	  -> v
  | ONE, ZERO | ZERO, ONE -> ONE
  | _, _ 	    	  -> TOP
			 
let meet b1 b2 =
  match b1, b2 with
  | ZERO, ZERO 	    	  -> ZERO
  | ONE, ONE 	    	  -> ONE
  | BOT, _ | _, BOT 	  -> BOT
  | ONE, ZERO | ZERO, ONE -> ZERO
  | _, TOP | TOP, _ 	  -> TOP
			       
let to_string b =
  match b with
  | TOP  -> "?"
  | BOT  -> "_"
  | ZERO -> "0"
  | ONE  -> "1"
	     
let equal b1 b2 = b1 = b2
			 
let add b1 b2 =
  match b1, b2 with
  | TOP, _ | _, TOP 	  -> TOP, true
  | BOT, _ | _, BOT 	  -> BOT, true
  | ZERO, ZERO 	    	  -> ZERO, false
  | ZERO, ONE | ONE, ZERO -> ONE, false
  | ONE, ONE 	    	  -> ZERO, true

let sub b1 b2 =
  match b1, b2 with
  | TOP, _ | _, TOP -> TOP, true
  | BOT, _ | _, BOT -> BOT, true
  | ZERO, ZERO 	    -> ZERO, false
  | ZERO, ONE       -> ONE, true
  | ONE, ZERO       -> ONE, false
  | ONE, ONE 	    -> ZERO, false
								
let xor b1 b2 =
  match b1, b2 with
  | TOP, _ | _, TOP 	  -> TOP
  | BOT, _ | _, BOT 	  -> BOT
  | ZERO, ZERO 	    	  -> ZERO
  | ZERO, ONE | ONE, ZERO -> ONE
  | ONE, ONE 	    	  -> ZERO
			 
let lognot v =
  match v with
  | BOT  -> BOT
  | TOP  -> TOP
  | ZERO -> ONE
  | ONE  -> ZERO
		     
(* finite lattice => widen = join *)
let widen = join
	      
(* conversion to Z.t. May raise an exception if the conversion fails *)
let to_value v =
  match v with
  | BOT | TOP -> raise Exceptions.Concretization
  | ZERO      -> Z.zero
  | ONE       -> Z.one
   
let default = BOT
		
let eq v1 v2 =
  match v1, v2 with
  | BOT, BOT 	    	      -> true
  | _, BOT | BOT, _ 	      -> false
  | TOP, _ | _, TOP 	      -> true
  | ZERO, ZERO | ONE, ONE     -> true
  | _, _ 	    	      -> false
			 
let neq v1 v2 =
  match v1, v2 with
  | BOT, BOT 	    	      -> false
  | _, BOT | BOT, _ 	      -> true
  | TOP, _ | _, TOP 	      -> true
  | ZERO, ZERO | ONE, ONE     -> false
  | _, _ 	    	      -> true
			 
let leq v1 v2 =
  match v1, v2 with
  | BOT, _ 	       		      -> true
  | _, BOT             		      -> false
  | TOP, _ | _, TOP    		      -> true
  | ZERO, ZERO | ONE, ONE | ZERO, ONE -> true
  | _, _ 	       		      -> false
			    
let lt v1 v2 =
  match v1, v2 with
  | _, BOT          -> false
  | BOT, _          -> true
  | TOP, _ | _, TOP -> true
  | ZERO, ONE       -> true
  | _, _ 	    -> false
			 
let geq v1 v2 =
  match v1, v2 with
  | BOT, BOT 	       		      -> true
  | TOP, _ | _, TOP    		      -> true
  | ZERO, ZERO | ONE, ONE | ONE, ZERO -> true
  | _, _ 	       		      -> false
			    
let gt v1 v2 =
  match v1, v2 with
  | BOT, _          -> false
  | _, BOT          -> true
  | TOP, _ | _, TOP -> true
  | ONE, ZERO       -> true
  | _, _ 	    -> false

		       
let compare v1 op v2 =
  match op with
  | Asm.EQ  -> eq v1 v2
  | Asm.NEQ -> neq v1 v2
  | Asm.LEQ -> leq v1 v2
  | Asm.GEQ -> geq v2 v1
  | Asm.LT  -> lt v1 v2
  | Asm.GT  -> gt v1 v2
		  
let subset v1 v2 = leq v1 v2
