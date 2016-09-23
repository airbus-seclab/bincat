(** data type *)
type t =
  | ZERO   (** zero *)
  | ONE   (** one *)
  | TOP (** top *)
       		     
let join b1 b2 =
  match b1, b2 with
  | ZERO, ZERO 	    	  -> ZERO
  | ONE, ONE 	    	  -> ONE
  | ONE, ZERO | ZERO, ONE -> ONE
  | _, _ 	    	  -> TOP
			 
let meet b1 b2 =
  match b1, b2 with
  | ZERO, ZERO 	    	  -> ZERO
  | ONE, ONE 	    	  -> ONE
  | ONE, ZERO | ZERO, ONE -> ZERO
  | _, TOP | TOP, _ 	  -> TOP
			       
let to_char b =
  match b with
  | TOP  -> '?'
  | ZERO -> '0'
  | ONE  -> '1'

let to_string b =
  match b with
  | TOP  -> "?"
  | ZERO -> "0"
  | ONE  -> "1"

let equal b1 b2 = b1 = b2
			 
let add b1 b2 =
  match b1, b2 with
  | TOP, _ | _, TOP 	  -> TOP, true
  | ZERO, ZERO 	    	  -> ZERO, false
  | ZERO, ONE | ONE, ZERO -> ONE, false
  | ONE, ONE 	    	  -> ZERO, true

let sub b1 b2 =
  match b1, b2 with
  | TOP, _ | _, TOP -> TOP, true
  | ZERO, ZERO 	    -> ZERO, false
  | ZERO, ONE       -> ONE, true
  | ONE, ZERO       -> ONE, false
  | ONE, ONE 	    -> ZERO, false
								
let xor b1 b2 =
  match b1, b2 with
  | TOP, _ | _, TOP 	  -> TOP
  | ZERO, ZERO 	    	  -> ZERO
  | ZERO, ONE | ONE, ZERO -> ONE
  | ONE, ONE 	    	  -> ZERO
			 
let lognot v =
  match v with
  | TOP  -> TOP
  | ZERO -> ONE
  | ONE  -> ZERO
		     
(* finite lattice => widen = join *)
let widen = join
	      
(* conversion to Z.t. May raise an exception if the conversion fails *)
let to_z v =
  match v with
  | TOP  -> raise Exceptions.Concretization
  | ZERO -> Z.zero
  | ONE  -> Z.one
   
let eq v1 v2 =
  match v1, v2 with
  | TOP, _ | _, TOP 	      -> true
  | ZERO, ZERO | ONE, ONE     -> true
  | _, _ 	    	      -> false
			 
let neq v1 v2 =
  match v1, v2 with
  | TOP, _ | _, TOP 	      -> true
  | ZERO, ZERO | ONE, ONE     -> false
  | _, _ 	    	      -> true
			 
let leq v1 v2 =
  match v1, v2 with
  | _, TOP    		      	      -> true
  | ZERO, ZERO | ONE, ONE | ZERO, ONE -> true
  | _, _ 	       		      -> false
			    
let lt v1 v2 =
  match v1, v2 with
  | TOP, _ | _, TOP -> true
  | ZERO, ONE       -> true
  | _, _ 	    -> false
			 
let geq v1 v2 =
  match v1, v2 with
  | TOP, _ | _, TOP    		      -> true
  | ZERO, ZERO | ONE, ONE | ONE, ZERO -> true
  | _, _ 	       		      -> false
			    
let gt v1 v2 =
  match v1, v2 with
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
