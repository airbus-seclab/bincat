  (** data type *)
type t =
  | T   (** bit is tainted *)
  | U   (** bit is untainted *)
  | TOP (** top *)
  | BOT (** bottom (undef) *)
      
let bot = BOT
	    
let join b1 b2 =
  match b1, b2 with
  | T, T 	    -> T
  | U, U 	    -> U
  | BOT, b | b, BOT -> b
  | _, _            -> TOP

let logor b1 b2 =
  match b1, b2 with
  | T, T | U, T | T, U -> T
  | U, U 	       -> U
  | BOT, _ | _, BOT    -> BOT
  | _, _ 	       -> TOP
			 
let meet b1 b2 =
  match b1, b2 with
  | T, T 	     -> T
  | U, U 	    -> U
  | b, TOP | TOP, b -> b
  | U, T | T, U     -> U
  | BOT, _ | _, BOT -> BOT
			 
			       
let to_string b =
  match b with
  | TOP -> "?"
  | BOT -> "_"
  | T   -> "1"
  | U   -> "0"
	     
let equal b1 b2 = b1 = b2
			 
let binary carry t1 t2 =
  match t1, t2 with
  | BOT, _ | _, BOT -> BOT
  | TOP, _ | _, TOP -> TOP
  | T, _ | _, T     -> T
  | U, U 	    -> if carry then T else U
						    
let add = binary
let sub = binary
let xor = binary false
let neg v = v

(* finite lattice => widen = join *)
let widen = join

(* default tainting value is Untainted *)
let default = U

let untaint _t = U
let taint _t = T
let weak_taint _t = TOP
		      
let is_tainted t =
  match t with
  | T | TOP -> true
  | _ 	    -> false
