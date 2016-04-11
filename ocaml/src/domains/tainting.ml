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
  | _, _ 	    -> TOP
			       
let meet b1 b2 =
  match b1, b2 with
  | T, T 	     -> T
  | U, U 	    -> U
  | b, TOP | TOP, b -> b
  | _, _ 	    -> BOT
			       
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
	      
