  (** data type *)
type t =
  | T   (** bit is tainted *)
  | U   (** bit is untainted *)
  | TOP (** top *)
	    
let join b1 b2 =
  match b1, b2 with
  | T, T 	    -> T
  | U, U 	    -> U
  | _, _            -> TOP

let logor b1 b2 =
  match b1, b2 with
  | T, _ | _, T -> T
  | U, U 	-> U
  | _, _ 	-> TOP

let logand b1 b2 =
  match b1, b2 with
  | T, T -> T
  | T, U | U, T -> U
  | U, U -> U
  | TOP, U | U, TOP -> TOP
  | TOP, _ | _, TOP -> TOP

   
let meet b1 b2 =
  match b1, b2 with
  | T, T 	     -> T
  | U, U 	    -> U
  | b, TOP | TOP, b -> b
  | U, T | T, U     -> U

let to_char b =
  match b with
  | TOP -> '?'
  | T   -> '1'
  | U   -> '0'

let to_string b =
  match b with
  | TOP -> "?"
  | T   -> "1"
  | U   -> "0"

let equal b1 b2 = b1 = b2

let binary carry t1 t2 =
  match t1, t2 with
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

let min t1 t2 =
  match t1, t2 with
  | U, t  | t, U -> t
  | T, _  | _, T -> T
  | _, _ -> TOP
     
		      
let is_tainted t =
  match t with
  | T | TOP -> true
  | _ 	    -> false

let to_z t =
  match t with
  | U -> Z.zero
  | T -> Z.one
  | _ -> raise Exceptions.Concretization
