(** reduced product between Value and Tainting *)
(** its signature is Vector.Value_domain *)

module V = Value
module T = Tainting

type t = V.t * T.t

let bot = V.BOT, T.BOT
let top = V.TOP, T.TOP
		   
let is_bot (v, _t) = v = V.BOT
let is_top (v, _t) = v = V.TOP
			      
let to_value (v, _t) = V.to_value v

let forget_taint (v, _t) = v, T.TOP
				
let join (v1, t1) (v2, t2) = V.join v1 v2, T.join t1 t2

let meet (v1, t1) (v2, t2) = V.meet v1 v2, T.meet t1 t2
						  
let xor (v1, t1) (v2, t2) = V.xor v1 v2, T.logor t1 t2

let core_sub_add op (v1, t1) (v2, t2) =
  let v', b = op v1 v2      in
  let t'    = T.logor t1 t2 in
  if b then
    (* overflow is propagated to tainting *)
    (v', t'), Some (V.ONE, t')
  else
    (v', t'), None
		   
let add (v1, t1) (v2, t2) = core_sub_add V.add (v1, t1) (v2, t2)
 
let sub (v1, t1) (v2, t2) = core_sub_add V.sub (v1, t1) (v2, t2)
							     
(* be careful: never reduce during widening *)
let widen (v1, t1) (v2, t2) = V.widen v1 v2, T.widen t1 t2
						     
let to_string (v, _t) = V.to_string v
				    
let string_of_taint (_v, t) = T.to_string t
					  
let default = V.default, T.default
			   
let untaint (v, t) = v, T.untaint t

let compare (v1, _t1) op (v2, _t2) = V.compare v1 op v2

let one = V.ONE, T.U
let is_one (v, _t) = v = V.ONE 
			    
let zero = V.ZERO, T.U
let is_zero (v, _t) = v = V.ZERO
	      
let subset (v1, _t1) (v2, _t2) = V.subset v1 v2
					  
let of_value z =
  if Z.compare z Z.zero = 0 then
    V.ZERO, T.U
  else 
    if Z.compare z Z.one = 0 then
      V.ONE, T.U
    else
      V.TOP, T.U
	       
let taint_of_value z (v, _t) =
  let t' =
  if Z.compare Z.zero z = 0 then T.U
  else
    if Z.compare Z.one z = 0 then T.T
    else T.TOP
  in
  v, t'
	       
let lognot (v, t) = V.lognot v, t

let lt (v1, _t1) (v2, _t2) = V.lt v1 v2

let logor (v1, t1) (v2, t2) = V.join v1 v2, T.join t1 t2
let logand (v1, t1) (v2, t2) = V.meet v1 v2, T.join t1 t2

