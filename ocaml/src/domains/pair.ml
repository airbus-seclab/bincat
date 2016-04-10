module Make(D1: Domain.T)(D2: Domain.T) =(
struct

  type t    = D1.t * D2.t
  let name  = Printf.sprintf "( %s x %s)" D1.name D2.name
 
  let subset (v11, v12) (v21, v22)            	= D1.subset v11 v21 && D2.subset v12 v22
  let to_string (v1, v2)                      	= (D1.to_string v1) @ (D2.to_string v2)
  let add_register r (v1, v2) 		      	= D1.add_register r v1                , D2.add_register r v2
  let remove_register r (v1, v2)     	      	= D1.remove_register r v1             , D2.remove_register r v2
  let taint_register_from_config r c (v1, v2) 	= D1.taint_register_from_config r c v1, D2.taint_register_from_config r c v2
  let taint_memory_from_config a c (v1, v2)   	= D1.taint_memory_from_config a c v1  , D2.taint_memory_from_config a c v2
  let set dst src c (v1, v2)        	        = D1.set dst src c v1                 , D2.set dst src c v2
  let join (v11, v12) (v21, v22)              	= D1.join v11 v21                     , D2.join v12 v22
  let meet (v11, v12) (v21, v22)              	= D1.meet v11 v21                     , D2.meet v12 v22
  let set_memory_from_config a r c (v1, v2)     = D1.set_memory_from_config a r c v1  , D2.set_memory_from_config a r c v2
  let set_register_from_config a r c (v1, v2)   = D1.set_register_from_config a r c v1, D2.set_register_from_config a r c v2
  let init ()    			      	= D1.init ()                          , D2.init ()
  let bot 					= D1.bot                              , D2.bot 
  let enter_fun (v1, v2) f                    	= D1.enter_fun v1 f                   , D2.enter_fun v2 f
  let leave_fun (v1, v2)                      	= D1.leave_fun v1                     , D2.leave_fun v2
  let compare (v1  , v2) e1 c e2 		= D1.compare v1 e1 c e2               , D2.compare v2 e1 c e2
  let forget r (v1 , v2) 			= D1.forget r v1                      , D2.forget r v2

  (** two exceptions used for internal purpose of mem_to_addresses *)
  exception Mem_v1
  exception Mem_v2 of Data.Address.Set.t
				
  let mem_to_addresses (v1, v2) m =
    try
      let a1' = try D1.mem_to_addresses v1 m with Exceptions.Enum_failure -> raise Mem_v1       in
      let a2' = try D2.mem_to_addresses v2 m with Exceptions.Enum_failure -> raise (Mem_v2 a1') in
	  Data.Address.Set.inter a1' a2'
    with
    | Mem_v1 -> D2.mem_to_addresses v2 m
    | Mem_v2 a1' -> a1'

  (** two exceptions used for internal purpose of to_value *)
  exception Cr_v1
  exception Cr_v2 of Z.t

  let value_of_register (v1, v2) r =
    try
      let v1' = try D1.value_of_register v1 r with _ -> raise Cr_v1       in
      let v2' = try D2.value_of_register v2 r with _ -> raise (Cr_v2 v1') in
      if Z.equal v1' v2' then v1' else raise Exceptions.Concretization
    with
    | Cr_v1    -> D2.value_of_register v2 r
    | Cr_v2 v1'-> v1'			   

  let value_of_exp (v1, v2) e =
    try
      let v1' = try D1.value_of_exp v1 e with _ -> raise Cr_v1 in
      let v2' = try D2.value_of_exp v2 e with _ -> raise (Cr_v2 v1') in
      if Z.equal v1' v2' then v1' else raise Exceptions.Concretization
    with
    | Cr_v1    -> D2.value_of_exp v2 e
    | Cr_v2 v1'-> v1'			   
end: Domain.T)
