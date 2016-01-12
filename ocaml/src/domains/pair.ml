module Make(D1: Domain.T)(D2: Domain.T) =(
struct

  type t    = D1.t * D2.t
  let name  = Printf.sprintf "( %s x %s)" D1.name D2.name
 
  let subset (v11, v12) (v21, v22)            = D1.subset v11 v21 && D2.subset v12 v22
  let to_string (v1, v2)                      = (D1.to_string v1) @ (D2.to_string v2)
  let remove_register r (v1, v2)     	      = D1.remove_register r v1             , D2.remove_register r v2
  let set_register r e sz c (v1, v2)          = D1.set_register r e sz c v1         , D2.set_register r e sz c v2
  let taint_register_from_config r c (v1, v2) = D1.taint_register_from_config r c v1, D2.taint_register_from_config r c v2
  let taint_memory_from_config a c (v1, v2)   = D1.taint_memory_from_config a c v1  , D2.taint_memory_from_config a c v2
  let set_memory dst sz src c (v1, v2)        = D1.set_memory dst sz src c v1       , D2.set_memory dst sz src c v2
  let join (v11, v12) (v21, v22)              = D1.join v11 v21                     , D2.join v12 v22
  let set_memory_from_config a c (v1, v2)     = D1.set_memory_from_config a c v1    , D2.set_memory_from_config a c v2
  let set_register_from_config a c (v1, v2)   = D1.set_register_from_config a c v1  , D2.set_register_from_config a c v2
  let init ()    			      = D1.init ()                          , D2.init ()
  let enter_fun (v1, v2) f                    = D1.enter_fun v1 f                   , D2.enter_fun v2 f
  let leave_fun (v1, v2)                      = D1.leave_fun v1                     , D2.leave_fun v2
  let mem_to_addresses m sz (v1, v2) =
    try
      let a1' = D1.mem_to_addresses m sz v1 in
	try
	  let a2' = D2.mem_to_addresses m sz v2 in
	  Data.Address.Set.inter a1' a2'
	with
	  Utils.Enum_failure -> a1'
    with
      Utils.Enum_failure -> D2.mem_to_addresses m sz v2

  let exp_to_addresses e sz (v1, v2) =
    (* TODO factorize with mem_to_addresses *)
    try
      let a1' = D1.exp_to_addresses e sz v1 in
	try
	  let a2' = D2.exp_to_addresses e sz v2 in
	  Data.Address.Set.inter a1' a2'
	with
	  Utils.Enum_failure -> a1'
    with
      Utils.Enum_failure -> D2.exp_to_addresses e sz v2


end: Domain.T)
