module Make(Dom1: Domain.T)(Dom2: Domain.T)(Data: Data.T)(Asm:Asm.T with type address = Data.Address.t and type word = Data.Word.t) =
struct
  module D1 = Dom1(Data)(Asm)
  module D2 = Dom2(Data)(Asm)
  type t    = D1.t * D2.t
  let name  = "(" ^ D1.name ^ " x " ^ D2.name ^ ")"
 
  let contains (v11, v12) (v21, v22)    = D1.contains v11 v21 && D2.contains v12 v22
  let to_string (v1, v2)                = (D1.to_string v1) @ (D2.to_string v2)
 
  let make () 			     	= D1.make ()                   , D2.make ()
  let forget (v1, v2) 		     	= D1.forget v1                 , D2.forget v2
  let remove_register r (v1, v2)     	= D1.remove_register r v1      , D2.remove_register r v2
  let set_register r e c (v1, v2)    	= D1.set_register r e c v1     , D2.set_register r e c v2
  let taint_register r (v1, v2)      	= D1.taint_register r v1       , D2.taint_register r v2
  let taint_memory a (v1, v2)        	= D1.taint_memory a v1         , D2.taint_memory a v2
  let set_memory dst sz src c (v1, v2)  = D1.set_memory dst sz src c v1, D2.set_memory dst sz src c v2
  let widen (v11, v12) (v21, v22)       = D1.widen v11 v21             , D2.widen v12 v22

  let mem_to_addresses m sz (v1, v2) =
    match D1.mem_to_addresses m sz v1, D2.mem_to_addresses m sz v2 with
      None, a | a, None  -> a
    | Some a1', Some a2' -> Some (Data.Address.Set.inter a1' a2')

  let exp_to_addresses (v1, v2) e =
 (* TODO factorize with mem_to_addresses *)
    match D1.exp_to_addresses v1 e, D2.exp_to_addresses v2 e with
      None, a | a, None  -> a
    | Some a1', Some a2' -> Some (Data.Address.Set.inter a1' a2')
end
