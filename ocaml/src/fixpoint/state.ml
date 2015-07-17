(**************************************************************************************************************************)
(* State module *)
(**************************************************************************************************************************)
(** signature of the abstract store (addresses, assembly language, etc.) *)
module type Store =
  sig
    type address
    type exp
    type asm
  end
    
module M(Store: Store) = 
struct
  module Dom = Dom(Store.Data)(Store.Asm)
  module M   = Map.Make(Data.Address)
  
  type t = { 
    state: Dom.t;   (* current state *)
    map: Dom.t M.t (* a Map from addresses to abstract values *)
  }
  
  class context d =
  object
    method mem_to_addresses m sz = Dom.mem_to_addresses m sz d
  end

  let make ()     	 = { state = Dom.make() ; map = M.empty }
  let exp_to_addresses s e = 
    match Dom.exp_to_addresses s.state e with
      None -> raise Utils.Enum_failure
    | Some s -> Data.Address.Set.elements s

  let contains s1 s2 	 = M.for_all2 Dom.contains s1.map s2.map
  let forget _s      	 = { state = Dom.make() ; map = M.empty }
  let is_top s 	     	 = s.map = M.empty 
  let widen s1 s2 	 = { state = Dom.widen s1.state s2.state ; map = M.concat s1.map s2.map }
  let set a lv e s 	 =
    let c = new context s.state in
    match lv with
      Asm.V r -> 
	let d' = Dom.set_register r e c s.state in
	{ state = d' ; map = M.replace a d' s.map }
    | Asm.M (m, sz) -> 
      let d' = Dom.set_memory m sz e c s.state in
      { state = d' ; map = M.replace a d' s.map }
  let guard _s _e = failwith "State.guard: to implement"
end

module Make = M(Pair.Make(Ptr.M)(Tainting.M))
