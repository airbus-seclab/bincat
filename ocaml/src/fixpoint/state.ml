module type T = sig
 type t
  (** abstract state data type *)
 type address
 type lval
 type exp

  val contains: t -> t -> bool
  (** [contains s1 s2] returns true whenever _s1_ contains _s2_ *)
    
  val make: unit -> t
  (** creates an initial state with top value *)    
    
  val forget: t -> t
  (** returns Top *)
    
  val is_top: t -> bool
(** returns true whenever its argument is top *)
    
  val set: address -> lval -> exp -> t -> t
(** function transfert of the assignment *)

  val widen: t -> t -> t
(** widening *)

  val guard: t -> exp -> t
(** restricts the given abstract state to values that satisfy then given expression *)

  val exp_to_addresses: t -> exp -> address list
(** returns the list of addresses corresponding to the given expression *)
end

module M(Dom: Domain.T)(Data: Data.T)(Asm: Asm.T with type address = Data.Address.t and type word = Data.Word.t) = 
struct
  module Dom = Dom(Data)(Asm)
  module M   = MapOpt.Make(Data.Address)
  
  type t = { 
    state: Dom.t;   (* current state *)
    map: Dom.t M.t (* a Map from addresses to abstract values *)
  }
  
  type address = Data.Address.t
  type lval = Asm.lval
  type exp = Asm.exp

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
