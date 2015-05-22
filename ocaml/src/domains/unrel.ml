class type ['addr, 'v] ctx_t =
object
  method get_val_from_register: Register.t -> 'v
  method get_val_from_memory  : 'addr -> 'v
end

module type T =
    functor (D: Data.T) ->
      functor (Asm: Asm.T with type word = D.Word.t and type address = D.Address.t) -> sig 
      type t
      val name	          : string
      val top 	          : t
      val contains 	  : t -> t -> bool
      val equal    	  : t -> t -> bool
      val to_string	  : t -> string
      val eval_exp	  : Asm.exp -> (Asm.memory, D.Address.Set.t) Domain.context -> (D.Address.t, t) ctx_t -> t
      val mem_to_addresses: Asm.memory -> int -> (D.Address.t, t) ctx_t -> D.Address.Set.t option (** None is Top *)
      val exp_to_addresses: Asm.exp -> (D.Address.t, t) ctx_t -> D.Address.Set.t option (** None is Top *)
      val taint_register  : Register.t -> t option
      val taint_memory    : D.Address.t -> t option
      val join	          : t -> t -> t
      val combine         : t -> t -> int -> int -> t 
      val widen 	  : t -> t -> t
    end


module Make(V: T)(D:Data.T)(A:Asm.T with type address = D.Address.t and type word = D.Word.t) = 
struct
  module Dom = V(D)(A)
  module K = 
  struct
   
    type t = 
      R of Register.t
    | M of D.Address.t
	
	
    let compare v1 v2 = 
      match v1, v2 with
	R r1, R r2 -> Register.compare r1 r2
      | M m1, M m2 -> D.Address.compare m1 m2
      | R _ , _    -> 1
      | _   , _    -> -1
	
    let to_string x = 
      match x with 
	R r -> Register.to_string r
      | M a -> D.Address.to_string a
  end

  module Map = Dimension.Make(K)
  type t     = Dom.t Map.t

  class ['addr, 'v] ctx m =
  object
    method get_val_from_register r = (Map.find (K.R r) m: 'v)
    method get_val_from_memory a   = (Map.find (K.M a) m: 'v)
  end
    
  let name 		   	= Dom.name
  let make () 	   	   	= Map.empty
  let forget s 		   	= Map.map (fun _ -> Dom.top) s
  let mem_to_addresses mem sz m = Dom.mem_to_addresses mem sz (new ctx m)
  let exp_to_addresses m e      = Dom.exp_to_addresses e (new ctx m)
  let remove_register v m  	= Map.remove (K.R v) m	
  let contains m1 m2 	   	= Map.for_all2 Dom.contains m1 m2
  let to_string m 	   	= Map.fold (fun _ v l -> (Dom.to_string v) :: l) m []
  
  let set_register r e c m = 
    let v = Dom.eval_exp e c (new ctx m) in
    match r with
      A.T r' 	     -> Map.replace (K.R r') v m
    | A.P (l, u, r') -> 
      let v2 = Map.find (K.R r') m in
      Map.replace (K.R r') (Dom.combine v v2 l u) m

  let taint_register r m   = 
    match Dom.taint_register r with
      Some v -> Map.replace (K.R r) v m
    | None -> m

  let taint_memory a m     = 
    match Dom.taint_memory a with
      Some v -> Map.replace (K.M a) v m
    | None -> m
 
  let set_memory dst sz src c m = 
    let addr = c#mem_to_addresses dst sz in
    match addr with 
      None 	 -> raise (Alarm.E Alarm.Empty)
    | Some addrs ->
      let v' = Dom.eval_exp src c (new ctx m) in 
      let l  = D.Address.Set.elements addrs   in
      match l with 
	[a] -> (* strong update *) Map.replace (K.M a) v' m
      | l   -> (* weak update   *) List.fold_left (fun m a -> Map.update (K.M a) (Dom.join v') m) m l

  let widen _m1 _m2 = failwith "Unrel.widen: to implement"
end
