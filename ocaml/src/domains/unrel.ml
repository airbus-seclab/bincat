(******************************************************************************)
(* Functor generating unrelational abstract domains                           *)
(* basically it is a map from Registers to abstract values                    *)
(******************************************************************************)

(** context *)
class type ['addr, 'v] ctx_t =
  object

    (** returns the abstract value associated to the given register *)
    method get_val_from_register: Register.t -> 'v

    (** returns the abstract value associated to the given address *)
    method get_val_from_memory  : 'addr -> 'v
end

(** Unrelational domain signature *)
module type T = sig

    module Asm: Asm.T

    (** abstract data type *)
    type t
	   
    (** name of the abstract domain *)
    val name: string
		
    (** top abstract value *)
    val top: t
	      
			      
    (** equality comparison : returns true whenever the two arguments are logically equal *)
    val equal: t -> t -> bool
		         
    (** order comparison : returns true whenever the first argument is greater than the second one *)
    val contains: t -> t -> bool
			      
    (** string conversion *)
    val to_string: t -> string
			  
    (** returns the evaluation of the given expression as an abstract value *)			    
    val eval_exp: Asm.exp -> (Asm.exp, Asm.Address.Set.t) Domain.context -> (Asm.Address.t, t) ctx_t -> t
												  
    (** returns the set of addresses associated to the memory expression of size _n_ where _n_ is the integer parameter *)
    val mem_to_addresses: Asm.exp -> int -> (Asm.Address.t, t) ctx_t -> Asm.Address.Set.t option
    (** None is Top *)										  
    (** never call the method ctx_t.to_addresses in this function *)
										    
    (** returns the set of addresses associated to the given expression *)											  
    val exp_to_addresses: Asm.exp -> (Asm.Address.t, t) ctx_t -> Asm.Address.Set.t option 
									     
    (** taint the given register into the given abstract value *)
    val taint_register: Register.t -> t option
    (** None means that this functionality is not handled *)
					
    (** taint the given address into the given abstract value *)
    val taint_memory: Asm.Address.t -> t option
    (** None means that this functionality is not handled *)
				       
    (** join two abstract values *)
    val join: t -> t -> t
			  
    (** [combine v1 v2 l u] computes v1[l, u] <- v2 *)
    val combine: t -> t -> int -> int -> t 
					   
    (** widens two abstract values *)
    val widen: t -> t -> t
  end
		  
		  
module Make(D: T) = 
  struct

    module Asm = D.Asm
		   
    module K = 
      struct
	type t = 
	  | R of Register.t
	  | M of Asm.Address.t
		   	   
	let compare v1 v2 = 
	  match v1, v2 with
	  | R r1, R r2 -> Register.compare r1 r2
	  | M m1, M m2 -> Asm.Address.compare m1 m2
	  | R _ , _    -> 1
	  | _   , _    -> -1
			     
	let to_string x = 
	  match x with 
	  | R r -> Register.to_string r
	  | M a -> Asm.Address.to_string a
      end
	      
    module Map = MapOpt.Make(K)

    (** type of the Map from Dimension (register or memory) to abstract values. This contains also an upper bound of the number of times a dimension has been already set *)
    type t     = (D.t * int) Map.t
				     
		       
    class ['addr, 'v] ctx m =
    object
      method get_val_from_register r = ((fst (Map.find (K.R r) m)): 'v)
      method get_val_from_memory a   = ((fst (Map.find (K.M a) m)): 'v)
    end
      
    let name 			  = D.name
    let make () 		  = Map.empty
    let forget s 		  = Map.map (fun v -> D.top, (snd v)+1) s
    let mem_to_addresses mem sz m = D.mem_to_addresses mem sz (new ctx m)
    let exp_to_addresses m e 	  = D.exp_to_addresses e (new ctx m)
    let remove_register v m 	  = Map.remove (K.R v) m	
    let contains m1 m2 		  = Map.for_all2 (fun v1 v2 -> D.equal (fst v1) (fst v2)) m1 m2
    let to_string m 		  = Map.fold (fun k v l -> ((K.to_string k) ^" -> " ^ (D.to_string (fst v))) :: l) m []
					   
    let set_register r e c m = 
      let v = D.eval_exp e c (new ctx m) in
      match r with
      |	Asm.T r' 	       ->
	 let _, n = Map.find (K.R r') m in
	 Map.replace (K.R r') (v, n+1) m
      | Asm.P (r', l, u) -> 
	 let v2, n = Map.find (K.R r') m in
	 Map.replace (K.R r') (D.combine v v2 l u, n+1) m
		     
    let taint_register r m   =
      (* we choose that tainting a register has no effect on the dimension that counts the number of times it has been set *)
      match D.taint_register r with
      | Some v -> let _, n = Map.find (K.R r) m in Map.replace (K.R r) (v, n) m
      | None   -> m
		  
    let taint_memory a m     =
      (* we choose that tainting the memory has no effect on the dimension that counts the number of times it has been set *)
      match D.taint_memory a with
      | Some v -> let _, n = Map.find (K.M a) m in Map.replace (K.M a) (v, n) m
      | None   -> m
		  
    let set_memory dst sz src c m = 
      let addr = c#mem_to_addresses dst sz in
      match addr with 
      |	None 	   -> raise (Alarm.E Alarm.Empty)
      | Some addrs ->
	 let v' = D.eval_exp src c (new ctx m) in 
	 let l  = Asm.Address.Set.elements addrs in
	 match l with 
	   [a] -> (* strong update *) let _, n = Map.find (K.M a) m in Map.replace (K.M a) (v', n+1) m
	 | l   -> (* weak update   *) List.fold_left (fun m a -> let v, n = Map.find (K.M a) m in Map.replace (K.M a) (D.join v v', n+1) m) m l
						     
    let widen m1 m2 = Map.map2 (fun (v1, n1) (v2, n2) -> D.widen v1 v2, max n1 n2) m1 m2
  end
    
