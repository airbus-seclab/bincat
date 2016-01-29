(******************************************************************************)
(* Functor generating common functions of unrelational abstract domains       *)
(* basically it is a map from Registers to abstract values                    *)
(******************************************************************************)

(** internal oracle used by non functional domains (see signature T below) *)
(** to pick up information from functional domain (ie functor Unrel.Make)  *)
class type ['v] ctx_t =
  object

    (** returns the abstract value associated to the given register *)
    method get_val_from_register: Register.t -> 'v

    (** returns the abstract value associated to the given address *)
    method get_val_from_memory  : Data.Address.t -> 'v
end

(** Unrelational domain signature *)
module type T =
  sig
    (** abstract data type *)
    type t

    (** name of the abstract domain *)
    val name: string

    (** bottom value *)
    (** the integer parameter is the size in bits to return *)
    val bot: int -> t
	       
    (** comparison *)
    (** returns true whenever the concretization of the first paramater is included in the concretization of the second parameter *)
    val subset: t -> t -> bool
			      
    (** string conversion *)
    val to_string: t -> string

    (** value generation from configuration *)
    (** the size of the value is given by the int parameter *)
    val of_config: Data.Address.region -> Config.cvalue -> int -> t
			       
    (** returns the evaluation of the given expression as an abstract value *)			    
    val eval_exp: Asm.exp -> int -> Domain.oracle -> t ctx_t -> t
												  
    (** returns the set of addresses associated to the memory expression of size _n_ where _n_ is the integer parameter *)
    (** may raise an exception if this set of addresses is too large *)									  
    (** never call the method ctx_t.to_addresses in this function *)
    val mem_to_addresses: Asm.exp -> int -> t ctx_t -> Data.Address.Set.t
   
										    
								   
    (** returns the tainted value corresponding to the given abstract value *)
    val taint_of_config: Config.tvalue -> t
				       
    (** join two abstract values *)
    val join: t -> t -> t
			  
    (** [combine v1 v2 l u] computes v1[l, u] <- v2 *)
    val combine: t -> t -> int -> int -> t 

    (** transfer function when the given function is entered *)
    val enter_fun: Asm.fct -> t ctx_t -> (Register.t * t) list * (Data.Address.t * t) list
								    
			  
    (** tranfer function when the current function is returned *)
    val leave_fun: t ctx_t -> (Register.t * t) list * (Data.Address.t * t) list
  end
		  
		  
module Make(D: T) = 
  (struct
		   
    module K = 
      struct
	type t = 
	  | R of Register.t
	  | M of Data.Address.t
		   	   
	let compare v1 v2 = 
	  match v1, v2 with
	  | R r1, R r2 -> Register.compare r1 r2
	  | M m1, M m2 -> Data.Address.compare m1 m2
	  | R _ , _    -> 1
	  | _   , _    -> -1
			     
	let to_string x = 
	  match x with 
	  | R r -> "reg [" ^ (Register.name r) ^ "]"
	  | M a -> "mem [" ^ (Data.Address.to_string a) ^ "]"
      end
	      
    module Map = MapOpt.Make(K)

    (** type of the Map from Dimension (register or memory) to abstract values. *)
    (**This contains also an upper bound of the number of times the given dimension has been already set *)
    type t     =
      | Val of (D.t * int) Map.t
      | BOT
				     
		       
    class ['addr, 'v] ctx m =
    object
      method get_val_from_register r = ((fst (Map.find (K.R r) m)): 'v)
      method get_val_from_memory a   = ((fst (Map.find (K.M a) m)): 'v)
    end
      
    let name = D.name		      
		    
    let mem_to_addresses mem sz m =
      match m with
      | Val m' -> D.mem_to_addresses mem sz (new ctx m')
      | BOT    -> raise (Exceptions.Enum_failure (Printf.sprintf "Unrel.Make(%s)" D.name, "mem_to_addresses"))
	 
    let add_register v m =
      let add m' =
	Val (Map.add (K.R v) (D.bot (Register.size v), 0) m')
      in
      match m with
      | BOT    -> add Map.empty
      | Val m' -> add m'
	 
    let remove_register v m =
      match m with
      | Val m' -> Val (Map.remove (K.R v) m')
      | BOT    -> BOT
		    
    let subset m1 m2 =
      match m1, m2 with
      | BOT, _ 		 -> true
      | _, BOT 		 -> false
      |	Val m1', Val m2' -> Map.for_all2 (fun v1 v2 -> D.subset (fst v1) (fst v2)) m1' m2'

    let to_string m =
      match m with
      |	BOT    -> ["?"]
      | Val m' -> Map.fold (fun k v l -> ((D.name ^" "^K.to_string k) ^ " = " ^ (D.to_string (fst v))) :: l) m' []
				   
    let set dst src c m =
      match m with
      |	BOT    -> BOT
      | Val m' ->
	 match dst with
	 | Asm.V r ->
	    begin
	      match r with
	      | Asm.T r' 	    ->
		 let v' = D.eval_exp src (Register.size r') c (new ctx m') in
		 let _, n = Map.find (K.R r') m' in
		 Val (Map.replace (K.R r') (v', n+1) m')
	      | Asm.P (r', l, u) ->
		 let v' = D.eval_exp src (u-l+1) c (new ctx m') in
		 let v2, n = Map.find (K.R r') m' in
		 Val (Map.replace (K.R r') (D.combine v' v2 l u, n+1) m')
	    end

	 | Asm.M (e, n) -> 
		let addrs = D.mem_to_addresses e n (new ctx m') in		
		let l  	  = Data.Address.Set.elements addrs     in
		let v' 	  = D.eval_exp src n c (new ctx m')     in
		match l with 
		| [a] -> (* strong update *) Val (try let _, n = Map.find (K.M a) m' in Map.replace (K.M a) (v', n+1) m' with Not_found -> Map.add (K.M a) (v', 0) m')
		| l   -> (* weak update   *) Val (List.fold_left (fun m a ->  try let v, n = Map.find (K.M a) m' in Map.replace (K.M a) (D.join v v', n+1) m with Not_found -> Map.add (K.M a) (v', 0) m)  m' l)


						  
    let join m1 m2 =
      match m1, m2 with
      | BOT, m | m, BOT -> m
      | Val m1', Val m2' -> Val (Map.map2 (fun (v1, n1) (v2, n2) -> D.join v1 v2, max n1 n2) m1' m2')

		       
    let init () = Val (Map.empty)

    let set_register_from_config r region c m =
      match D.name with
      |	"Tainting" -> m
      | _          -> 
	 match m with
	 | BOT -> BOT
	 | Val m' ->
	    let v' = D.of_config region c (Register.size r) in

	    try
	      Val (Map.replace (K.R r) (v', 0) m')
	    with Not_found -> Val (Map.add (K.R r) (v', 0) m')

    let set_memory_from_config a region c m =
       match D.name with
      |	"Tainting" -> m
      | _          -> 
	 match m with
	 | BOT    -> BOT
 	 | Val m' ->
	    let v' = D.of_config region c !Config.operand_sz in
	    try
	      Val (Map.replace (K.M a) (v', 0) m')
	    with Not_found -> Val (Map.add (K.M a) (v', 0) m')
				  
    let taint_memory_from_config a c m =
      match D.name with
      | "Tainting" ->
	 begin
	   (* we choose that tainting the memory has no effect on the dimension that counts the number of times it has been set *)
	   match m with
	   | BOT -> BOT
	   | Val m' ->
	      let v' = D.taint_of_config c in
	      try
		Val (Map.replace (K.M a) (v', 0) m')
	      with Not_found -> Val (Map.add (K.M a) (v', 0) m')
	 end
      | _         -> m

    let taint_register_from_config r c m =
      if String.compare D.name "Tainting" = 0 then
	   (* we choose that tainting a register has no effect on the dimension that counts the number of times it has been set *)
	   match m with
	     BOT    -> BOT
	   | Val m' ->
	      let v' = D.taint_of_config c in
	      try
		Val (Map.replace (K.R r) (v', 0) m')
	      with Not_found -> Val (Map.add (K.R r) (v', 0) m')
      else
	m

    let process_fun f m' =
      let registers, memories = f (new ctx m') in
      let m' = List.fold_left (fun m' (r, v) -> try let _, n = Map.find (K.R r) m' in Map.replace (K.R r) (v, n) m' with Not_found -> Map.add (K.R r) (v, 0) m') m' registers in
      List.fold_left (fun m' (a, v) -> let _, n = Map.find (K.M a) m' in try Map.replace (K.M a) (v, n) m' with Not_found -> Map.add (K.M a) (v, 0) m') m' memories
	     
    let enter_fun m f =
      match m with
      | BOT    -> BOT
      | Val m' -> Val (process_fun (D.enter_fun f) m')
	

    let leave_fun m =
      match m with
      | BOT    -> BOT
      | Val m' -> Val (process_fun D.leave_fun m')
	 
  end: Domain.T)
    
