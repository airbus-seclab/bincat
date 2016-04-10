(******************************************************************************)
(* Functor generating common functions of unrelational abstract domains       *)
(* basically it is a map from Registers/Memory cells to abstract values       *)
(******************************************************************************)

(** Unrelational domain signature *)
module type T =
  sig
    (** abstract data type *)
    type t

    (** name of the abstract domain *)
    val name: string

    (** bottom value *)
    val bot: t

    (** comparison to bottom *)
    val is_bot: t -> bool
		       
    (** top value *)
    val top: t
	       
    (** conversion to values of type Z.t *)
    val to_value: t -> Z.t

    (** converts a word into an abstract value *)
    val of_word: Data.Word.t -> t
				
    (** comparison *)
    (** returns true whenever the concretization of the first parameter is included in the concretization of the second parameter *)
    val subset: t -> t -> bool
			      
    (** string conversion *)
    val to_string: t -> string

    (** value generation from configuration *)
    (** the size of the value is given by the int parameter *)
    val of_config: Data.Address.region -> Config.cvalue -> int -> t

    (** returns the tainted value corresponding to the given abstract value *)
    val taint_of_config: Config.tvalue -> t
				       
    (** join two abstract values *)
    val join: t -> t -> t

    (** meet the two abstract values *)
    val meet: t -> t -> t

    (** [extract v l u] return v[l, u] *)
    val extract: t -> int -> int -> t
				      
    (** [combine v1 v2 l u] computes v1[l, u] <- v2 *)
    val combine: t -> t -> int -> int -> t 

    (** converts an abstract value into a set of concrete adresses *)
    val to_addresses: t -> Data.Address.Set.t

    (** [binary op v1 v2] return the result of v1 op v2 *)
    val binary: Asm.binop -> t -> t -> t

    (** [unary op v] return the result of (op v) *)
    val unary: Asm.unop -> t -> t
				  
    (** binary comparison *)
    val compare: t -> Asm.cmp -> t -> bool

    (** [untainted_value n] return an untainted value of size n *)
    val untainted_value: int -> t
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
				     

    let name = D.name		      
    let bot = BOT
		
    let value_of_register m r =
      match m with
      | BOT    -> raise Exceptions.Concretization
      | Val m' ->
	 try
	   let v, _ = Map.find (K.R r) m' in D.to_value v
	 with _ -> raise Exceptions.Concretization
					 
    let add_register v m =
      let add m' =
	Val (Map.add (K.R v) (D.bot, 0) m')
      in
      match m with
      | BOT    -> add Map.empty
      | Val m' -> add m'
	 
    let remove_register v m =
      match m with
      | Val m' -> Val (Map.remove (K.R v) m')
      | BOT    -> BOT

    let forget r m =
      match m with
      | Val m' ->
	 let r' = K.R r in
	 Val (try let _, n = Map.find r' m' in Map.replace r' (D.top, n) m' with _ -> Map.add r' (D.top, 0) m')
      | BOT -> BOT
		 
    let subset m1 m2 =
      match m1, m2 with
      | BOT, _ 		 -> true
      | _, BOT 		 -> false
      |	Val m1', Val m2' -> Map.for_all2 (fun v1 v2 -> D.subset (fst v1) (fst v2)) m1' m2'

    let to_string m =
      match m with
      |	BOT    -> ["?"]
      | Val m' -> Map.fold (fun k v l -> ((D.name ^" "^K.to_string k) ^ " = " ^ (D.to_string (fst v))) :: l) m' []

    (** evaluates the given expression *)
    let eval_exp m e =
      let rec eval e =
	match e with
	| Asm.Const c 			     -> D.of_word c
	| Asm.Lval (Asm.V (Asm.T r)) 	     ->
	   begin
	     try fst (Map.find (K.R r) m)
	     with Not_found ->
	       match D.name with
	       | "Tainting" -> D.untainted_value (Register.size r)
	       | _ 	    -> D.bot
	   end
	| Asm.Lval (Asm.V (Asm.P (_r, _l, _u))) -> D.top (* can be more precise *)
	| Asm.Lval (Asm.M (e, _n))            ->
	   begin
	     try
	       let addresses = Data.Address.Set.elements (D.to_addresses (eval e)) in
	       let rec to_value a =
		 match a with
		 | a::l -> D.join (fst (Map.find (K.M a) m)) (to_value l)
		 | [] -> D.bot
	       in
	       to_value addresses
	     with
	     | Exceptions.Enum_failure -> D.top
	     | Exceptions.Empty        -> D.bot
	   end
	| Asm.BinOp (Asm.Xor, Asm.Lval (Asm.V (Asm.T r1)), Asm.Lval (Asm.V (Asm.T r2))) when Register.compare r1 r2 = 0 ->
	   begin
	     match D.name with
	     | "Tainting" -> D.untainted_value (Register.size r1)
	     | _ 	  -> D.of_word (Data.Word.of_int (Z.zero) (Register.size r1))
	   end
	| Asm.BinOp (op, e1, e2) -> D.binary op (eval e1) (eval e2)
	| Asm.UnOp (op, e) 	 -> D.unary op (eval e)
      in
      eval e

    let mem_to_addresses m e =
      match m with
      | BOT -> raise Exceptions.Enum_failure
      | Val m' ->
	 try D.to_addresses (eval_exp m' e)
	 with _ -> raise Exceptions.Enum_failure
			 
    let set dst src c m =
      match m with
      |	BOT    -> BOT
      | Val m' ->
	 let v' = eval_exp m' src in
	 match dst with
	 | Asm.V r ->
	    begin
	      match r with
	      | Asm.T r' ->
		 begin
		   try
		     let _prev, n = Map.find (K.R r') m' in
		     Val (Map.replace (K.R r') (v', n+1) m')
		   with
		     Not_found -> Val (Map.add (K.R r') (v', 1) m')
		 end
	      | Asm.P (r', l, u) ->
		 try
		   let prev, n = Map.find (K.R r') m' in
		   Val (Map.replace (K.R r') (D.combine prev v' l u, n+1) m')
		 with
		   Not_found -> raise Exceptions.Empty
	    end
	 | Asm.M (e, _n) ->
	    begin
	      let addrs = 
		match D.name with
		| "Ptr" ->
		   D.to_addresses (eval_exp m' e)
		| _ -> c#mem_to_addresses e 
	      in
	      let l  	= Data.Address.Set.elements addrs     in
	      match l with 
	      | [a] -> (* strong update *) Val (try let _v, n = Map.find (K.M a) m' in Map.replace (K.M a) (v', n+1) m' with Not_found -> Map.add (K.M a) (v', 0) m')
	      | l   -> (* weak update   *) Val (List.fold_left (fun m a ->  try let v, n = Map.find (K.M a) m' in Map.replace (K.M a) (D.join v v', n+1) m with Not_found -> Map.add (K.M a) (v', 0) m)  m' l)
	    end

						  
    let join m1 m2 =
      match m1, m2 with
      | BOT, m | m, BOT  -> m
      | Val m1', Val m2' -> Val (Map.map2 (fun (v1, n1) (v2, n2) -> D.join v1 v2, max n1 n2) m1' m2')

    let meet m1 m2 =
      match m1, m2 with
      | BOT, _ | _, BOT  -> BOT
      | Val m1', Val m2' -> Val (Map.map2 (fun (v1, n1) (v2, n2) -> D.meet v1 v2, max n1 n2) m1' m2')
				
    let init () = Val (Map.empty)

    let set_register_from_config r region c m =
      match D.name with
      |	"Tainting" -> m
      | _          -> 
	 match m with
	 | BOT    -> BOT
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

    (* let process_fun _f _m' = 
      let registers, memories = f (new ctx m') in
      let m' = List.fold_left (fun m' (r, v) -> try let _, n = Map.find (K.R r) m' in Map.replace (K.R r) (v, n) m' with Not_found -> Map.add (K.R r) (v, 0) m') m' registers in
      List.fold_left (fun m' (a, v) -> let _, n = Map.find (K.M a) m' in try Map.replace (K.M a) (v, n) m' with Not_found -> Map.add (K.M a) (v, 0) m') m' memories *)
	     
    let enter_fun _m _f = raise (Exceptions.Error "Unrel.enter_fun")
     	
    let leave_fun _m = raise (Exceptions.Error "Unrel.leave_fun")
    
    let val_restrict m e1 _v1 cmp _e2 v2 =
      if D.name = "Ptrs" then 
	match e1, cmp with
	| Asm.Lval (Asm.V (Asm.T r)), cmp when cmp = Asm.EQ || cmp = Asm.LEQ ->
	   let v, n = Map.find (K.R r) m in
	   let v'   = D.meet v v2        in
	   if D.is_bot v' then
	     raise Exceptions.Empty
	   else
	     Map.replace (K.R r) (v', n) m
	| _, _ -> m
		  
      else
	(* identity is a sound default case *)
	m
		
    let compare m (e1: Asm.exp) op e2 =
      match m with
      | BOT -> BOT
      | Val m' ->
	 let v1 = eval_exp m' e1 in
	 let v2 = eval_exp m' e2 in
	 if D.compare v1 op v2 then
	   try
	     Val (val_restrict m' e1 v1 op e2 v2)
	   with Exceptions.Empty -> BOT
	 else
	   BOT

    let value_of_exp m e =
      match m with
      | BOT -> raise Exceptions.Empty
      | Val m' -> D.to_value (eval_exp m' e)
			   
  end: Domain.T)
    
