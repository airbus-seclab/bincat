(******************************************************************************)
(* Functor generating common functions of unrelational abstract domains       *)
(* basically it is a map from Registers/Memory cells to abstract values       *)
(******************************************************************************)

(** Unrelational domain signature *)
module type T =
  sig
    (** abstract data type *)
    type t

    (** bottom value *)
    val bot: t

    (** comparison to bottom *)
    val is_bot: t -> bool

    (** returns true whenever at least one bit of the parameter may be tainted. False otherwise *)
    val is_tainted: t -> bool
			   
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
    (** the size of the value is given by the int parameter *)
    (** the option parameter is the previous init value *)
    val taint_of_config: Data.Address.region -> Config.tvalue -> int -> t option -> t
				       
    (** join two abstract values *)
    val join: t -> t -> t

    (** meet the two abstract values *)
    val meet: t -> t -> t

    (** widen the two abstract values *)
    val widen: t -> t -> t
			   
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

    (** [untaint v] untaint v *)
    val untaint: t -> t
			
    (** [taint v] taint v *)
    val taint: t -> t

    (** [weak_taint v] weak taint v *)
    val weak_taint: t -> t

    (** default value. The integer is the size in bits of the dimension to initialise *)
    val default: int -> t

    (** returns the sub value between bits l and u *)
    val extract: t -> int -> int -> t
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

    (** type of the Map from Dimension (register or memory) to abstract values *)
    type t     =
      | Val of D.t Map.t
      | BOT
				     
    let bot = BOT

    let is_bot m = m = BOT
			 
    let value_of_register m r =
      match m with
      | BOT    -> raise Exceptions.Concretization
      | Val m' ->
	 try
	   let v = Map.find (K.R r) m' in D.to_value v
	 with _ -> raise Exceptions.Concretization
					 
    let add_register r m =
      let add m' =
	Val (Map.add (K.R r) (D.default (Register.size r)) m')
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
      | Val m' -> Val (Map.add (K.R r) D.top m')
      | BOT -> BOT
		 
    let subset m1 m2 =
      match m1, m2 with
      | BOT, _ 		 -> true
      | _, BOT 		 -> false
      |	Val m1', Val m2' ->
	 try Map.for_all2 D.subset m1' m2'
	 with _ ->
	   try 
	     Map.iteri (fun k v1 -> try let v2 = Map.find k m2' in if not (D.subset v1 v2) then raise Exit with Not_found -> ()) m1';
	     true
	   with Exit -> false
			  
    let to_string m =
      match m with
      |	BOT    -> ["_"]
      | Val m' -> Map.fold (fun k v l -> ((K.to_string k) ^ " = " ^ (D.to_string v)) :: l) m' []

    let string_of_register m r =
      match m with
      | BOT -> "_"
      | Val m' -> Printf.sprintf "%s = %s" (Register.name r) (D.to_string (Map.find (K.R r) m'))

(** computes the value read from a set of consecutive values in the map around address a *) 
    let build_value m a sz =
      let rec search i =
	if i >= !Config.operand_sz then raise Not_found
	else
	  let a' = Data.Address.add_offset a (Z.of_int i) in
	  if Map.mem (K.M a') m then a'
	  else search (i+1)
      in
      try
	(* 1. find the key k in the map that address a belongs to *)
	(* it is such that k <= a <= k+Config.operand_sz *)
	let k  = search 0				                in
	(* 2. we compute from key k the word starting at address k and of length sz *)
	let u  = !Config.operand_sz - (Z.to_int (Data.Address.sub a k)) in
	let m0 = D.extract (Map.find (K.M k) m) 0 (u-1)                 in
	let o  = !Config.operand_sz / 8			                in
	let rec build i sz =
	  if sz <= 0 then m0
	  else
	    let a  = Data.Address.add_offset k (Z.of_int (i*o))   		   in
	    let m1 = Map.find (K.M a) m		       				   in
	    let m1'= D.extract m1 ((!Config.operand_sz)-sz) (!Config.operand_sz-1) in
	    let m2 = build (i+1) (sz-(!Config.operand_sz))			   in
	    (* m2 + (m1' << Config.operand_sz) *)
	    D.binary Asm.Add m2 (D.binary Asm.Shl m1' (D.of_word (Data.Word.of_int (Z.of_int (!Config.operand_sz)) sz)))
	in
	build o (sz-u)
	with Not_found -> D.bot
	  
			  
    (** evaluates the given expression *)
    let eval_exp m e =
      let rec eval e =
	match e with
	| Asm.Const c 			     -> D.of_word c
	| Asm.Lval (Asm.V (Asm.T r)) 	     -> 
	   begin
	     try Map.find (K.R r) m
	     with Not_found -> D.bot
	   end
	| Asm.Lval (Asm.V (Asm.P (r, l, u))) ->
	   begin
	     try
	       let v = Map.find (K.R r) m in
	       D.extract v l u
	     with
	     | Not_found -> D.bot
	   end
	| Asm.Lval (Asm.M (e, n))            ->
	   begin
	     try
	       let r = eval e in
	       let addresses = Data.Address.Set.elements (D.to_addresses r) in
	       let rec to_value a =
		 match a with
		 | [a]  ->
		    build_value m a n
		 | a::l ->
		    D.join (build_value m a n) (to_value l)
		 | []   -> raise Exceptions.Bot_deref
	       in
	       to_value addresses
	     with
	     | Exceptions.Enum_failure               -> D.top
	     | Not_found | Exceptions.Concretization ->
			    Log.from_analysis (Printf.sprintf "undefined memory dereference [%s]: analysis stops in that context" (Asm.string_of_exp e));
			    raise Exceptions.Bot_deref
	   end
	     
	| Asm.BinOp (Asm.Xor, Asm.Lval (Asm.V (Asm.T r1)), Asm.Lval (Asm.V (Asm.T r2))) when Register.compare r1 r2 = 0 && Register.is_stack_pointer r1 ->
	   D.of_config Data.Address.Stack (Config.Content Z.zero) (Register.size r1)
		       
	| Asm.BinOp (Asm.Xor, Asm.Lval (Asm.V (Asm.T r1)), Asm.Lval (Asm.V (Asm.T r2))) when Register.compare r1 r2 = 0 ->
	   D.untaint (D.of_word (Data.Word.of_int (Z.zero) (Register.size r1)))

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


    (** [update_taint strong m e v] (weak-)taint v if at least one bit of one of the registers in e is tainted *)
    (** the taint is strong when the boolean strong is true ; weak otherwise *)
    let weak_taint m e v =
      let rec process e =
	match e with
	| Asm.Lval (Asm.V (Asm.T r)) | Asm.Lval (Asm.V (Asm.P (r, _, _))) -> let r' = Map.find (K.R r) m in if D.is_tainted r' then raise Exit else ()
	| Asm.BinOp (_, e1, e2) 			 -> process e1; process e2
	| Asm.UnOp (_, e') 				 -> process e'
	| _ 					 -> ()
      in
      try
	begin
	  match e with
	  | Asm.Lval (Asm.M (e', _)) -> process e'
	  | _ -> ()
	end;
	v
      with Exit -> D.weak_taint v

    
			  
    let set dst src m =
      match m with
      |	BOT    -> BOT
      | Val m' ->
	 let v' = eval_exp m' src in
	 let v' = weak_taint m' src v' in 
	 if D.is_bot v' then
	   BOT
	 else
	   match dst with
	   | Asm.V r ->
	      begin
		match r with
		| Asm.T r' -> Val (Map.add (K.R r') v' m')
		| Asm.P (r', l, u) ->
		   try
		     let prev = Map.find (K.R r') m' in
		     Val (Map.replace (K.R r') (D.combine prev v' l u) m')
		   with
		     Not_found -> BOT
	      end
	   | Asm.M (e, _n) ->
	      let addrs = D.to_addresses (eval_exp m' e) in
	      let l     = Data.Address.Set.elements addrs in
	      match l with 
	      | [a] -> (* strong update *) Val (Map.add (K.M a) v' m')
	      | l   -> (* weak update   *) Val (List.fold_left (fun m a ->  try let v = Map.find (K.M a) m' in Map.replace (K.M a) (D.join v v') m with Not_found -> Map.add (K.M a) v' m)  m' l)
					       
					       
    let join m1 m2 =
      match m1, m2 with
      | BOT, m | m, BOT  -> m
      | Val m1', Val m2' ->
	 try Val (Map.map2 D.join m1' m2')
	 with _ ->
	      let m = Map.empty in
	      let m' = Map.fold (fun k v m -> Map.add k v m) m1' m in
	      Val (Map.fold (fun k v m -> try let v' = Map.find k m1' in Map.replace k (D.join v v') m with Not_found -> Map.add k v m) m2' m')
	     
	      
	   
    let meet m1 m2 =
      match m1, m2 with
      | BOT, _ | _, BOT  -> BOT
      | Val m1', Val m2' -> Val (Map.map2 D.meet m1' m2')

    let widen m1 m2 =
      match m1, m2 with
      | BOT, m | m, BOT  -> m
      | Val m1', Val m2' ->
	 try Val (Map.map2 D.widen m1' m2')
	 with _ ->
	   let m = Map.empty in
	   let m' = Map.fold (fun k v m -> Map.add k v m) m1' m in
	   Val (Map.fold (fun k v m -> try let v' = Map.find k m1' in let v2 = try D.widen v' v with _ -> D.top in Map.replace k v2 m with Not_found -> Map.add k v m) m2' m')
	  
		  
    let init () = Val (Map.empty)

    let set_register_from_config r region c m =
      match m with
      | BOT    -> BOT
      | Val m' ->
	 let v' = D.of_config region c (Register.size r) in
	 Val (Map.add (K.R r) v' m')
			       
    let set_memory_from_config a region c m =
      match m with
      | BOT    -> BOT
      | Val m' ->
	 let v' = D.of_config region c !Config.operand_sz in
	 Val (Map.add (K.M a) v' m')

    let taint_from_config dim sz region c m =
      match m with
      | BOT -> BOT
      | Val m' ->
	 let prev =
	   try Some (Map.find dim m')
	   with Not_found -> None
	 in
	 let v' = D.taint_of_config region c sz prev in
	 Val (Map.add dim v' m')
			       
    let taint_memory_from_config a region c m = taint_from_config (K.M a) !Config.operand_sz region c m 
    
    let taint_register_from_config r region c m = taint_from_config (K.R r) (Register.size r) region c m

    
    let val_restrict m e1 _v1 cmp _e2 v2 =
	match e1, cmp with
	| Asm.Lval (Asm.V (Asm.T r)), cmp when cmp = Asm.EQ || cmp = Asm.LEQ ->
	     let v  = Map.find (K.R r) m in
	     let v' = D.meet v v2        in
	     if D.is_bot v' then
	       raise Exceptions.Empty
	     else
	       Map.replace (K.R r) v' m
	| _, _ -> m
		
    let compare m (e1: Asm.exp) op e2 =
      match m with
      | BOT -> BOT
      | Val m' ->
	 let v1 = eval_exp m' e1 in
	 let v2 = eval_exp m' e2 in
	 if D.is_bot v1 || D.is_bot v2 then
	   BOT
	 else
	 if D.compare v1 op v2 then
	   try
	     Val (val_restrict m' e1 v1 op e2 v2)
	   with Exceptions.Empty -> BOT
	 else
	   BOT
		 
    let value_of_exp m e =
      match m with
      | BOT -> raise Exceptions.Concretization
      | Val m' -> D.to_value (eval_exp m' e)
			   
  end: Domain.T)
    
