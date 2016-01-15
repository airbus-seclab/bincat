(******************************************************************************)
(* Functor generating the unrelational abstract domain of data tainting       *)
(******************************************************************************)

    (** basically a tainting abstract value is a vector of bits *)
    (** the bit domain is implemented as the sub module Bit (see below) *)
    (** binary operations are supposed to process on bit vector of the same size *)

 
  (** abstract type of the source of (un)tainting of a bit *)
  (** we keep only trace of the immediate source of tainting (the complete trace may be recovered by iterating on pathes in the CFA *)
  module Src =
  struct
    type s =
      | INPUT 	       (** source is the dimension itself *)
      | Fun of string  (** source is a function (see the parsing of the configuration file) *)
      | Exp of Asm.exp (** source is an assembly expression *) 
		 
    (** data type for the source *)
    type t =
      | TOP
      | Val of s

    let join s1 s2 =
      match s1, s2 with
      |	Val (Exp e1), Val (Exp e2) -> if Asm.equal_exp e1 e2 then s1 else TOP
      | Val (Fun f1), Val (Fun f2) -> if f1 = f2 then s1 else TOP
      | Val INPUT, Val INPUT 	   -> s1
      | _, _ 			   -> TOP
		  
    (** subset *)			  
    (** returns true whenever the concretization of the first parameter is a subset of the concretization of the second parameter *)
    (** false otherwise *)
    let subset s1 s2 =
      match s1, s2 with
      | Val (Exp e1), Val (Exp e2) -> Asm.equal_exp e1 e2
      | Val (Fun f1), Val (Fun f2) -> f1 = f2
      | Val INPUT, Val INPUT 	   -> true
      | _, TOP 	       		   -> true
      | _, _  	       		   -> false

    let to_string s =
      match s with
      | Val (Exp e) -> Asm.string_of_exp e
      | Val (Fun f) -> f
      | Val INPUT   -> "INPUT"
      | TOP         -> "T"
end
    
  (** abstract type of a bit *)
  module Bit =
    struct
      (** data type *)
      type t =
	| BOT 		     (** uninitialized tainting value *)
	| Tainted of Src.t   (** bit is tainted. Its immediate source is the paramater of the constructor *)
	| Untainted of Src.t (** bit is untainted. Its immediate source is the parameter of the constructor *)
	| TOP 		     (** top *)
		       
      let subset b1 b2 =
	match b1, b2 with
	| Tainted s1, Tainted s2     -> Src.subset s1 s2
	| Untainted s1, Untainted s2 -> Src.subset s1 s2
	| BOT, _ 	      	     -> true
	| _, TOP 	      	     -> true
	| _, _ 		      	     -> false

      let join b1 b2 =
	match b1, b2 with
	| BOT, b
	| b, BOT 		     -> b
	| Tainted s1, Tainted s2     -> Tainted (Src.join s1 s2)
	| Untainted s1, Untainted s2 -> Untainted (Src.join s1 s2)
	| _, _ 			     -> TOP
					    
      let to_string b =
	match b with
	| BOT 	      -> "_|_"
	| TOP 	      -> "T"
	| Tainted s   -> Printf.sprintf "1(%s)" (Src.to_string s)
	| Untainted s -> Printf.sprintf "0(%s)" (Src.to_string s)
    end

  (** abstract type of a tainting bit vector *)
  type t =
    | BOT
    | Val of Bit.t array

  let name = "Tainting" (* be sure that if this name changes then Unrel.taint_from_config is updated *)

  let bot = BOT
	      
  (* iterators on bit vectors *)
  (* remember that binary iterators are supposed to proceed on vector of the same length *)
  let map2 f v1 v2 =
    let n = Array.length v1 in
    let v = Array.make n Bit.BOT in
    for i = 0 to n-1 do
      v.(i) <- f v1.(i) v2.(i)
    done;
    v

  let for_all p v =
    try
      for i = 0 to (Array.length v) - 1 do
	if not (p v.(i)) then raise Exit
      done;
      true
    with Exit -> false

  let for_all2 p v1 v2 =
    let n = Array.length v1 in
    try
      for i = 0 to n - 1 do
	if not (p v1.(i) v2.(i)) then raise Exit
      done;
      true
    with Exit -> false

  let subset v1 v2 =
    match v1, v2 with
    | BOT, _ 	       -> true
    | _, BOT 	       -> false
    | Val v1, Val v2 -> for_all2 Bit.subset v1 v2
			
  let join v1 v2 =
    match v1, v2 with
    | BOT, v | v, BOT -> v
    | Val v1, Val v2  -> Val (map2 Bit.join v1 v2)
 
  let taint_of_config v =
    match v with
    | Config.Bits b ->
       let sz = String.length b       in
       let t  = Array.make sz Bit.BOT in
       for i = 0 to sz-1 do
	 if String.get b i = '1' then
	   t.(i) <- Bit.Tainted (Src.Val Src.INPUT)
	 else
	   t.(i) <- Bit.Untainted (Src.Val Src.INPUT)
       done;
       Val t
	 
    | Config.MBits (b, m) ->
       let sz = String.length b       in
       let t  = Array.make sz Bit.BOT in
	 for i=0 to sz-1 do
	   if String.get m i = '1' then
	     t.(i) <- Bit.TOP
	   else
	     if String.get b i = '1' then
	      t.(i) <- Bit.Tainted (Src.Val Src.INPUT)
	   else
	     t.(i) <- Bit.Untainted (Src.Val Src.INPUT)
	 done;
	 Val t
   
 let to_string v =
   match v with
   | BOT    -> "_|_"
   | Val v  -> Array.fold_left (fun s b ->  s ^ (Bit.to_string b)) "" v

 let of_config _c = BOT

  let mem_to_addresses _e _sz _c = raise Utils.Enum_failure
  let exp_to_addresses _e _sz _c = raise Utils.Enum_failure

  let rec eval_exp e sz (c: (Asm.exp, Data.Address.Set.t) Domain.context) ctx: t = 
    match e with
    | Asm.Lval (Asm.V (Asm.T r)) ->
       ctx#get_val_from_register r
							      
    | Asm.Lval (Asm.V (Asm.P (r, l, u))) -> 
       let e = ctx#get_val_from_register r in
       begin
	 match e with
	 | BOT   -> BOT
	 | Val v -> Val (Array.sub v l (l-u+1))
       end
	 
    | Asm.Lval (Asm.M (m, sz)) -> 
      let addr = c#mem_to_addresses m sz in
      begin
	match addr with
	  None 	     -> BOT
	| Some addr' -> 
	  try
	    let addr_l = Data.Address.Set.elements addr'	  in
	    let v      = ctx#get_val_from_memory (List.hd addr_l) in 
	    List.fold_left (fun s a -> join s ( ctx#get_val_from_memory a )) v (List.tl addr_l)
	  with _ -> BOT
      end

    | Asm.BinOp (Asm.Xor, e1, e2) when Asm.equal_exp e1 e2 -> Val (Array.make sz (Bit.Untainted ((Src.Val (Src.Exp e)))))
					 
    | Asm.BinOp (Asm.Add, e1, e2) | Asm.BinOp (Asm.Sub, e1, e2) | Asm.BinOp (Asm.Mul, e1, e2) | Asm.BinOp (Asm.Div, e1, e2) | Asm.BinOp (Asm.Divs, e1, e2) | Asm.BinOp (Asm.And, e1, e2) | Asm.BinOp (Asm.Or, e1, e2) | Asm.BinOp (Asm.Xor, e1, e2)  | Asm.BinOp(Asm.Mod, e1, e2) ->
       begin
       let v1 = eval_exp e1 sz c ctx in
       let v2 = eval_exp e2 sz c ctx in
       	 match v1, v2 with
	 | BOT, v | v, BOT -> v
	 | Val v1, Val v2 ->
	    let v = Array.make sz Bit.BOT in
	    for i = 0 to sz-1 do
	      v.(i) <-
		begin
		  match v1.(i), v2.(i) with 
		  | Bit.Untainted _, Bit.Untainted _ 				     -> Bit.Untainted (Src.Val (Src.Exp e))
		  | Bit.Tainted _, Bit.Tainted _ 				     -> Bit.Tainted (Src.Val (Src.Exp e))
		  | Bit.Tainted _, Bit.Untainted _ | Bit.Untainted _, Bit.Tainted _  -> Bit.Tainted (Src.Val (Src.Exp e))
		  | Bit.BOT, Bit.Tainted _ | Bit.Tainted _, Bit.BOT 		     -> Bit.Tainted (Src.Val (Src.Exp e))
		  | Bit.BOT, Bit.Untainted _ | Bit.Untainted _, Bit.BOT 	     -> Bit.Untainted (Src.Val (Src.Exp e)) (* by default unitialized tainted value is Untainted *)
		  | Bit.TOP, Bit.Tainted _ | Bit.Tainted _, Bit.TOP 		     -> Bit.Tainted (Src.Val (Src.Exp e))
		  | Bit.TOP, _ | _, Bit.TOP 					     -> Bit.TOP
		  | Bit.BOT, Bit.BOT 						     -> Bit.BOT
		end
	    done;
	    Val v
       end


    | Asm.BinOp (Asm.Shl, _e1, _e2) -> failwith "Tainting.eval_exp: shl not implemented"

    | Asm.BinOp (Asm.Shr, _e1, _e2) -> failwith "Tainting.eval_exp: shr not implemented"

    | Asm.BinOp (Asm.Shrs, _e1, _e2) -> failwith "Tainting.eval_exp: shrs not implemented"
						 
    | Asm.BinOp _ -> failwith "Tainting.eval_exp: boolean binary operators not implemented"
						 
    | Asm.UnOp _ -> failwith "Tainting.eval_exp: unop not implemented"
  
    | Asm.Const c      -> Val (Array.make (Data.Word.size c) (Bit.Untainted (Src.Val Src.INPUT)))


  let enter_fun _f _ctx = failwith "Tainting.enter_fun: to implement" 

  let leave_fun _ctx = failwith "Tainting.leave_fun: to implement"
      
  let combine v1 v2 l u =
    match v1, v2 with
    | BOT, _ | _, BOT -> BOT
    | Val v1, Val v2 ->
    let n = Array.length v1 in
    let v = Array.make n Bit.BOT in
    for i = 0 to l-1 do
      v.(i) <- v1.(i)
    done;
    for i = u+1 to n-1 do
      v.(i) <- v1.(i)
    done;
    for i = l to u do
      v.(i) <- v2.(i)
    done;
    Val v


				    

		  
   
