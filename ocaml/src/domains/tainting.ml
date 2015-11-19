(******************************************************************************)
(* Functor generating the unrelational abstract domain of data tainting       *)
(******************************************************************************)

(** immediate source of the current tainting (in the CFA) *)
module ISrc =
  struct
    type s =
      | R of Register.t  (** source of tainting is a register *)
      | M of D.Address.t (** source of tainting is a memory address *)
      | F of string      (** source of tainting is a function *)

    (** data type for the source. None is used to represent that the source is the dimension itself (root of the tainting) *)
    type t = s option
	       
    (** returns true whenever origins are equal *)
    let equal p1 p2 =
      match p1, p2 with
      | None, None 	  -> true
      | None, _ | _, None -> false
      | Some s1, Some s2  ->
	 match s1, s2 with
	   R v1, R v2 -> Register.compare v1 v2 = 0
	 | M a1, M a2 -> D.Address.equal a1 a2
	 | F f1, F f2 -> String.compare f1 f2 = 0
	 | _, _       -> false
			   
    let to_string s =
      match s with
	None 	-> "_"
      | Some s' -> 
	 match s with
	 | R r -> Register.to_string r
	 | M a -> D.Address.to_string a
	 | F f -> f
  end

(** tainting of a bit vector *)
module Taint =
  struct
    (** data type of a bit *)
    type btaint = 
      | Untainted (** untainted *)
      | Tainted   (** tainted *)
      | Maybe 	  (** top *)

    let bjoin b1 b2 =
      match b1, b2 with
      | b, b' when b=b' -> b
      | _, _            -> Maybe

    type t = o array 
	       
    let equal t1 t2 = Array.for_all2 (=) t1 t2
    let join t1 t2 = Array.mapi (fun i v1 -> bjoin v1 v2.(i) v1
  end
    

				 module Value = Set.Make (struct type t = BTaint.t * ISrc.t * int (* the integer is the position in the immediate src *) let equal (t1, s1, p1) (t2, s2, p2) = BTaint.equal t1 t2 && ISrc.equal s1 s2 & p1 = p2 end)



module Make(Asm: Asm.T) =
  (** all binary operations are supposed to compute on operands of the same size *)
struct
  module Asm = Asm

  (** tainting data type represents the set of possible tainting values and immediate origins of a given dimension *)
  type t = Value.t

  let name 		 = "Data Tainting"
			     
  (** initially everything is untainted *)
  let bot sz             = Array.make sz BTaint.Untainted
				      
  let is_top v 		 = Array.for_all (fun v -> v = BTaint.Maybe) v
  
  let taint_from_config v =
      match v with
      | Config.Bits b -> Array.copy b

      | Config.MBits (b, m) ->
	 let t = Array.copy b in
	 for i=0 to !Context.address_sz-1 do
	 if String.get m i = '1' then t.(i) <- Tainted;
	 done;
	 t

 
	   
  let join v1 v2 = Array.mapi (fun i v1 -> BTaint.join v1 v2.(i)) v1
   

  let for_all2 f v1 v2 =
    let len1 = Array.length v1 in
    let len2 = Array.length v2 in
      try
	if len1 <> len2 then raise Exit;
	for i = 0 to len1-1 do
	  if not (f v1.(i) v2.(i)) then raise Exit
	done;
	true
      with Exit -> false

  let equal v1 v2 = Value.equal
  
  let contains v1 v2 = Value.subset v2 v1 

  let to_string v =
    let s = ref "" in
    let src_to_string (b, s, p) =
    in
    Value.fold (fun s v -> s := (src_to_string v) ^ (!s)) v


  let mem_to_addresses _e _sz _c = raise Utils.Enum_failure
  let exp_to_addresses _e _c = raise Utils.Enum_failure

  let eval_exp e (c: (Asm.exp, Asm.Address.Set.t) Domain.context) ctx: t =
    match e with
      Asm.Lval (Asm.V (Asm.T r)) -> ctx#get_val_from_register r
    | Asm.Lval (Asm.V (Asm.P (r, l, u))) -> 
		  let e = ctx#get_val_from_register r in
		  begin
		    match e with
		      None -> None
		    | Some a -> Some (Array.sub a l (u+1))
		  end
    | Asm.Lval (Asm.M (m, sz)) -> 
      let addr = c#mem_to_addresses m sz in
      begin
	match addr with
	  None 	     -> None
	| Some addr' -> 
	  try
	    let addr_l = Asm.Address.Set.elements addr'		  in
	    let v      = ctx#get_val_from_memory (List.hd addr_l) in 
	    List.fold_left (fun s a -> join s ( ctx#get_val_from_memory a )) v (List.tl addr_l)
	  with _ -> raise Utils.Emptyset
	end
  
    | Asm.Const c      -> Some (Array.make (Asm.Word.size c) Safe) 
    | _ 	     -> None

  let combine v1 v2 l u = 
    match v1, v2 with
      Some v1', Some v2' ->
	let n = min u (Array.length v1') in
	let v = Array.make n Safe in
	for i = 0 to n-1 do
	  if i >= l && i<= u then
	    v.(i) <- v2'.(i)
	  else
	    v.(i) <- v1'.(i)
	done;
	Some v
    | _, _ -> None (* note that the case Some v, None should never occurs as l and u are supposed to be indices in v2 hence a top value for v2 has to be of the form Some v2' with all cells equal to top *)


end


