(******************************************************************************)
(* Functor generating the unrelational abstract domain of data tainting       *)
(******************************************************************************)


(** auxilary module in charge of keeping path information about the source of tainting *)
module Src(D: Asm.T) =
struct 
  type src =
    R  of Register.t
  | M  of D.Address.t

  type t = 
    Leaf
  | Path of src * t 
  | Or	 of t * t 

  let equal_src s1 s2 = 
    match s1, s2 with
	R v1, R v2 -> Register.compare v1 v2 = 0
      | M a1, M a2 -> D.Address.equal a1 a2 
      | _, _       -> false

  let rec equal t1 t2 =
    match t1, t2 with
      Or (l1, r1), Or (l2, r2)     -> equal l1 l2 && equal r1 r2
    | Path (v1, t1), Path (v2, t2) -> equal_src v1 v2 && equal t1 t2
    | Leaf, Leaf 		   -> true
    | _, _ 			   -> false

  let join t1 t2 = Or (t1, t2)

  let singleton s = Path (s, Leaf)

  let rec contains t1 t2 =
    match t1, t2 with
	Leaf, Leaf 		     -> true
      | Leaf, _ 		     -> false
      | Or _, Leaf 		     -> true
      | Or (l, r), Path _ 	     -> contains l t2 || contains r t2
      | Path _, Leaf 		     -> true
      | Or (l1, r1), Or (l2, r2)     -> contains l1 l2  && contains r1 r2
      | Path (v1, t1), Path (v2, t2) -> equal_src v1 v2 && contains t1 t2
      | Path _, _ 		     -> false

  let string_of_src s =
    match s with
      R r  -> Register.to_string r
    | M a  -> D.Address.to_string a

  let rec to_string t =
    match t with
      Leaf 	  -> ""
    | Or (t1, t2) -> (to_string t1) ^ "\n or\n" ^ (to_string t2) 
    | Path (v, t) -> (string_of_src v) ^ " -> " ^ (to_string t)
end

module Make(Asm: Asm.T) =
struct
  module S = Src(Asm)
  module Asm = Asm
  type o = 
      Safe
    | Tainted of S.t 
    | Maybe   of S.t option

  type t = o array option (** None is Top *)
  (** Note that there are several Top : None and an array whose every cell contains Maybe None. Keep it as they are more precise : you know at least the size of the Top value (the length of the array) *)

  let name 		 = "Data Tainting"
  let top 		 = None
  let is_top v 		 = v = None
  let taint_register r = Some (Some (Array.make (Register.size r) (Tainted (S.singleton (S.R r)))))
  let taint_memory a = Some (Some (Array.make (Asm.Address.size a) (Tainted (S.singleton(S.M a)))))
 
  let join v1 v2 =
    let join_b b1 b2 =
      match b1, b2 with
	Safe, Safe 				  -> Safe
      | Tainted s1, Tainted s2 when S.equal s1 s2 -> b1
      | Tainted s1, Tainted s2 			  -> Tainted (S.join s1 s2) 
      | Safe	, Tainted s 
      | Tainted s	, Safe 			  -> Tainted s
      | Maybe (Some s1)	, Maybe (Some s2)
      | Maybe (Some s1)    , Tainted s2
      | Tainted s1, Maybe (Some s2) 		  -> Maybe (Some (S.join s1 s2)) 
      | _		, Maybe s	
      | Maybe s     , _		                  -> Maybe s
    in
    match v1, v2 with
      None, _ | _, None -> None
    | Some v1, Some v2  ->
      let len1 	 = Array.length v1				  in
      let len2 	 = Array.length v2				  in
      let m, len = if len1 < len2 then len1, len2 else len2, len1 in
      let v 	 = Array.make len (Maybe None)			  in
      for i = 0 to m-1 do
	v.(i) <- join_b v1.(i) v2.(i)
      done;
      Some v

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

  let equal v1 v2 = 
    let equal_b b1 b2 =
      match b1, b2 with
	Tainted s1     , Tainted s2 
      | Maybe (Some s1), Maybe (Some s2) -> S.equal s1 s2
      | Maybe None     , Maybe None 	 -> true
      | Safe	       , Safe 	       	 -> true
      | _	       , _ 	       	 -> false
    in
    match v1, v2 with
      Some v1', Some v2' -> for_all2 equal_b v1' v2'
    | None    , None 	 -> true
    | _	      , _ 	 -> false

  let contains v1 v2 =
    let contains_b b1 b2 =
      match b1, b2 with
	Safe	       , Safe       	 -> true
      | Safe	       , _ 	       	 -> false
      | Tainted _      , Safe       	 -> true
      | Tainted s1     , Tainted s2 
      | Maybe (Some s1), Maybe (Some s2) -> S.contains s1 s2
      | Maybe _	       , _ 	       	 -> true
      | _	       , _ 	       	 -> false
    in
    match v1, v2 with
      Some v1', Some v2' -> for_all2 contains_b v1' v2'
    | None    , _ 	 -> true
    | _       , _ 	 -> false

  let to_string v =
    let to_string_b b =
      match b with
	Safe      	   -> "Safe"
      | Tainted s 	   -> "Tainted from " ^ ( S.to_string s )
      | Maybe (Some s)     -> "Tainted from " ^ ( S.to_string s ) ^ "?"
      | Maybe None 	   -> "Tainted ?"
    in
    match v with
      None    -> "Tainted ?"
    | Some v' -> 
      let s = ref "" in
      Array.iteri (fun i b -> s := !s ^ (string_of_int i)^"->"^(to_string_b b)) v';
      !s


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


