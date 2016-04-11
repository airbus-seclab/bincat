(******************************************************************************)
(* Functor generating the unrelational abstract domain of data tainting       *)
(******************************************************************************)

    (** basically a tainting abstract value is a vector of bits *)
    (** the bit domain is implemented as the sub module Bit (see below) *)
    (** binary operations are supposed to process on bit vector of the same size *)

    
  (** abstract type of a bit *)
  module Bit =
    struct
      (** data type *)
      type t =
	| T   (** bit is tainted *)
	| U   (** bit is untainted *)
	| TOP (** top *)
	| BOT (** bottom (undef) *)
		       
      let subset b1 b2 =
	match b1, b2 with
	| T, T | U, U -> true
	| _, TOP      -> true
	| BOT, _      -> true
	| _, _ 	      -> false

      let join b1 b2 =
	match b1, b2 with
	| T, T 	          -> T
	| U, U 	 	  -> U
	| BOT, b | b, BOT -> b
	| _, _ 	 	  -> TOP

      let meet b1 b2 =
	match b1, b2 with
	| T, T 		  -> T
	| U, U 		  -> U
	| b, TOP | TOP, b -> b
	| _, _ 		  -> BOT
		    
      let to_string b =
	match b with
	| TOP -> "?"
	| BOT -> "_"
	| T   -> "1"
	| U   -> "0"

      let equal b1 b2 = b1 = b2
    end

  (** abstract type of a tainting bit vector *)
  type t =
    | BOT
    | TOP
    | Val of (Bit.t array)

  let name = "Tainting" (* be sure that if this name changes then Unrel.taint_from_config is updated *)

  let to_value _v = raise Exceptions.Concretization

  let to_addresses _v = raise Exceptions.Enum_failure
				    
  let val_make sz = Array.make sz Bit.U (* BE CAREFUL: by default initialization by Untainted rather than usual BOT for other domains *)

  let make sz = Val (val_make sz)
		    
  let bot = BOT
  let is_bot v = v = BOT
  let top = TOP
			  
  (* iterators on bit vectors *)
  (* remember that binary iterators are supposed to proceed on vector of the same length *)

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
    with _ -> false

  let val_subset v1 v2 = for_all2 Bit.subset v1 v2

  let subset v1 v2 =
    match v1, v2 with
    | BOT, _ | _, TOP   -> true
    | TOP, _ | _, BOT   -> false
    | Val v1', Val v2' 	-> val_subset v1' v2'

  let val_map2 f v1 v2 =
    let n1 = Array.length v1 in
    let n2 = Array.length v2 in
    let n = if n1 <= n2 then n1 else n2 in
    let v = val_make n in
    for i = 0 to n-1 do
      v.(i) <- f v1.(i) v2.(i)
    done;
    v
    
  let val_join v1 v2 = val_map2 Bit.join v1 v2

  let join v1 v2 =
    match v1, v2 with
    | BOT, v | v, BOT  -> v
    | _, TOP | TOP, _  -> TOP
    | Val v1', Val v2' -> Val (val_join v1' v2')
			      
  let val_meet v1 v2 = val_map2 Bit.meet v1 v2

  let meet v1 v2 =
    match v1, v2 with
    | BOT, _ | _, BOT -> BOT
    | TOP, v | v, TOP -> v
    | Val v1', Val v2' -> Val (val_meet v1' v2')
			      
  let taint_of_config v =
    match v with
    | Config.Bits b ->
       let sz = String.length b in
       let t  = val_make sz     in
       for i = 0 to sz-1 do
	 if String.get b i = '1' then
	   t.(i) <- Bit.T
	 else
	   t.(i) <- Bit.U
       done;
       Val t
	 
    | Config.MBits (b, m) ->
       let sz = String.length b in
       let t  = val_make sz     in
	 for i=0 to sz-1 do
	   if String.get m i = '1' then
	     t.(i) <- Bit.TOP
	   else
	     if String.get b i = '1' then
	      t.(i) <- Bit.T
	   else
	     t.(i) <- Bit.U
	 done;
	 Val t
   
  let to_string v =
    match v with
    | BOT    -> "_"
    | TOP    -> "?"
    | Val v' ->
      let s = Array.fold_left (fun s b -> s ^ (Bit.to_string b)) "" v' in
      Printf.sprintf ("%s") (String.sub s 0 (String.length s))

 let of_word c = make (Data.Word.size c)
		  
 let of_config _r _c sz = make sz

 let val_equal v1 v2 =
   let n1 = Array.length v1 in
   let n2 = Array.length v2 in
   if n1 = n2 then
     try
       for i = 0 to n1-1 do
	 if not (Bit.equal v1.(i) v2.(i)) then
	   raise Exit
       done;
       true
     with Exit 	 -> false
   else
     false
       
 let equal v1 v2 =
   match v1, v2 with
   | BOT, BOT | TOP, TOP -> true
   | Val v1', Val v2' 	 -> val_equal v1' v2'
   | _, _ 		 -> false
	       
 let binary op v1 v2 =
   match v1, v2 with
   | BOT, _ | _, BOT  -> BOT
   | TOP, _ | _, TOP  -> TOP
   | Val v1', Val v2' -> 
      match op with
      | Asm.Xor when val_equal v1' v2' -> Val (Array.make (Array.length v1') Bit.U)
      | Asm.And 		       -> meet v1 v2
      | _ 			       -> join v1 v2 (* sound but could be more precise *)


 let unary op v =
   match v with
   | BOT | TOP -> v
   | Val v' ->
      match op with
      | Asm.Not -> Val v'
      | Asm.SignExt n ->
	 let sz = Array.length v' in
	 if sz >= n then v
	 else
	   let vext = val_make n in
	   let o = n-sz in
	   for i=1 to sz-1 do
	     vext.(i+o) <- v'.(i);
	   done;
	   (* set the sign bit *)
	   vext.(0) <- v'.(0);
	   Val vext
      | Asm.Shr nb ->
	 begin
	   let sz = Array.length v' in
	   try
	     let v = val_make (sz-nb) in
	     for i = nb to sz-nb-1 do
	       v.(i+nb) <- v'.(i)
	     done;
	     Val v
	   with _ -> TOP
	 end
      | Asm.Shl nb ->
	 begin
	   let sz = Array.length v' in
	   try
	     let v = val_make (sz-nb) in
	     for i = nb to sz-1 do
	       v.(i-nb) <- v'.(i)
	     done;
	     Val v
	   with _ -> TOP	      
	 end
	   
  let enter_fun _f _ctx = raise (Exceptions.Error "Tainting.enter_fun: to implement")

  let leave_fun _ctx = raise (Exceptions.Error "Tainting.leave_fun: to implement")
      
  let combine v1 v2 l u =
    match v1, v2 with
    | TOP, _ | _, TOP | _, BOT | BOT, _ -> TOP
    | Val v1', Val v2' ->
    try
       let n = Array.length v1' in
       let v = val_make n       in
       for i = 0 to l-1 do
	 v.(i) <- v1'.(i)
       done;
       for i = u+1 to n-1 do
	 v.(i) <- v1'.(i)
       done;
       for i = l to u do
	 v.(i) <- Bit.join v1'.(i) v2'.(i)
       done;
       Val v
    with _ -> TOP

  let untainted_value sz = make sz
				
  let extract _ _ _ = TOP
  let compare  _v1 _op _v2 = true
		  
   
