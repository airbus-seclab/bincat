(** vector lifting of a value_domain *)
(** binary operations are supposed to apply on operands of the same length *)

(** signature of value domain *)
module type Val =
  sig
    (** abstract data type *)
    type t
    (** bottom *) 
    val bot: t
    (** comparison to bottom *)
    val is_bot: t -> bool
    (** comparison to top *)
    val is_top: t -> bool
    (** default value *)
    val default: t
    (** conversion to value of type Z.t. May raise an exception *)
    val to_value: t -> Z.t
    (** conversion from Z.t value *)
    val of_value: Z.t -> t
    (** taint the given value from Z.t value *)
    val taint_of_value: Z.t -> t -> t
    (** abstract join *)
    val join: t -> t -> t
    (** abstract meet *)
    val meet: t -> t -> t
    (** string conversion *)
    val to_string: t -> string
    (** string conversion of the taint *)
    val string_of_taint: t -> string
    (** add operation. The optional return value is None when no carry *)
    (** occurs in the result and Some c with c the carry value otherwise *)
    val add: t -> t -> t * (t option)
    (** sub operation. The optional return value is None when no borrow *)
    (** occurs and Some b with b the borrow value otherwise *)
    val sub: t -> t -> t * (t option)
    (** xor operation *)
    val xor: t -> t -> t
    (** logical and *)
    val logand: t -> t -> t
    (** logical or *)
    val logor: t -> t -> t
    (** bit neg *)
    val neg: t -> t
    (** untaint *)
    val untaint: t -> t
    (** abstract value of 1 *)
    val one: t
    (** comparison to one *)
    val is_one: t -> bool
    (** abstract value of 0 *)
    val zero: t
    (** comparison to zero *)
    val is_zero: t -> bool
    (** strictly less than comparison *)
    val lt: t -> t -> bool
    (** check whether the first abstract value is included in the second one *)
    val subset: t -> t -> bool
    (** comparison *)
    val compare: t -> Asm.cmp -> t -> bool
  end
    
(** signature of vector *)
module type T =
  sig
    (** abstract data type *)
    type t
    (** default value *)
    val default: int -> t
    (** value conversion. May raise an exception *)
    val to_value: t -> Z.t
    (** abstract join *)
    val join: t -> t -> t
    (** abstract meet *)
    val meet: t -> t -> t
    (** string conversion *)
    val to_string: t -> string
    (** binary operation *)
    val binary: Asm.binop -> t -> t -> t
    (** unary operation *)
    val unary: Asm.unop -> t -> t
    (** untaint *)
    val untaint: t -> t
    (** conversion from word *)
    val of_word: Data.Word.t -> t
    (** comparison *)
    val compare: t -> Asm.cmp -> t -> bool
    (** conversion to a set of addresses *)
    val to_addresses: Data.Address.region -> t -> Data.Address.Set.t
    (** check whether the first argument is included in the second one *)
    val subset: t -> t -> bool
    (** conversion from a config value *)
    (** the integer parameter is the size in bits of the config value *)
    val of_config: Config.cvalue -> int -> t
    (** conversion from a tainting value *)
    (** the value option is a possible previous init *)
    val taint_of_config: Config.tvalue -> int -> t option -> t
    (** [combine v1 v2 l u] computes v1[l, u] <- v2 *)
    val combine: t -> t -> int -> int -> t
  end
    
module Make(V: Val) =
  (struct
    type t = V.t array (** bit order is little endian, ie v[0] is the most significant bit and v[Array.length v - 1] the least significant *) 

    let map2 f v1 v2 =
      let n = Array.length v1        in
      let v = Array.make n V.default in
      for i = 0 to n-1 do
	v.(i) <- f v1.(i) v2.(i)
      done;
      v

    let for_all2 p v1 v2 =
      try
	for i = 0 to (Array.length v1)-1 do
	  if not (p v1.(i) v2.(i)) then raise Exit
	done;
	true
      with Exit -> false

    let for_all p v =
      try
	for i = 0 to (Array.length v) -1 do
	  if not (p v.(i)) then raise Exit
	done;
	true
      with Exit -> false

    let exists p v =
      try
	for i = 0 to (Array.length v) - 1 do
	  if p v.(i) then raise Exit
	done;
	false
      with Exit -> true
    let join v1 v2 = map2 V.join v1 v2

    let meet v1 v2 = map2 V.meet v1 v2


    (* common utility to add and sub *)
    let core_add_sub op v1 v2 =
      let n = Array.length v1        in
      let v = Array.make n V.default in
      let carry_borrow = ref None in
      for i = 0 to n - 1 do
	let c = 
	  (* add the carry/borrow if present *)
	  match !carry_borrow with
	  | None -> None
	  | Some b' -> let b', c' = op v.(i) b' in v.(i) <- b'; c'
	in
	(* compute the ith bit of the result with the ith bit of the operand *)
	let b, c' = op v1.(i) v2.(i) in
	v.(i) <- b;
	(* update the new carry/borrow *)
	match c with
	| Some _ -> carry_borrow := c
	| None   -> carry_borrow := c' (* correct as we know that we cannot have both cpred = Some ... and c' = Some ... *)
      done;
      v
	     
    let add v1 v2 = core_add_sub V.add v1 v2
    let sub v1 v2 = core_add_sub V.sub v1 v2

    let xor v1 v2 = map2 V.xor v1 v2
    let logand v1 v2 = map2 V.logand v1 v2
    let logor v1 v2 = map2 V.logor v1 v2

			   
    let zero_extend v n =
      let n' = Array.length v in
      if n <= n' then
	v
      else
	let o  = n - n'              in
	let v' = Array.make n V.zero in
	for i = 0 to n'-1 do
	  v'.(i+o) <- v.(i)
	done;
	v'

	  
    let shl v i = 
      let n  = Array.length v      in
      let v' = Array.make n V.zero in
      for j = n-1 downto n-i+1 do
	v'.(j-i) <- v.(j)
      done;
      v'

    let shr v i =
      let n  = Array.length v      in
      let v' = Array.make n V.zero in
      for j = 0 to i-1 do
	v'.(j+i) <- v.(j)
      done;
      v'

    let mul v1 v2 =
      let n   = 2*(Array.length v1) in
      let v   = Array.make n V.zero in
      let v2' = zero_extend v2 n    in
      let rec loop i v =
	if i = 0 then
	  v
	else
	  let v' =
	    if V.is_one v1.(i) then add v (shl v2' i)
	    else v
	  in
	  loop (i-1) v'
      in
      loop (n-1) v

    (** return v1 / v2, modulo *)
    let core_div v1 v2 =
      (* check first that v2 is not zero *)
      if for_all V.is_zero v2 then
	Log.error "Division by zero"
      else
	let n   = Array.length v1        in
	let v   = Array.make n V.default in
	let one = Array.make n V.one     in 
	let rec loop v r =
	  if for_all2 (fun b1 b2 -> V.lt b1 b2) r v2 then
	    loop (add v one) (sub r v2)
	  else
	    v, r
	in
	loop v v1
	
	     
    let div v1 v2 = fst (core_div v1 v2)
				     
    let modulo v1 v2 = snd (core_div v1 v2)
	
    let binary op v1 v2 =
      match op with
      | Asm.Add -> add v1 v2
      | Asm.Sub -> sub v1 v2
      | Asm.Xor -> xor v1 v2
      | Asm.And -> logand v1 v2
      | Asm.Or  -> logor v1 v2
      | Asm.Mul -> mul v1 v2
      | Asm.Div -> div v1 v2
      | Asm.Mod -> modulo v1 v2
			  

	  
    let sign_extend v i =
      let n = Array.length v in
      if n >= i then
	v
      else
	let sign = v.(0) in
	let o    = n - i in
	let v' =
	  if V.is_zero sign then Array.make (n+i) V.zero
	  else Array.make (n+i) V.one
	in
	for j = 0 to n-1 do
	  v'.(j+o) <- v.(j)
	done;
	v'
	
    let unary op v =
      match op with
      | Asm.Not       -> Array.map V.neg v
      | Asm.Shl i     -> shl v i
      | Asm.Shr i     -> shr v i
      | Asm.SignExt i -> sign_extend v i
	   
    let default sz = Array.make sz V.default

    let untaint v = Array.map V.untaint v

    let nth_of_value v i = Z.logand (Z.shift_right v i) Z.one
				    
    let of_word w =
      let sz = Data.Word.size w	       in
      let w' = Data.Word.to_int w      in
      let r  = Array.make sz V.default in
      let n' =sz-1 in
      for i = 0 to n' do
	r.(n'-i) <- if Z.compare (nth_of_value w' i) Z.one = 0 then V.one else V.zero
      done;
      r

    let to_value v =
      try
	let z = ref Z.zero in
	for i = 0 to (Array.length v) - 1 do
	  let n = V.to_value v.(i) in
	  z := Z.add n (Z.shift_left !z 1)
	done;
	!z
      with _ -> raise Exceptions.Concretization

    (* this function may raise an exception if one of the bits cannot be converted into a Z.t integer (one bit at BOT or TOP) *) 
    let to_word v = Data.Word.of_int (to_value v) (Array.length v)

    let to_string v =
      let v' =
	if exists V.is_bot v || exists V.is_top v then
	  Array.fold_left (fun s v -> s ^ (V.to_string v)) "" v
	else
	    Data.Word.to_string (to_word v)
      in
      let t = Array.fold_left (fun s v -> s ^(V.string_of_taint v)) "" v  in
      if String.length t = 0 then v'
      else Printf.sprintf "%s ! %s" v' t
    let to_addresses r v = Data.Address.Set.singleton (r, to_word v)

    let subset v1 v2 = for_all2 V.subset v1 v2

    let of_config c n =
      let v  = Array.make n V.default in
      let n' = n-1                    in
      for i = 0 to n' do
	v.(n'-i) <- V.of_value (nth_of_value c i)
      done;
      v
	
    let taint_of_config t n (prev: t option) =
      let v =
	match prev with
	| Some v' -> Array.copy v'
	| None    -> Array.make n V.default
      in
      match t with
      | Config.Bits b ->
	 let n' =n-1 in
	 for i = 0 to n-1 do
	   v.(n'-i) <- V.taint_of_value (nth_of_value b i) v.(i)
	 done;
	 v
      | Config.MBits (b, m) ->
	 let n' = n-1 in
	 for i = 0 to n' do
	   let bnth = nth_of_value b i in
	   let mnth = nth_of_value m i in
	   v.(n'-i) <- V.join (V.taint_of_value bnth v.(i)) (V.taint_of_value mnth v.(i))
	 done;
	 v

    let combine v1 v2 l u =
      let v = Array.copy v1 in
      for i = l to u do
	v.(i) <- v2.(i)
      done;
      v

    let compare v1 op v2 = for_all2 (fun b1 b2 -> V.compare b1 op b2) v1 v2
      
  end: T)
