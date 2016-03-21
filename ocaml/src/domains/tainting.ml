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
		       
      let subset b1 b2 =
	match b1, b2 with
	| T, T | U, U -> true
	| _, TOP      -> true
	| _, _ 	      -> false

      let join b1 b2 =
	match b1, b2 with
	| T, T -> T
	| U, U -> U
	| _, _ -> TOP
					    
      let to_string b =
	match b with
	| TOP -> "?"
	| T   -> "1"
	| U   -> "0"
    end

  (** abstract type of a tainting bit vector *)
  type t = Bit.t array

  let name = "Tainting" (* be sure that if this name changes then Unrel.taint_from_config is updated *)

  let to_value _v = raise Exceptions.Concretization
			  
  let make sz = Array.make sz Bit.U

  let bot sz = make sz

  let top sz = Array.make sz Bit.TOP
			  
  (* iterators on bit vectors *)
  (* remember that binary iterators are supposed to proceed on vector of the same length *)
  let map2 f v1 v2 =
    let n = Array.length v1 in
    let v = make n	    in
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

  let subset v1 v2 = for_all2 Bit.subset v1 v2
			
  let join v1 v2 = map2 Bit.join v1 v2
 
  let taint_of_config v =
    match v with
    | Config.Bits b ->
       let sz = String.length b in
       let t  = make sz         in
       for i = 0 to sz-1 do
	 if String.get b i = '1' then
	   t.(i) <- Bit.T
	 else
	   t.(i) <- Bit.U
       done;
       t
	 
    | Config.MBits (b, m) ->
       let sz = String.length b in
       let t  = make sz         in
	 for i=0 to sz-1 do
	   if String.get m i = '1' then
	     t.(i) <- Bit.TOP
	   else
	     if String.get b i = '1' then
	      t.(i) <- Bit.T
	   else
	     t.(i) <- Bit.U
	 done;
	 t
   
 let to_string v =
      let s = Array.fold_left (fun s b -> s ^ (Bit.to_string b) ^ ", ") "" v in
      Printf.sprintf ("%s") (String.sub s 0 ((String.length s) -2))

 let of_config _r _c sz = make sz
			    
 let mem_to_addresses _e _sz _c = raise (Exceptions.Enum_failure ("Tainting", "mem_to_addresses"))


 let eval_exp e sz (c: Domain.oracle) ctx: t =
   let rec eval e =
    match e with
    | Asm.Lval (Asm.V (Asm.T r)) ->
       ctx#get_val_from_register r
							      
    | Asm.Lval (Asm.V (Asm.P (r, l, u))) -> 
       let c = ctx#get_val_from_register r in
       Array.sub c l (l-u+1)
	 
    | Asm.Lval (Asm.M (m, sz)) ->
       begin
	 try
	   let addr   = c#mem_to_addresses m sz                  in
	   let addr_l = Data.Address.Set.elements addr	         in
	   let v      = ctx#get_val_from_memory (List.hd addr_l) in 
	   List.fold_left (fun s a -> join s ( ctx#get_val_from_memory a )) v (List.tl addr_l)
	 with
	 | _ -> top sz
      end

    | Asm.BinOp (Asm.Xor, e1, e2) when Asm.equal_exp e1 e2 -> Array.make sz Bit.U
									  
    | Asm.BinOp (_, e1, e2) -> join (eval e1) (eval e2)
	    
    | Asm.Const _c -> make sz

    | _ -> top sz
   in
   eval e

 let eval_bexp e sz c ctx =
   let rec eval e =
     match e with
     | Asm.BBinOp (_, e1, e2) -> join (eval e1) (eval e2)
     | Asm.Cmp (_, e1, e2)    -> join (eval_exp e1 sz c ctx) (eval_exp e2 sz c ctx) 
     | Asm.BUnOp (_, e')      -> eval e'
     | Asm.BConst _ 	      -> make sz
   in
   eval e
	
  let enter_fun _f _ctx = failwith "Tainting.enter_fun: to implement" 

  let leave_fun _ctx = failwith "Tainting.leave_fun: to implement"
      
  let combine v1 v2 l u =
       let n = Array.length v1 in
       let v = make n          in
       for i = 0 to l-1 do
	 v.(i) <- v1.(i)
       done;
       for i = u+1 to n-1 do
	 v.(i) <- v1.(i)
       done;
       for i = l to u do
	 v.(i) <- v2.(i)
       done;
       v   

				    

		  
   
