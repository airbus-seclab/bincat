open Data.Address

module Make (V: Vector.T) =
  (struct
    type t =
      | BOT
      | Val of (region * V.t) (** a pointer is a pair (r, o) where r is the region it points-to and o an offset in that region *) 
      | TOP

    let bot = BOT
    let top = TOP
    let is_bot p = p = BOT
			 
    let to_value p =
      match p with
      | BOT         -> raise Exceptions.Empty
      | TOP         -> raise Exceptions.Enum_failure
      | Val (_r, v) -> V.to_value v

    let to_string p =
      match p with
      | BOT -> "_"
      | TOP -> "?"
      | Val (r, o) -> Printf.sprintf "(%s, %s)" (string_of_region r) (V.to_string o)

    let default sz = Val (Global, V.default sz)

    let untaint p =
      match p with
      | TOP | BOT  -> p
      | Val (r, o) -> Val (r, V.untaint o)

    let join p1 p2 =
      match p1, p2 with
      | BOT, p | p, BOT 	   -> p
      | TOP, _ | _, TOP 	   -> TOP
      | Val (r1, o1), Val (r2, o2) ->
	 if r1 = r2 then Val (r1, V.join o1 o2)
	 else TOP

    let meet p1 p2 =
      match p1, p2 with
      | TOP, p | p, TOP 	   -> p
      | BOT, _ | _, BOT 	   -> BOT
      | Val (r1, o1), Val (r2, o2) ->
	 if r1 = r2 then Val (r1, V.meet o1 o2)
	 else BOT

    let unary op p =
      match p with
      | BOT 	   -> BOT
      | TOP 	   -> TOP
      | Val (r, o) ->
	 try Val (r, V.unary op o)
	 with _ -> BOT
		     
    let binary op p1 p2 =
      match p1, p2 with
      | BOT, _ | _, BOT 	   -> BOT
      | TOP, _ | _, TOP 	   -> TOP
      | Val (r1, o1), Val (r2, o2) ->
	 match r1, r2 with
	 | Global, r | r, Global ->
			begin
			  try Val (r, V.binary op o1 o2)
			  with _ -> BOT
			end
	 | r1, r2                ->
	 if r1 = r2 then Val (r1, V.binary op o1 o2)
	 else BOT
      
		
    let of_word w = Val (Global, V.of_word w)

    let compare p1 op p2 =
      match p1, p2 with
      | BOT, BOT 		   -> op = Asm.EQ || op = Asm.LEQ
      | BOT, _ 			   -> op = Asm.LEQ || op = Asm.LT
      | _, BOT 			   -> false
      | _, TOP | TOP, _		   -> true
      | Val (r1, o1), Val (r2, o2) ->
	 if r1 = r2 then V.compare o1 op o2
	 else true

    let to_addresses p =
      match p with
      | BOT 	   -> raise Exceptions.Empty
      | TOP 	   -> raise Exceptions.Enum_failure
      | Val (r, o) -> V.to_addresses r o

    let subset p1 p2 =
      match p1, p2 with
      | BOT, _ | _, TOP 	   -> true
      | _, BOT | TOP, _            -> false
      | Val (r1, o1), Val (r2, o2) ->
	 if r1 = r2 then V.subset o1 o2
	 else true

    let taint_of_config r t n prev =
      match prev with
      | None -> Val (r, V.taint_of_config t n None)
      | Some p ->
	 match p with
	 | BOT 		-> Val (r, V.taint_of_config t n None)
	 | TOP 		-> Val (r, V.taint_of_config t n None)
	 | Val (_r', o) -> Val (r, V.taint_of_config t n (Some o)) 
			      
    let of_config r c n = Val (r, V.of_config c n)

    let combine p1 p2 l u =
      match p1, p2 with
      | BOT, _ | _, BOT 	   -> BOT
      | TOP, _ | _, TOP 	   -> TOP
      | Val (r1, o1), Val (r2, o2) ->
	 if r1 = r2 then Val (r1, V.combine o1 o2 l u)
	 else BOT
		
  end: Unrel.T)
