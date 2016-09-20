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

        let to_z p =
            match p with
            | BOT         -> raise Exceptions.Empty
            | TOP         -> raise Exceptions.Enum_failure
            | Val (_r, v) -> V.to_z v

        let to_string p =
            match p with
            | BOT -> "B0x_"
            | TOP -> "T0x?"
            | Val (r, o) -> Printf.sprintf "%c%s" (char_of_region r) (V.to_string o)

        let untaint p =
            match p with
            | TOP | BOT  -> p
            | Val (r, o) -> Val (r, V.untaint o)

        let taint p =
            match p with
            | TOP | BOT  -> p
            | Val (r, o) -> Val (r, V.taint o)

        let weak_taint  p =
            match p with
            | TOP | BOT  -> p
            | Val (r, o) -> Val (r, V.weak_taint o)

        let join p1 p2 =
            match p1, p2 with
            | BOT, p | p, BOT 	   -> p
            | TOP, _ | _, TOP 	   -> TOP
            | Val (r1, o1), Val (r2, o2) ->
              match r1, r2 with
              | Global, r | r, Global -> Val (r, V.join o1 o2)
              | r1, r2 ->
                if r1 = r2 then Val (r1, V.join o1 o2)
                else BOT

        let widen p1 p2 =
            match p1, p2 with
            | p, BOT
            | BOT, p 			   -> p
            | TOP, _ | _, TOP		   -> TOP
            | Val (r1, o1), Val (r2, o2) ->
              match r1, r2 with
              | Global, r | r, Global ->
                Val (r, V.widen o1 o2)
              | r1, r2 ->
                if r1 = r2 then Val (r1, V.widen o1 o2)
                else BOT


        let meet p1 p2 =
            match p1, p2 with
            | TOP, p | p, TOP 	   -> p
            | BOT, p | p, BOT 	   -> p
            | Val (r1, o1), Val (r2, o2) ->
              match r1, r2 with
              | Global, r | r, Global ->
                Val (r, V.meet o1 o2)
              | r1, r2 ->
                 if r1 = r2 then
		   try Val (r1, V.meet o1 o2)
		   with _ -> BOT
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
                    with _ -> Printf.printf "%s %s %s => BOT\n" (to_string p1) (Asm.string_of_binop op) (to_string p2); flush stdout; BOT
                end
              | r1, r2                ->
                try
                    if r1 = r2 then Val (r1, V.binary op o1 o2)
                    else BOT
                with Exceptions.Enum_failure -> TOP


        let of_word w = Val (Global, V.of_word w)

        let compare p1 op p2 =
            match p1, p2 with
            | BOT, BOT 		   -> op = Asm.EQ || op = Asm.LEQ
            | BOT, _ 			   -> op = Asm.LEQ || op = Asm.LT
            | _, BOT 			   -> false
            | _, TOP | TOP, _		   -> true
            | Val (r1, o1), Val (r2, o2) ->
              if r1 = r2 || r1 = Global || r2 = Global then V.compare o1 op o2
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

        let taint_of_config t n prev =
            match prev with
            | Val (r, o) -> Val (r, V.taint_of_config t n (Some o))
            | _ 	   -> prev

        let of_config r c n = Val (r, V.of_config c n)

        let combine p1 p2 l u =
            match p1, p2 with
            | BOT, _ | _, BOT 	   -> BOT
            | TOP, _ | _, TOP 	   -> TOP
            | Val (r1, o1), Val (r2, o2) ->
              if r1 = r2 then Val (r1, V.combine o1 o2 l u)
              else BOT

        let extract p l u =
            match p with
            | BOT | TOP  -> p
            | Val (r, o) ->
              try
                  Val (r, V.extract o l u)
              with _ -> BOT

        let from_position p i len =
            Log.debug (Printf.sprintf "Pointer.from_position %s %d %d" (to_string p) i len);
            match p with
            | BOT | TOP -> p
            | Val (r, o) ->
              try
                  Val (r, V.from_position o i len)
              with _ -> BOT

        let is_tainted p =
            match p with
            | BOT 	   -> false
            | TOP 	   -> true
            | Val (_, o) -> V.is_tainted o

        let of_repeat_val v v_len nb =
            match v with
            | BOT -> BOT
            | TOP -> TOP
            | Val (region, offset) ->
              let newoffset = V.of_repeat_val offset v_len nb in
              Val(region, newoffset)

        let rec concat l =
            Log.debug (Printf.sprintf "concat len %d" (List.length l) );
            match l with
            |	[ ] -> BOT
            | [v] -> Log.debug (Printf.sprintf "concat single : %s" (to_string v) );v
            | v::l' ->
              let v' = concat l' in
              Log.debug (Printf.sprintf "concat : %s %s" (to_string v) (to_string v'));
              match v, v' with
              | BOT, _ | _, BOT -> BOT
              | TOP, _ | _, TOP -> TOP
              | Val (r1, o1), Val (r2, o2 ) ->
                if r1 = r2 then
                    Val (r1, V.concat o1 o2)
                else BOT

    end: Unrel.T)
