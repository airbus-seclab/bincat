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
    val taint_of_config: Config.tvalue -> int -> t  -> t

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

    (** returns the sub value between bits low and up *)
    val extract: t -> int -> int -> t

    (** [from_position v p len] returns the sub value from bit p to bit p-len-1 *)
    val from_position: t -> int -> int -> t

    (** [of_repeat_val val v_len nb] repeats provided pattern val having length v_len, nb times**)
    val of_repeat_val: t -> int -> int -> t

    (** [concat [v1; v2 ; ... ; vn] ] returns value v such that v = v1 << |v2+...+vn| + v2 << |v3+...+vn| + ... + vn *)
    val concat: t list -> t
end


module Make(D: T) = 
    (struct

        module K = 
        struct
            type t = 
              | R of Register.t
              | M of Data.Address.t * Data.Address.t (* interval of addresses *)

            let compare v1 v2 = 
                match v1, v2 with
                | R r1, R r2 -> Register.compare r1 r2
                | M (m11, m12), M (m21, m22) ->
                  if m12 < m21 then -1
                  else if m22 < m11 then 1
                  else 0
                | R _ , _    -> 1
                | _   , _    -> -1

            let to_string x = 
                match x with 
                | R r -> "reg [" ^ (Register.name r) ^ "]"
                | M (a, a') -> "mem [" ^ (Data.Address.to_string a) ^ ", " ^(Data.Address.to_string a') ^ "]"
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
                Val (Map.add (K.R r) D.bot m')
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

        (** compute the position of the address a with respect to key k of type K.t *)
        (** remember that registers (key K.R) are before any address in the order defined in K *)
        let where a k =
            match k with
            | K.R _ -> -1
            | K.M (a1, a2) -> 
              if Data.Address.compare a a1 < 0 then
                  -1
              else
              if Data.Address.compare a a2 > 0 then 1
              else 0 (* return 0 if a1 <= a <= a2 *)

        (** computes the value read from a the map around at the key k containing address a *) 
        let build_value m a sz =
            try
                (* find the key k in the map that address a belongs to *)
                let k, m0  = Map.find_key (where a) m in
                match k with
                | K.R _      -> Log.error "Implementation error in Unrel: the found key should be a pair of addresses"
                | K.M (_l, u) -> D.from_position m0 (((Z.to_int (Data.Address.sub u a))+1)*8-1) sz
            with _ -> D.bot


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
                | Asm.Lval (Asm.V (Asm.P (r, low, up))) ->
                  begin
                      try
                          let v = Map.find (K.R r) m in
                          D.extract v low up
                      with
                      | Not_found -> D.bot
                  end
                | Asm.Lval (Asm.M (e, n))            ->
                  begin
                      let r = eval e in
                      try
                          let addresses = Data.Address.Set.elements (D.to_addresses r) in
                          let rec to_value a =
                              match a with
                              | [a]  -> build_value m a n
                              | a::l -> D.join (build_value m a n) (to_value l)
                              | []   -> raise Exceptions.Bot_deref
                          in
                          to_value addresses
                      with
                      | Exceptions.Enum_failure               -> D.top
                      | Not_found | Exceptions.Concretization ->
                        Log.from_analysis (Printf.sprintf "undefined memory dereference [%s]=[%s]: analysis stops in that context" (Asm.string_of_exp e true) (D.to_string r));
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


        let write_in_memory addr domain value sz strong =
            let nb = sz / 8					   in
            let min_addr = addr in
            let max_addr = Data.Address.add_offset addr (Z.of_int (nb-1))   in
            let to_array first =
                let arr = Array.make (nb-first) addr in
                    for i = first to nb-1 do
                        arr.(i) <- Data.Address.add_offset addr (Z.of_int i);
                    done;
                arr in
            (* TODO : get rid of the list, but f*cking OCaml doesn't include
               Array.exists *)
            let to_list i =
                Array.to_list (to_array (i+1))
            in
            Log.debug ("----------------------");
            Log.debug (Printf.sprintf "write_in_memory : %s %s %d" (Data.Address.to_string addr) (D.to_string value) sz);
            Log.debug (Printf.sprintf "write_in_memory : min_addr : %s max_addr : %s" (Data.Address.to_string min_addr) (Data.Address.to_string max_addr));
            let addrs = to_list (-1) in
            List.iter (fun t ->   Log.debug (Printf.sprintf "addrs : %s" (Data.Address.to_string t))) addrs;
            let within domain =
                (* TODO: optimize the search scanning by removing already found addresses in list addrs + avoid exploring all the map by knowing how it is structured *)
                match domain with
                | K.M (low', up') -> 

                     let has_it = List.exists (fun addr' ->
                    ((Data.Address.compare low' addr' <= 0 ) && (* XXX CHECK if < or <= *)
                     (Data.Address.compare addr' up' <= 0))) addrs (* SAME *)
                     in
                     Log.debug (Printf.sprintf "within %s:%s %B" (Data.Address.to_string low')(Data.Address.to_string up') has_it);
                     has_it
                | _ 	       -> false 
            in
            let all_addrs = Map.find_all_keys within domain in
            List.iter (fun (_, t) ->   Log.debug (Printf.sprintf "all_addrs : %s" (D.to_string t))) all_addrs;
            let before low up pvalue =
                (* get data from pvalue from low to 'addr' *)
                let pend = ((Z.to_int (Data.Address.sub up low)*8+7)) in 
                let len = ((Z.to_int (Data.Address.sub addr low))*8) in
                Log.debug (Printf.sprintf "before(low, up) : %s %s" (Data.Address.to_string low) (Data.Address.to_string up));
                Log.debug (Printf.sprintf "before : pvalue %s" (D.to_string pvalue));
                D.from_position pvalue pend len
            in
            let inpart up pvalue =
                Log.debug (Printf.sprintf "inpart(up, pv) : %s %s"  (Data.Address.to_string up)(D.to_string pvalue));
                if strong then value
                else
                if Data.Address.compare max_addr up <= 0 then
                    D.join value (D.from_position pvalue (((Z.to_int (Data.Address.sub up addr))+1)*8-1) sz)
                else raise Exceptions.Empty
            in
            let after up' pv =
                Log.debug (Printf.sprintf "after : %s %s" (Data.Address.to_string up') (D.to_string pv));
                let pos = Z.to_int (Data.Address.sub up' max_addr) in
                D.from_position pv pos ((pos)*8)
            in
            let rec split l =
                match l with
                | [ K.M (l, u), v]    -> (l, u, v), []
                | (K.M _ as k, _)::l' -> let e, l' = split l' in e, k::l'
                | _ 		      -> raise Exceptions.Empty
            in
            match all_addrs with
              (* only one address in the domain *)
              [ K.M (low, up) as k, match_val ] ->
              if Data.Address.compare up min_addr = 0 then
                  (* new address is at the end of an existing chunk :
                   * merge *)
                  if strong then
                      let m' = Map.remove k domain in
                      Map.add (K.M (low, Data.Address.add_offset addr (Z.of_int (nb-1)))) (D.concat [match_val ; value]) m'
                  else
                      raise Exceptions.Empty
              else
              if Data.Address.compare low max_addr = 0 then
                  (* new data is right before an existing chunk :
                   * merge *)
                  if strong then
                      let m' = Map.remove k domain in
                      Map.add (K.M (addr, up)) (D.concat [value ; match_val]) m'
                  else raise Exceptions.Empty
              else
                  let w1 = before low up match_val in
                  let w2 = inpart up match_val in
                  let w3 = after up match_val in
                  let m' = Map.remove k domain in 
                  let new_val = D.concat [ w1 ; w2 ; w3 ] in 
                  Log.debug (Printf.sprintf "w1 : %s ; w2 : %s; w3 : %s => new_val : %s" (D.to_string w1) (D.to_string w2)(D.to_string w3)(D.to_string new_val));
                  Map.add (K.M (low, up)) new_val m'

            | (K.M (l1, u1) as k1, pv1)::l ->
              if strong then
                  let b =
                      if Data.Address.compare u1 min_addr = 0 then pv1
                      else before l1 u1 pv1
                  in
                  let m' = Map.remove k1 domain in
                  let (l, u, pv), r = split l in
                  let w3 =
                      if Data.Address.compare l max_addr = 0 then pv
                      else after u pv
                  in
                  let m' = Map.remove (K.M (l, u)) m' in
                  let m' = List.fold_left (fun domain k -> Map.remove k domain) m' r in
                  Map.add (K.M (l1, u)) (D.concat [b ; value ; w3]) m'
              else raise Exceptions.Empty
            | [] ->
              if strong then
                  Map.add (K.M (addr, Data.Address.add_offset addr (Z.of_int (nb-1)))) value domain
              else
                  raise Exceptions.Empty	  
            | _ -> raise Exceptions.Empty	     

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
                        | Asm.P (r', low, up) ->
                          try
                              let prev = Map.find (K.R r') m' in
                              Val (Map.replace (K.R r') (D.combine prev v' low up) m')
                          with
                            Not_found -> BOT
                    end
                  | Asm.M (e, n) ->
                    let addrs = D.to_addresses (eval_exp m' e) in
                    let l     = Data.Address.Set.elements addrs in
                    try
                        match l with
                        | [a] -> (* strong update *) Val (write_in_memory a m' v' n true)
                        | l   -> (* weak update *) Val (List.fold_left (fun m a ->  write_in_memory a m v' n false) m' l)
                    with Exceptions.Empty -> BOT			       

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

        (** returns size of content, rounded to the next multiple of Config.operand_sz *)
        let size_of_content c =
            let sz = 
                match c with
                | Config.Content z | Config.CMask (z, _) -> Z.numbits z
            in
            if sz < !Config.operand_sz then
                !Config.operand_sz
            else
            if sz mod !Config.operand_sz <> 0 then
                !Config.operand_sz * (sz / !Config.operand_sz + 1)
            else
                sz


        (** builds an abstract tainted value from a config concrete tainted value *)
        let of_config region (content, taint) sz =
            let v' = D.of_config region content sz in
            match taint with
            | Some taint' -> D.taint_of_config taint' sz v'
            | None 	-> v'

        let set_memory_from_config addr region (content, taint) nb domain =
            if nb > 0 then
                match domain with
                | BOT    -> BOT
                | Val domain' ->
                  let sz = size_of_content content in
                  let val_taint = of_config region (content, taint) sz in
                  let r = D.of_repeat_val val_taint sz nb in
                  Val (write_in_memory addr domain' r (sz*nb) true)
            else
                domain

        let set_register_from_config r region c m =
            match m with
            | BOT    -> BOT
            | Val m' ->
              let sz = Register.size r in
              let vt = of_config region c sz in
              Val (Map.add (K.R r) vt m')

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

