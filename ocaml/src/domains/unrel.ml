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
    val to_z: t -> Z.t

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

        module Key =
        struct
            type t =
              | Reg of Register.t
              | Mem_Itv of Data.Address.t * Data.Address.t (* interval of addresses, from init *)
              | Mem of Data.Address.t                      (* address to single byte *)

            let compare v1 v2 =
                match v1, v2 with
                | Reg r1, Reg r2 -> Register.compare r1 r2
                | Mem addr1, Mem addr2 ->
                  Data.Address.compare addr1 addr2
                | Mem addr1, Mem_Itv (m2_low, m2_high) ->
                  if addr1 < m2_low then -1
                  else if m2_high < addr1 then 1
                  else 0
                | Mem_Itv (m1_low, m1_high), Mem addr2 ->
                  if m1_high < addr2 then -1
                  else if addr2 < m1_low then 1
                  else 0
                | Mem_Itv (m1_low, m1_high), Mem_Itv (m2_low, m2_high) ->
                  if m1_high < m2_low then -1
                  else if m2_high < m1_low then 1
                  else 0
                | Reg _ , _    -> 1
                | _   , _    -> -1

            let to_string x =
                match x with
                | Reg r -> Printf.sprintf "reg [%s]"  (Register.name r)
                | Mem_Itv (low_a, high_a) -> Printf.sprintf "mem [%s, %s]" (Data.Address.to_string low_a) (Data.Address.to_string high_a) 
                | Mem addr -> Printf.sprintf "mem [%s, %s]" (Data.Address.to_string addr) (Data.Address.to_string (Data.Address.inc addr))
        end

        (* For Ocaml non-gurus : creates a Map type which uses MapOpt with keys of type Key *)
        module Map = MapOpt.Make(Key)

        (** type of the Map from Dimension (register or memory) to abstract values *)
        type t     =
          | Val of D.t Map.t (* For Ocaml non-gurus : Val is a Map, indexed by Key, with values of D.t *)
          | BOT

        let bot = BOT

        let is_bot m = m = BOT

        let value_of_register m r =
            match m with
            | BOT    -> raise Exceptions.Concretization
            | Val m' ->
              try
                  let v = Map.find (Key.Reg r) m' in D.to_z v
              with _ -> raise Exceptions.Concretization

        let add_register r m =
            let add m' =
                Val (Map.add (Key.Reg r) D.top m')
            in
            match m with
            | BOT    -> add Map.empty
            | Val m' -> add m'

        let remove_register v m =
            match m with
            | Val m' -> Val (Map.remove (Key.Reg v) m')
            | BOT    -> BOT


        let forget m =
            match m with
            | BOT -> BOT
            | Val m' -> Val (Map.map (fun _ -> D.top) m')

        let forget_register r m =
            match m with
            | Val m' -> Val (Map.add (Key.Reg r) D.top m')
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
            | Val m' -> Map.fold (fun k v l -> (Printf.sprintf "%s = %s" (Key.to_string k) (D.to_string v)) :: l) m' []

        (***************************)
        (** Memory access function *)
        (***************************)

        (* Helper to get an array of addresses : base..(base+nb-1) *)
        let get_addr_array base nb =
            let arr = Array.make nb base in
            for i = 0 to nb-1 do
                arr.(i) <- Data.Address.add_offset base (Z.of_int i);
            done;
            arr

        let get_addr_list base nb =
            Array.to_list (get_addr_array base nb)

        (** compare the given _addr_ to key, for use in MapOpt.find_key **)
        (** remember that registers (key Key.Reg) are before any address in the order defined in K *)
        let where addr key =
            match key with
            | Key.Reg _ -> -1
            | Key.Mem addr_k -> Data.Address.compare addr addr_k
            | Key.Mem_Itv (a_low, a_high) ->
              if Data.Address.compare addr a_low < 0 then
                  -1
              else
              if Data.Address.compare addr a_high > 0 then 1
              else 0 (* return 0 if a1 <= a <= a2 *)

        (** computes the value read from the map where _addr_ is located *)
        let get_mem_value map addr sz =
            (*Log.debug (Printf.sprintf "state : %s" ((List.fold_left (fun acc s -> Printf.sprintf "%s\n %s" acc s)) "" ( Map.fold (fun k v l -> ((Key.to_string k) ^ " = " ^ (D.to_string v)) :: l) domain [] )));*)
            Log.debug (Printf.sprintf "get_mem_value : %s %d" (Data.Address.to_string addr) sz );
            try
                (* expand the address + size to a list of addresses *)
                let exp_addrs = get_addr_list addr (sz/8) in
                (* find the corresponding keys in the map, will raise [Not_found] if no addr matches *)
                let vals = List.rev_map (fun cur_addr -> snd (Map.find_key (where cur_addr) map)) exp_addrs in
                (* TODO big endian, here the map is reversed so it should be ordered in little endian order *)
                let res = D.concat vals in
                Log.debug (Printf.sprintf "get_mem_value result : %s" (D.to_string res));
                res
            with _ -> D.bot

        (** helper to look for a an address in map, returns an option with None
            if no key matches *)
        let safe_find addr dom : (Map.key * 'a) option  =
            try
                let res = Map.find_key (where addr) dom in
                Log.debug (Printf.sprintf "safe_find addr -> key : %s -> [%s]" (Data.Address.to_string addr) (Key.to_string (fst res)));
                Some res
            with Not_found ->
               Log.debug (Printf.sprintf "safe_find addr -> key : %s -> []" (Data.Address.to_string addr));
               None

        (** helper to split an interval at _addr_, returns a map with nothing
            at _addr_ but _itv_ split in 2 *)
        let split_itv domain itv addr =
              let map_val = Map.find itv domain in
              match itv with
                | Key.Mem_Itv (low_addr, high_addr) ->
                  let dom' = Map.remove itv domain in
                  (* addr just below the new byte *)
                  let addr_before = Data.Address.dec addr  in
                  (* addr just after the new byte *)
                  let addr_after = Data.Address.inc addr in
                  (* add the new interval just before, if it's not empty *)
                  let dom' =
                    if Data.Address.equal addr low_addr then
                        dom'
                    else
                        Map.add (Key.Mem_Itv (low_addr, addr_before)) map_val dom'
                  in
                  (* add the new interval just after, if its not empty *)
                    if Data.Address.equal addr high_addr then
                        dom'
                    else
                        Map.add (Key.Mem_Itv (addr_after, high_addr)) map_val dom'
                | _ -> Log.error "Trying to split a non itv"

        (* strong update of memory with _byte_ repeated _nb_ times *)
        let write_repeat_byte_in_mem addr domain byte nb =
            let addrs = get_addr_list addr nb in
            (* helper to remove keys to be overwritten, splitting Mem_Itv
               as necessary *)
            let delete_mem  addr domain =
                let key = safe_find addr domain in
                match key with
                | None -> domain;
                | Some (Key.Reg _,_) ->  Log.error "Implementation error in Unrel: the found key is a Reg"
                (* We have a byte, delete it *)
                | Some (Key.Mem (_) as addr_k, _) -> Map.remove addr_k domain
                | Some (Key.Mem_Itv (_, _) as key, _) ->
                    split_itv domain key addr
            in
            let rec do_cleanup addrs map =
                match addrs with
                | [] -> map
                | to_del::l -> do_cleanup l (delete_mem to_del map) in
            let dom_clean = do_cleanup addrs domain in
            Map.add (Key.Mem_Itv (addr, (Data.Address.add_offset addr (Z.of_int nb)))) byte dom_clean


        (* Write _value_ of size _sz_ in _domain_ at _addr_, in
           _big_endian_ if needed. _strong_ means strong update *)
        let write_in_memory addr domain value sz strong big_endian =
            Log.debug (Printf.sprintf "write_in_memory : %s %s %d %B" (Data.Address.to_string addr) (D.to_string value) sz strong);
            (*Log.debug (Printf.sprintf "state : %s" ((List.fold_left (fun acc s -> Printf.sprintf "%s\n %s" acc s)) "" ( Map.fold (fun k v l -> ((Key.to_string k) ^ " = " ^ (D.to_string v)) :: l) domain [] )));*)

            let nb = sz / 8 in
            let addrs = get_addr_list addr nb in
            let addrs = if big_endian then List.rev addrs else addrs in
            (* helper to update one byte in memory *)
            let update_one_key (addr, byte) domain =
                let key = safe_find addr domain in
                match key with
                | Some (Key.Reg _, _) -> Log.error "Implementation error in Unrel: the found key is a Reg"
                (* single byte to update *)
                | Some (Key.Mem (_) as addr_k, match_val) ->
                  if strong then
                      Map.replace addr_k byte domain
                  else
                      Map.replace addr_k (D.join byte match_val) domain
                (* we have to split the interval *)
                | Some (Key.Mem_Itv (_, _) as key, match_val) ->
                  let dom' = split_itv domain key addr in
                      if strong then
                          Map.add (Key.Mem(addr)) byte dom'
                      else
                          Map.add (Key.Mem(addr)) (D.join byte match_val) dom'
                (* the addr was not previously seen *)
                | None -> if strong then
                      Map.add (Key.Mem(addr)) byte domain
                  else
                      raise Exceptions.Empty
            in
            let rec do_update new_mem map =
(*                Log.debug "do_update";
                List.iter (fun (a,v) ->   Log.debug (Printf.sprintf "addr,v : %s %s" (Data.Address.to_string a) (D.to_string v))) new_mem;*)
                match new_mem with
                | [] -> map
                | new_val::l -> do_update l (update_one_key new_val map) in
            let new_mem = List.mapi (fun i addr -> (addr, (D.extract value (i*8) ((i+1)*8-1)))) addrs in
            do_update new_mem domain



        (***************************)
        (** Non mem functions  :)  *)
        (***************************)

        (** evaluates the given expression *)
        let eval_exp m e =
            let rec eval e =
                match e with
                | Asm.Const c 			     -> D.of_word c
                | Asm.Lval (Asm.V (Asm.T r)) 	     ->
                  begin
                      try Map.find (Key.Reg r) m
                      with Not_found -> D.bot
                  end
                | Asm.Lval (Asm.V (Asm.P (r, low, up))) ->
                  begin
                      try
                          let v = Map.find (Key.Reg r) m in
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
                              | [a]  -> get_mem_value m a n
                              | a::l -> D.join (get_mem_value m a n) (to_value l)
                              | []   -> raise Exceptions.Bot_deref
                          in
                          let value = to_value addresses
                          in
                          value
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
                | Asm.Lval (Asm.V (Asm.T r)) | Asm.Lval (Asm.V (Asm.P (r, _, _))) -> let r' = Map.find (Key.Reg r) m in if D.is_tainted r' then raise Exit else ()
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
                        | Asm.T r' -> Val (Map.add (Key.Reg r') v' m')
                        | Asm.P (r', low, up) ->
                          try
                              let prev = Map.find (Key.Reg r') m' in
                              Val (Map.replace (Key.Reg r') (D.combine prev v' low up) m')
                          with
                            Not_found -> BOT
                    end
                  | Asm.M (e, n) ->
                    let addrs = D.to_addresses (eval_exp m' e) in
                    let l     = Data.Address.Set.elements addrs in
                    try
                        match l with
                        | [a] -> (* strong update *) Val (write_in_memory a m' v' n true false)
                        | l   -> (* weak update *) Val (List.fold_left (fun m a ->  write_in_memory a m v' n false false) m' l)
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
            let round_sz sz =
                if sz < !Config.operand_sz then
                    !Config.operand_sz
                else
                if sz mod !Config.operand_sz <> 0 then
                    !Config.operand_sz * (sz / !Config.operand_sz + 1)
                else
                    sz
            in
            match c with
            | Config.Content z | Config.CMask (z, _) -> round_sz (Z.numbits z)
            | Config.Bytes b | Config.Bytes_Mask (b, _) -> Log.debug (Printf.sprintf "size_of_content %s" b); (String.length b)*4


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
                  if nb > 1 then
                    if sz != 8 then
                        Log.error "Repeated memory init only works with bytes"
                    else
                        Val (write_repeat_byte_in_mem addr domain' val_taint nb)
                  else
                      let big_endian =
                        match content with
                        | Config.Bytes _ | Config.Bytes_Mask (_, _) -> true
                        | _ -> false
                        in
                          Val (write_in_memory addr domain' val_taint sz true big_endian)
            else
                domain

        let set_register_from_config r region c m =
            match m with
            | BOT    -> BOT
            | Val m' ->
              let sz = Register.size r in
              let vt = of_config region c sz in
              Val (Map.add (Key.Reg r) vt m')

        let val_restrict m e1 _v1 cmp _e2 v2 =
            match e1, cmp with
            | Asm.Lval (Asm.V (Asm.T r)), cmp when cmp = Asm.EQ || cmp = Asm.LEQ ->
              let v  = Map.find (Key.Reg r) m in
              let v' = D.meet v v2        in
              if D.is_bot v' then
                  raise Exceptions.Empty
              else
                  Map.replace (Key.Reg r) v' m
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
            | Val m' -> D.to_z (eval_exp m' e)

    end: Domain.T)

