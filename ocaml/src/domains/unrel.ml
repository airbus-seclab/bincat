(*
    This file is part of BinCAT.
    Copyright 2014-2021 - Airbus

    BinCAT is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or (at your
    option) any later version.

    BinCAT is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with BinCAT.  If not, see <http://www.gnu.org/licenses/>.
*)

(******************************************************************************)
(* Functor generating common functions of unrelational abstract domains       *)
(* basically it is a map from Registers/Memory cells to abstract values       *)
(******************************************************************************)

module L = Log.Make(struct let name = "unrel" end)

(** Unrelational domain signature *)
module type T =
  sig
    (** abstract data type *)
    type t
 
    (** bottom value *)
    val bot: t

    (** comparison to bottom *)
    val is_bot: t -> bool

    (** forgets the content but preserves the taint *)
    val forget: t -> (int * int) option -> t
    (** the forget operation is bounded to bits from l to u if the second parameter is Some (l, u) *)

    (** returns a string representation of the set of taint sources of the given abstract value. The string is empty if untainted *)
    val taint_sources: t -> Taint.t

    (** top value *)
    val top: t

    (** conversion to values of type Z.t *)
    val to_z: t -> Z.t

    (** char conversion.
    May raise an exception if conversion fail (not a concrete value or too large) *)
    val to_char: t -> char

    (** converts a word into an abstract value *)
    val of_word: Data.Word.t -> t

    (** converts an address into an abstract value *)
    val of_addr: Data.Address.t -> t
      
    (** comparison.
    Returns true whenever the concretization of the first parameter is included in the concretization of the second parameter *)
    val is_subset: t -> t -> bool

    (** string conversion *)
    val to_string: t -> string

    (** return the taint and the value as a string separately *)
    val to_strings: t -> string * string

    (** value generation from configuration.
    The size of the value is given by the int parameter *)
    val of_config: Config.cvalue -> int -> t

    (** taint the given abstract value.
    The size of the value is given by the int parameter. The taint itself is also returned *)
    val taint_of_config: Config.tvalue list -> int -> t -> t * Taint.t


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

    (** [span_taint v t] span taint t on each bit of v *)
    val span_taint: t -> Taint.t -> t

    (** forgets the taint of the given value *)
    val forget_taint: t -> t
      
    (** returns the sub value between bits low and up *)
    val extract: t -> int -> int -> t

    (** [from_position v p len] returns the sub value from bit p to bit p-len-1 *)
    val from_position: t -> int -> int -> t

    (** [of_repeat_val val v_len nb] repeats provided pattern val having length v_len, nb times**)
    val of_repeat_val: t -> int -> int -> t

    (** [concat [v1; v2 ; ... ; vn] ] returns value v such that v = v1 << |v2+...+vn| + v2 << |v3+...+vn| + ... + vn *)
    val concat: t list -> t

    (** returns the minimal taint value of the given parameter *)
    val get_minimal_taint: t -> Taint.t

    val get_taint: t -> Taint.t
  end


module Make(D: T) =
  struct
      
    (** type of the Map from Dimension (register or memory) to abstract values *)
    type t = D.t Env.t (* For Ocaml non-gurus : Env is a Map, indexed by Key, with values of D.t *)


    let empty = Env.empty
              
    let top = Env.empty
            
 
  
    let value_of_register m r =
      let v =
        try
          Env.find (Env.Key.Reg r) m
        with Not_found -> raise (Exceptions.Empty (Printf.sprintf "unrel.value_of_register: register %s not found in environment" (Register.name r)))
      in D.to_z v

    let string_of_register m r =
      let v =
        try
          Env.find (Env.Key.Reg r) m
        with Not_found -> raise (Exceptions.Empty (Printf.sprintf "unrel.value_of_string: register %s not found in environment" (Register.name r)))
      in D.to_string v

    let add_register r m w =
      let v =
        match w with
        | None -> D.top
        | Some w' -> D.of_word w'
      in
      Env.add (Env.Key.Reg r) v m

    let remove_register v m = Env.remove (Env.Key.Reg v) m


    let forget m = Env.map (fun _ -> D.top) m

    let forget_reg m' r opt =
      let key = Env.Key.Reg r in
      let top' =
        try
          let v = Env.find key m' in
          let v' = D.forget v opt in
          v'
        with Not_found -> D.top
      in
    Env.add key top' m'

    let is_subset m1 m2 =
      try Env.for_all2 D.is_subset m1 m2
      with _ ->
        try
          Env.iteri (fun k v1 ->
              try
                let v2 = Env.find k m2 in
                if not (D.is_subset v1 v2) then
                  raise Exit
              with Not_found -> ()) m1;
          true
        with Exit -> false


    let coleasce_to_strs (m : D.t Env.t) (strs : string list) =
      let addr_zero = Data.Address.of_int Data.Address.Global Z.zero 0 in
      let prev_addr = ref addr_zero in
      let in_itv = ref false in
      let build_itv k _v itvs : ((Data.Address.t ref * Data.Address.t) list) =
        match k with
        | Env.Key.Reg _ -> in_itv := false; prev_addr := addr_zero; itvs
        | Env.Key.Mem_Itv (_low_addr, _high_addr) -> in_itv := false; prev_addr := addr_zero; itvs
        | Env.Key.Mem (addr) ->
           let new_itv =
             if !in_itv && Data.Address.compare (!prev_addr) (Data.Address.inc addr) == 0 then
               begin
                 (* continue byte string *)
                 prev_addr := addr;
                 let cur_start = fst (List.hd itvs) in cur_start := addr;
                 itvs
               end else begin
                 (* not contiguous, create new itv *)
                 in_itv := true;
                 prev_addr := addr;
                 let new_head = (ref addr, addr) in
                 new_head :: itvs
               end
           in new_itv
      in
      let itv_to_str itv =
        let low = !(fst itv) in
        let high = snd itv in
        let addr_str = Printf.sprintf "mem[%s, %s]" (Data.Address.to_string low) (Data.Address.to_string high) in
        let len = (Z.to_int (Data.Address.sub high low))+1 in
        let strs = let indices = Array.make len 0 in
                   for offset = 0 to len-1 do
                     indices.(offset) <- offset
                   done;
                   let buffer = Buffer.create (len*10) in
                   Array.iter (fun off -> Printf.bprintf buffer ", %s" (D.to_string (Env.find (Env.Key.Mem (Data.Address.add_offset low (Z.of_int off))) m))) indices ;
                   Buffer.contents buffer
        in Printf.sprintf "%s = %s" addr_str (String.sub strs 2 ((String.length strs)-2))
      in
      let itvs = Env.fold build_itv m [] in
      List.fold_left (fun strs v -> (itv_to_str v)::strs) strs itvs

    let non_itv_to_str k v =
      match k with
      | Env.Key.Reg _ | Env.Key.Mem_Itv(_,_) -> Printf.sprintf "%s = %s" (Env.Key.to_string k) (D.to_string v)
      | _ -> ""

    let to_string m =
      let non_itv = Env.fold (fun k v strs -> let s = non_itv_to_str k v in if String.length s > 0 then s :: strs else strs) m [] in
      coleasce_to_strs m non_itv

    (***************************)
    (* Memory access function  *)
    (***************************)

    (* Helper to get an array of addresses : base..(base+nb-1) *)
    let get_addr_array base nb =
      let arr = Array.make nb base in
      for i = 0 to nb-1 do
        let addr' = Data.Address.add_offset base (Z.of_int i) in
        match addr' with
        | Data.Address.Heap (_, sz), o when Z.compare sz (Data.Word.to_int o) < 0 ->
           raise (Exceptions.Heap_out_of_bounds (Data.Address.to_string addr'))
        | _ -> arr.(i) <- addr'
      done;
      arr

    let get_addr_list base nb =
      Array.to_list (get_addr_array base nb)

    (** compare the given _addr_ to key, for use in MapOpt.find_key.
        Remember that registers (key Env.Key.Reg) are before any address in the order defined in K *)
    let where addr key =
      match key with
      | Env.Key.Reg _ -> -1
      | Env.Key.Mem addr_k -> Data.Address.compare addr addr_k
      | Env.Key.Mem_Itv (a_low, a_high) ->
         if Data.Address.compare addr a_low < 0 then
           -1
         else
           if Data.Address.compare addr a_high > 0 then 1
           else 0 (* return 0 if a1 <= a <= a2 *)

    (** computes the value read from the map where _addr_ is located
        The logic is the following:
        1) expand the base address and size to an array of addrs
        2) check "map" for existence
        3) if "map" contains the adresses, get the values and concat them
        4) else check in the "sections" maps and read from the file (or raise Not_found)
    **)
    let get_mem_value ?endianness map addr sz  =
      let endianness' = match endianness with
        | None -> !Config.endianness
        | Some x -> x in
      L.debug (fun p -> p "get_mem_value : addr=%s sz=%d bytes, %s"
                          (Data.Address.to_string addr) sz
                          (Config.endianness_to_string endianness'));
      try
        (* expand the address + size to a list of addresses *)
        let exp_addrs = get_addr_list addr (sz/8) in

        (* find the corresponding keys in the map, will raise [Not_found] if no addr matches *)
        let map_or_revmap = match endianness' with
          | Config.BIG -> List.map
          | Config.LITTLE -> List.rev_map in
        let read_one_byte addr =
          try
            snd (Env.find_key (where addr) map)
          with Not_found ->
          L.debug (fun p -> p "Address %s not found in mapping, checking sections"
                              (Data.Address.to_string addr));
          (* not in mem map, check file sections, again, will raise [Not_found] if not matched *)
          let mapped_mem = match !Mapped_mem.current_mapping with
            | None -> L.abort (fun p -> p "File not mmapped")
            | Some x -> x in
          D.of_word (Mapped_mem.read mapped_mem addr) in
        let vals = map_or_revmap read_one_byte exp_addrs in
        let res = D.concat vals in
        L.debug (fun p -> p "get_mem_value result : %s" (D.to_string res));
        res
      with _ -> D.bot

    (** helper to look for a an address in map, returns an option with None
        if no key matches *)
    let safe_find addr dom : (Env.key * 'a) option  =
      try
        let res = Env.find_key (where addr) dom in
        Some res
      with Not_found -> None

    (** helper to split an interval at _addr_, returns a map with nothing
        at _addr_ but _itv_ split in 2 *)
    let split_itv domain itv addr =
      let map_val = Env.find itv domain in
      match itv with
      | Env.Key.Mem_Itv (low_addr, high_addr) ->
         L.debug2 (fun p -> p "Splitting (%s, %s) at %s" (Data.Address.to_string low_addr) (Data.Address.to_string high_addr) (Data.Address.to_string addr));
        let dom' = Env.remove itv domain in
         (* addr just below the new byte *)
        let addr_before = Data.Address.dec addr  in
         (* addr just after the new byte *)
        let addr_after = Data.Address.inc addr in
         (* add the new interval just before, if it's not empty *)
        let dom' =
          if Data.Address.equal addr low_addr || Data.Address.equal low_addr addr_before then begin
            dom'
          end else begin
            Env.add (Env.Key.Mem_Itv (low_addr, addr_before)) map_val dom'
          end
        in
         (* add the new interval just after, if its not empty *)
        let res =
          if Data.Address.equal addr high_addr || Data.Address.equal addr_after high_addr then
            dom'
          else
          Env.add (Env.Key.Mem_Itv (addr_after, high_addr)) map_val dom'
        in
        res
      | _ -> L.abort (fun p -> p "Trying to split a non itv")

    (* strong update of memory with _byte_ repeated _nb_ times *)
    let write_repeat_byte_in_mem addr domain byte nb =
      let addrs = get_addr_list addr nb in
      (* helper to remove keys to be overwritten, splitting Mem_Itv
         as necessary *)
      let delete_mem  addr domain =
        let key = safe_find addr domain in
        match key with
        | None -> domain
        | Some (Env.Key.Reg _,_) ->  L.abort (fun p -> p "Implementation error: the found key is a Reg")
        (* We have a byte, delete it *)
        | Some (Env.Key.Mem (_) as addr_k, _) -> Env.remove addr_k domain
        | Some (Env.Key.Mem_Itv (_, _) as key, _) ->
           split_itv domain key addr
      in
      let rec do_cleanup addrs map =
        match addrs with
        | [] -> map
        | to_del::l -> do_cleanup l (delete_mem to_del map)
      in
      let dom_clean = do_cleanup addrs domain in
      Env.add (Env.Key.Mem_Itv (addr, (Data.Address.add_offset addr (Z.of_int nb)))) byte dom_clean


    (* Write _value_ of size _sz_ in _domain_ at _addr_, in
       _endianness_. _strong_ means strong update *)
    let write_in_memory ?endianness addr domain value sz strong check_address_validity =
      check_address_validity addr;
      let endianness' = match endianness with
        | None -> !Config.endianness
        | Some x -> x in
      L.debug (fun p -> p "write_in_memory (addr=%s, value=%s, size=%d bits, %s)" 
                          (Data.Address.to_string addr) (D.to_string value) sz
                          (Config.endianness_to_string endianness'));
      let nb = sz / 8 in
      let addrs = get_addr_list addr nb in
      let addrs = match endianness' with
        | Config.BIG -> List.rev addrs
        | Config.LITTLE -> addrs in
      (* helper to update one byte in memory *)
      let update_one_key (addr, byte) domain =
        L.debug2 (fun p -> p "update_one_key (%s, %s)" (Data.Address.to_string addr) (D.to_string byte));
        let key = safe_find addr domain in
        match key with
        | Some (Env.Key.Reg _, _) -> L.abort (fun p -> p "Implementation error: the found key is a Reg")
        (* single byte to update *)
        | Some (Env.Key.Mem (_) as addr_k, match_val) ->
           if strong then
             Env.replace addr_k byte domain
           else
             Env.replace addr_k (D.join byte match_val) domain
        (* we have to split the interval *)
        | Some (Env.Key.Mem_Itv (_, _) as key, match_val) ->
           let dom' = split_itv domain key addr in
           if strong then
             Env.add (Env.Key.Mem(addr)) byte dom'
           else
             Env.add (Env.Key.Mem(addr)) (D.join byte match_val) dom'
        (* the addr was not previously seen *)
        | None -> if strong then
                    Env.add (Env.Key.Mem(addr)) byte domain
                  else
                    raise (Exceptions.Empty (Printf.sprintf
                                      "unrel.write_in_memory: no key found for weak update at address %s for byte %s" (Data.Address.to_string addr) (D.to_string byte)))
      in
      let rec do_update new_mem map =
        match new_mem with
        | [] -> map
        | new_val::l ->
       do_update l (update_one_key new_val map)
      in
      let new_mem = List.mapi (fun i addr -> (addr, (D.extract value (i*8) ((i+1)*8-1)))) addrs in
      do_update new_mem domain

                
    (***************************)
    (* Non mem functions  :)   *)
    (***************************)
    (** opposite the given comparison operator *)
    let inv_cmp (cmp: Asm.cmp): Asm.cmp =
      (* TODO factorize with Interpreter *)
      match cmp with
      | Asm.EQ  -> Asm.NEQ
      | Asm.NEQ -> Asm.EQ
      | Asm.LT  -> Asm.GEQ
      | Asm.GEQ -> Asm.LT
      | Asm.LEQ -> Asm.GT
      | Asm.GT  -> Asm.LEQ
      | Asm.GES -> Asm.LTS
      | Asm.LTS -> Asm.GES



    (** evaluates the given expression
        returns the evaluated expression and a boolean to say if
        the resulting expression is tainted
    *)
    let rec eval_exp m e check_address_validity: (D.t * Taint.t) =
      L.debug (fun p -> p "eval_exp(%s)" (Asm.string_of_exp e true));
      let rec eval (e: Asm.exp): D.t * Taint.t =
        match e with
        | Asm.Const c                -> D.of_word c, Taint.U
        | Asm.Lval (Asm.V (Asm.T r))         ->
           begin
             try
               let v = Env.find (Env.Key.Reg r) m in
               v, D.taint_sources v
             with Not_found -> D.bot, Taint.U
           end

        | Asm.Lval (Asm.V (Asm.P (r, low, up))) ->
           begin
             try
               let v = Env.find (Env.Key.Reg r) m in
               let v' = D.extract v low up in
               v', D.taint_sources v'
             with
             | Not_found -> D.bot, Taint.U
           end

        | Asm.Lval (Asm.M (e, n))            ->
           begin
             let r, tsrc = eval e in
             try
               let addresses = Data.Address.Set.elements (D.to_addresses r) in
               let rec to_value a =
                 match a with
                 | [a]  ->
                    check_address_validity a;
                   let v = get_mem_value m a n in
                   v, Taint.logor tsrc (D.taint_sources v)

                 | a::l ->
                    check_address_validity a;
                    let v = get_mem_value m a n in
                    let v', tsrc' = to_value l in
                    D.join v v', Taint.join (D.taint_sources v) (Taint.logor tsrc tsrc')

                 | []   -> raise Exceptions.Bot_deref
               in
               to_value addresses
             with
             | Exceptions.Too_many_concrete_elements _ -> D.top, Taint.TOP
             | Not_found ->
                L.analysis (fun p -> p ("undefined memory dereference [%s]=[%s]: analysis stops in that context") (Asm.string_of_exp e true) (D.to_string r));
               raise Exceptions.Bot_deref
             | Exceptions.Empty _ as ex ->
                L.exc ex (fun p -> p ("Undefined memory dereference"));
                L.analysis (fun p -> p ("Undefined memory dereference [%s]=[%s]: analysis stops in that context") (Asm.string_of_exp e true) (D.to_string r));
               raise Exceptions.Bot_deref
           end

        | Asm.BinOp (Asm.Xor, Asm.Lval (Asm.V (Asm.T r1)), Asm.Lval (Asm.V (Asm.T r2))) when Register.compare r1 r2 = 0 ->
           D.untaint (D.of_word (Data.Word.of_int (Z.zero) (Register.size r1))), Taint.U


        | Asm.BinOp (op, e1, e2) ->
           let v1, tsrc1 = eval e1 in
           let v2, tsrc2 = eval e2 in
           let v = D.binary op v1 v2 in
           v, Taint.logor tsrc1 (Taint.logor tsrc2  (D.taint_sources v))

        | Asm.UnOp (op, e) ->
           let v, tsrc = eval e in
           let v' = D.unary op v in
           v', Taint.logor tsrc (D.taint_sources v')

        | Asm.TernOp (c, e1, e2) ->
           let r, tsrc = eval_bexp c true check_address_validity in
           let res, taint_res =
             if r then (* condition is true *)
               let r2, tsrc2 = eval_bexp c false check_address_validity in
               if r2 then
                 let v1, tsrc1' = eval e1 in
                 let v2, tsrc2' = eval e2 in
                 D.join v1 v2, Taint.logor tsrc2 (Taint.logor tsrc1' tsrc2')
               else
                 let v1, tsrc1' = eval e1 in
                 v1, Taint.logor tsrc1' tsrc2
             else
               let r2, tsrc2 = eval_bexp c false check_address_validity in
               if r2 then
                 let v2, tsrc2' = eval e2 in
                 v2, Taint.logor tsrc2 tsrc2'
               else
                 D.bot, tsrc
           in
           D.span_taint res taint_res, taint_res

      (* TODO: factorize with Interpreter.restrict *)
      and eval_bexp (c: Asm.bexp) (b: bool) check_address_validity: bool * Taint.t =
        match c with
        | Asm.BConst b'           -> if b = b' then true, Taint.U else false, Taint.U
        | Asm.BUnOp (Asm.LogNot, e) -> eval_bexp e (not b) check_address_validity

        | Asm.BBinOp (Asm.LogOr, e1, e2)  ->
           let v1, b1 = eval_bexp e1 b check_address_validity in
           let v2, b2 = eval_bexp e2 b check_address_validity in
           if b then v1||v2, Taint.logor b1 b2
           else v1&&v2, Taint.logand b1 b2

        | Asm.BBinOp (Asm.LogAnd, e1, e2) ->
           let v1, b1 = eval_bexp e1 b check_address_validity in
           let v2, b2 = eval_bexp e2 b check_address_validity in
           if b then v1&&v2, Taint.logand b1 b2
           else v1||v2, Taint.logor b1 b2

        | Asm.Cmp (cmp, e1, e2)   -> 
           let cmp' = if b then cmp else inv_cmp cmp in
           compare_env m e1 cmp' e2 check_address_validity
      in
      eval e

    and compare_env env (e1: Asm.exp) op e2 check_address_validity: bool * Taint.t =
      let v1, tsrc1 = eval_exp env e1 check_address_validity in
      let v2, tsrc2 = eval_exp env e2 check_address_validity in
      D.compare v1 op v2, Taint.logor tsrc1 tsrc2

    let forget_lval lv m' check_address_validity = 
      match lv with
      | Asm.V (Asm.T r) -> forget_reg m' r None
      | Asm.V (Asm.P (r, l, u)) -> forget_reg m' r (Some (l, u))
      | Asm.M (e, n) ->
         let v, _b = eval_exp m' e check_address_validity in
         let addrs = D.to_addresses v in
         let l     = Data.Address.Set.elements addrs in
         List.fold_left (fun m a ->  write_in_memory a m D.top n true check_address_validity) m' l


    let val_restrict m e1 v1 cmp _e2 v2: t list =
      match e1, cmp with
      | Asm.Lval (Asm.V (Asm.T r)), cmp when cmp = Asm.EQ ->
         let v  = Env.find (Env.Key.Reg r) m in
         let v' = D.meet v v2 in
         if D.is_bot v' then
               raise (Exceptions.Empty "unrel.val_restrict")
         else
           [Env.replace (Env.Key.Reg r) v' m]
      | _, _ ->
         (* TODO: improve by restricting result + integrationg into the domain to have better reductions *)
         try
           let z1 = D.to_z v1 in
           let z2 = D.to_z v2 in
           let diff = Z.compare z1 z2 in
           let b =
             match diff, cmp with
             | 0, Asm.LEQ -> true
             | 0, Asm.EQ -> true
             | 0, _ -> false
             | _, Asm.NEQ -> true
             | n, Asm.LEQ when n <= 0 -> true
             | n, Asm.GT when n > 0 -> true
             | _, _ -> false
           in
           if b then
             [m]
           else
             raise (Exceptions.Empty "unrel.val_restrict")
         with _ -> [m]

    (* TODO factorize with compare_env *)
    let compare m' check_address_validity (e1: Asm.exp) op e2 =
      let v1, b1 = eval_exp m' e1 check_address_validity in
      let v2, b2 = eval_exp m' e2 check_address_validity in
      if D.is_bot v1 || D.is_bot v2 then
        raise (Exceptions.Empty "Unrel.compare")
      else
        if D.compare v1 op v2 then
          val_restrict m' e1 v1 op e2 v2, Taint.logor b1 b2
        else
          raise (Exceptions.Empty "Unrel.compare")
      
    let mem_to_addresses m' e check_address_validity =
      let v, b = eval_exp m' e check_address_validity in
      let addrs = D.to_addresses v in
      (* check whether the address is allowed to be dereferenced *)
      (* could be put elsewhere with a set of forbidden addresses to check (e.g. range of low addresses) *)
      Data.Address.Set.iter (fun a -> if Data.Address.is_null a then raise (Exceptions.Null_deref (Asm.string_of_exp e true))) addrs;
      addrs, b

    (** [span_taint m e v] span the taint of the strongest *tainted* value of e to all the fields of v.
    If e is untainted then nothing is done *)
    let span_taint m e (v: D.t) =
      L.debug (fun p -> p "span_taint(%s) v=%s"  (Asm.string_of_exp e true) (D.to_string v));
      let rec process e =
        match e with
        | Asm.Lval (Asm.V (Asm.T r)) ->
           let r' = Env.find (Env.Key.Reg r) m in
           D.get_minimal_taint r'

        | Asm.Lval (Asm.V (Asm.P (r, low, up))) ->
           let r' =  Env.find (Env.Key.Reg r) m in
           D.get_minimal_taint (D.extract r' low up)

        | Asm.Lval (Asm.M (e', _n)) -> process e'
        | Asm.BinOp (_, e1, e2) -> Taint.min (process e1) (process e2)
        | Asm.UnOp (_, e') -> process e'
        | _ -> Taint.U
      in
      match e with
      | Asm.BinOp (_, _e1, Asm.Lval (Asm.M (e2_m, _))) ->
         begin
           let taint = process e2_m in
           match taint with
           | Taint.U -> v
           | _ -> D.span_taint v taint
         end

      | Asm.Lval (Asm.M (e', _)) ->
         begin
           let taint = process e' in
           match taint with
           | Taint.U -> v
           | _ -> D.span_taint v taint
         end

      | Asm.UnOp(_, e') ->
         begin
           let taint = process e' in
           match taint with
           | Taint.U -> v
           | _ -> D.span_taint v taint
         end
      | _ -> v


    let set_to_memory dst_exp dst_sz v' m' b check_address_validity =
      let v, b' = eval_exp m' dst_exp check_address_validity in
      let addrs = D.to_addresses v in
      try
        let l     = Data.Address.Set.elements addrs in
        let t' = Taint.logor b b' in
        match l with
        | [a] -> (* strong update *) write_in_memory a m' v' dst_sz true check_address_validity, t'
        | l   -> (* weak update *) List.fold_left (fun m a -> write_in_memory a m v' dst_sz false check_address_validity) m' l, t'
      with
      | Exceptions.Too_many_concrete_elements "unrel.set" -> Env.empty, Taint.TOP

    let set_to_register r v' m' =
      match r with
      | Asm.T r' ->  Env.add (Env.Key.Reg r') v' m'
      | Asm.P (r', low, up) ->
         let prev = Env.find (Env.Key.Reg r') m' in
           Env.replace (Env.Key.Reg r') (D.combine prev v' low up) m'
         
             
    let set dst src m' check_address_validity: (t * Taint.t) =
      let v', _ = eval_exp m' src check_address_validity in
         let v' = span_taint m' src v' in
         L.info2 (fun p -> p "(set) %s = %s (%s)" (Asm.string_of_lval dst true) (Asm.string_of_exp src true) (D.to_string v'));
         let b = D.taint_sources v' in
         if D.is_bot v' then
           raise (Exceptions.Empty "Unrel.set"), b
         else
           match dst with
           | Asm.V r ->
              begin
                try
                  set_to_register r v' m', b
                with Not_found -> raise (Exceptions.Empty "Unrel.set (register case)"), Taint.BOT
              end
                
           | Asm.M (e, n) ->
              try
                set_to_memory e n v' m' b check_address_validity
              with
              | _ -> raise (Exceptions.Empty "Unrel.set (memory case)")

    let join m1' m2' =
      try Env.map2 D.join m1' m2'
      with _ ->
        let m = Env.empty in
        let m' = Env.fold (fun k v m -> Env.add k v m) m1' m in
        Env.fold (fun k v m -> try
              L.debug2 (fun p -> p "Unrel.join on %s" (Env.Key.to_string k));
              let v' = Env.find k m1' in Env.replace k (D.join v v') m with Not_found -> Env.add k v m) m2' m'


    let meet m1 m2 =
      if Env.is_empty m1 then
        m2
      else
        if Env.is_empty m2 then
          m1
        else
          let m' = Env.empty in
          Env.fold (fun k v1 m' ->
              try                
                let v2 = Env.find k m2 in
                let v' = D.meet v1 v2 in
                if D.is_bot v' then
                  raise (Exceptions.Empty "Unrel.meet")
                else
                  Env.add k v' m'
              with Not_found -> raise (Exceptions.Empty "Unrel.meet")
            ) m1 m'

    let widen m1 m2 =
       try Env.map2 D.widen m1 m2
         with _ ->
           let m = Env.empty in
           let m' = Env.fold (fun k v m -> Env.add k v m) m1 m in
           Env.fold (fun k v m -> try let v' = Env.find k m1 in let v2 = try D.widen v' v with _ -> D.top in Env.replace k v2 m with Not_found -> Env.add k v m) m2 m'

    (** returns size of content, rounded to the next multiple of Config.operand_sz *)
    let round_sz sz =
      if sz < !Config.operand_sz then
        !Config.operand_sz
      else
        if sz mod !Config.operand_sz <> 0 then
          !Config.operand_sz * (sz / !Config.operand_sz + 1)
        else
          sz

   

    let extract_taint_src_ids taint =
      let extract acc taint =
        match taint with
        | Config.Taint_all id
        | Config.Taint (_, id) 
        | Config.TMask (_, _, id)  
        | Config.TBytes (_, id) 
        | Config.TBytes_Mask (_, _, id) -> id::acc
        | Config.Taint_none -> acc
      in 
      List.fold_left extract [] taint 
   
    (** builds an abstract tainted value from a config concrete tainted value *)
    let of_config (content, (taint: Config.tvalue list)) sz: (D.t * Taint.t) =
      let v' = D.of_config content sz in  
      if taint = [] then
        (v', Taint.U)
      else
        D.taint_of_config taint sz v'

    let taint_register_mask reg taint m': t * Taint.t =
      let k = Env.Key.Reg reg in
      let v = Env.find k m' in
      let v', taint =  D.taint_of_config [taint] (Register.size reg) v in
      Env.replace k v' m', taint

    let span_taint_to_register reg taint m': t * Taint.t =
         let k = Env.Key.Reg reg in
         let v = Env.find k m' in
         let v' = D.span_taint v taint in
         Env.replace k v' m', taint

    let taint_address_mask a (taints: Config.tvalue list) m': t * Taint.t =
      L.debug (fun p->p "Unrel.taint_address_mask (%s)" (Data.Address.to_string a));
         let k = Env.Key.Mem a in
         let v = Env.find k m' in
         let v', taint = D.taint_of_config taints (Config.size_of_taints taints) v in
         Env.replace k v' m', taint

    let span_taint_to_addr a taint m': t * Taint.t =
      let k = Env.Key.Mem a in
      let v = Env.find k m' in
      let v' = D.span_taint v taint in
      Env.replace k v' m', taint


    let forget_taint m = Env.map (fun v -> D.forget_taint v) m

                 
    let taint_in_memory a m taint sz strong =
      let addrs = get_addr_list a (sz/8) in
      let update_one_key a (m, prev_taint): D.t Env.t * Taint.t =
        let key = safe_find a m in
        let m', taint' =
                  match key with
                  | None ->
                     raise (Exceptions.Empty (Printf.sprintf
                                                "unrel.taint_in_memory: no key found for taint update at address %s" (Data.Address.to_string a)))
                  | Some (Env.Key.Reg _, _) -> L.abort (fun p -> p "Implementation error: the found key is a Reg")
                  (* single byte to update *)
                  | Some (Env.Key.Mem (_) as addr_k, match_val) ->
                     if strong then
                       Env.replace addr_k (D.span_taint match_val taint) m, taint
                     else
                       let taint' = Taint.join (D.get_taint match_val) taint in
                       Env.replace addr_k (D.span_taint match_val taint) m, taint'
                  (* we have to split the interval *)
                  | Some (Env.Key.Mem_Itv (_, _) as key, match_val) ->
                     let dom' = split_itv m key a in
                     if strong then
                       Env.add (Env.Key.Mem(a)) (D.span_taint match_val taint) dom', taint
                     else
                       let taint' = Taint.join (D.get_taint match_val) taint in
                       Env.add (Env.Key.Mem(a)) (D.span_taint match_val taint') dom', taint'
        in
        m', Taint.join taint' prev_taint
      in
      List.fold_left (fun prev a -> update_one_key a prev) (m, Taint.U) addrs

    let get_taint lv m check_address_validity =
      let _, taint = eval_exp m (Asm.Lval lv) check_address_validity in
      taint
                       
    let taint_lval lv taint check_address_validity m: t * Taint.t =
      match lv with
      | Asm.V (Asm.T r) -> span_taint_to_register r taint m
      | Asm.V (Asm.P (r, _l, _u)) -> span_taint_to_register r Taint.TOP m (* TODO: could be more precise *)
      | Asm.M (e, sz) ->
         try
           let v, _ = eval_exp m e check_address_validity in
           let addrs = D.to_addresses v in
           let l = Data.Address.Set.elements addrs in
           begin 
             match l with
             | [a] -> taint_in_memory a m taint sz true
             | _  -> List.fold_left (fun (m, prev_t) a ->
                         let m', taint' = taint_in_memory a m taint sz false in
                       m', Taint.join prev_t taint') (m, Taint.U) l
           end
         with _ -> forget_taint m, Taint.TOP
         
         
    let set_memory_from_config addr ((content: Config.cvalue option), (taint: Config.tvalue list)) nb check_address_validity domain': t * Taint.t =
      L.debug (fun p->p "Unrel.set_memory_from_config");  
      let taint_srcs = extract_taint_src_ids taint in          
      let m', taint, sz =
        match content with
        | None ->
           begin
             let taint_sz = Config.size_of_taints taint in
             let rec repeat (m, t) n =
               if n < nb then
                 let a' = Data.Address.add_offset addr (Z.of_int (n*taint_sz)) in
                 let k = Env.Key.Mem a' in
                 let v = Env.find k m in
                 let v', taint' = D.taint_of_config taint taint_sz v in
                 let m' = Env.replace k v' m in
                 repeat (m', taint') (n+1)
               else
                 m, t
             in
             let m', taint = repeat (domain', Taint.U) 0 in
             m', taint, taint_sz                
           end
        | Some content' ->
           let sz = Config.size_of_content content' in
           let (v', taint) = of_config (content', taint) sz in
           if nb > 1 then
             if sz != 8 then
               L.abort (fun p -> p "Repeated memory init only works with bytes")
             else
               write_repeat_byte_in_mem addr domain' v' nb, taint, sz
           else
             let endianness =
               match content' with
               | Config.Bytes _ | Config.Bytes_Mask (_, _) -> Config.BIG
               | _ -> !Config.endianness
             in
             write_in_memory ~endianness:endianness addr domain' v' sz true check_address_validity, taint, sz
      in
      List.iter (fun id -> if not (Hashtbl.mem Dump.taint_src_tbl id) then
                             Hashtbl.add Dump.taint_src_tbl id (Dump.M(addr, sz*nb))) taint_srcs;  
      m', taint



    let set_register_from_config r (content, taint) m': t * Taint.t =     
      let taint_srcs = extract_taint_src_ids taint in
      List.iter (fun id ->
          if not (Hashtbl.mem Dump.taint_src_tbl id) then
            Hashtbl.add Dump.taint_src_tbl id (Dump.R r)) taint_srcs;
      match content with
      | None ->
         let k = Env.Key.Reg r in
         let v = Env.find k m' in
         let v', taint' =  D.taint_of_config taint (Register.size r) v in
         Env.replace k v' m', taint'
      | Some c ->  
         let sz = Register.size r in

            let vt, taint = of_config  (c, taint) sz in               
            Env.replace (Env.Key.Reg r) vt m', taint

            
    let set_lval_to_addr lv (region, word) m check_address_validity =
      (* TODO: should we taint the lvalue if the address to set is tainted ? *)
      L.debug2 (fun p -> p "entering set_lval_to_addrs with lv = %s" (Asm.string_of_lval lv true));  
         match lv with
         | Asm.M (e, n) ->
            if n <> !Config.address_sz then
              raise (Exceptions.Empty "inconsistent dereference size wrt to address size")
            else
              begin
                try
                  let bytes = Data.Word.to_bytes word in
                  let m', taint, _ =
                    List.fold_left (fun (m', taint, i) byte ->
                        let v = D.of_addr (region, byte) in
                        let e' = Asm.BinOp (Asm.Add, e, Asm.Const (Data.Word.of_int i !Config.operand_sz)) in
                        let m', taint' =
                          set_to_memory e' 8 v m' Taint.U check_address_validity
                        in
                        m', Taint.logor taint taint', Z.add i Z.one) (m, Taint.U, Z.zero) bytes
                  in
                  m', taint
                with _ -> raise (Exceptions.Empty "set_lval_to_addr: invalid dereference"), Taint.BOT 
              end
              
         | Asm.V r ->
            let v = D.of_addr (region, word) in
            try
              set_to_register r v m, Taint.U
            with Not_found -> raise (Exceptions.Empty (Printf.sprintf "set_lval_to_addr: register %s not found" (Asm.string_of_reg r))), Taint.BOT
            
    let value_of_exp m e check_address_validity =
      D.to_z (fst (eval_exp m e check_address_validity))


    let taint_sources e m check_address_validity =
      snd (eval_exp m e check_address_validity)


    let i_get_bytes (addr: Asm.exp) (cmp: Asm.cmp) (terminator: Asm.exp) (upper_bound: int) (sz: int) (m': t) (with_exception: bool) pad_options check_address_validity: (int * D.t list) =

      L.debug(fun p -> p "i_get_bytes addr=%s cmp='%s' terminator=%s upper_bound=%i sz=%i"
        (Asm.string_of_exp addr true) (Asm.string_of_cmp cmp)
        (Asm.string_of_exp terminator true) upper_bound sz);
    
         let v, _ = eval_exp m' addr check_address_validity in
         let addrs = Data.Address.Set.elements (D.to_addresses v) in
         let term = fst (eval_exp m' terminator check_address_validity) in
         let off = sz / 8 in
         let rec find (a: Data.Address.t) (o: int): (int * D.t list) =
           if o >= upper_bound then
             if with_exception then raise Not_found
             else o, []
           else
             let a' = Data.Address.add_offset a (Z.of_int o) in
             let v = get_mem_value m' a' sz in
             if D.compare v cmp term then
               match pad_options with
               | None -> o, []
               | Some (pad_char, pad_left) ->
                  if o = upper_bound then upper_bound, []
                  else
                    let n = upper_bound-o in
                    let z = D.of_word (Data.Word.of_int (Z.of_int (Char.code pad_char)) 8) in
                    if pad_left then L.abort (fun p -> p "left padding in i_get_bytes not managed")
                    else
                      let chars = ref [] in
                      for _i = 0 to n-1 do
                        chars := z::!chars
                      done;
                      upper_bound, !chars
             else
               let o', l = find a (o+off) in
               o', v::l
     in
     match addrs with
     | [a] -> find a 0
     | _::_ ->
        let res = List.fold_left (fun acc a ->
          try
        let n = find a 0 in
        match acc with
        | None -> Some n
        | Some prev -> Some (max prev n)
          with _ -> acc) None addrs
        in
        begin
          match res with
          | Some n -> n
          | None -> raise Not_found
        end
     | [] -> raise (Exceptions.Empty "unrel.i_get_bytes")

    let get_bytes e cmp terminator (upper_bound: int) (sz: int) (m: t) check_address_validity: int * Bytes.t =
      try
        let len, vals = i_get_bytes e cmp terminator upper_bound sz m true None check_address_validity in
        let bytes = Bytes.create len in
    (* TODO: endianess ! *)
        List.iteri (fun i v ->
          Bytes.set bytes i (D.to_char v)) vals;
        len, bytes
      with Not_found -> raise (Exceptions.Too_many_concrete_elements "unrel.get_bytes")

    let get_offset_from e cmp terminator upper_bound sz m check_address_validity = fst (i_get_bytes e cmp terminator upper_bound sz m true None check_address_validity) 

    let copy_register r dst' src' =
      let k = Env.Key.Reg r in
      let v = Env.find k src' in
      Env.replace k v dst'
      


    (* Remove the prefix of the string, if needed
     * For example : "S0x1F" => "1F" or "0b1" => "1" or "1" => "1"
     *
     *)
    let strip str =
      L.debug (fun p->p "strip, before: %s" str);
      let res = if String.length str < 3 then str else
          let fst_chr = String.get str 0 in
          let skip = if fst_chr = 'G' || fst_chr = 'S' || fst_chr = 'H' then 1 else 0 in
          let prefix = String.sub str skip 2 in
          if String.compare prefix "0x" = 0 || String.compare prefix "0b" = 0 then
            String.sub str (skip+2) (String.length str - (skip+2))
          else
            String.sub str skip (String.length str - skip)
      in
      L.debug (fun p->p "strip, after: %s" res);
      res

    let copy_until m' dst e terminator term_sz upper_bound with_exception pad_options check_address_validity: int * t =  
       let addrs = Data.Address.Set.elements (D.to_addresses (fst (eval_exp m' dst check_address_validity))) in
       (* TODO optimize: m is pattern matched twice (here and in i_get_bytes) *)
       let len, bytes = i_get_bytes e Asm.EQ terminator upper_bound term_sz m' with_exception pad_options check_address_validity in
       let copy_byte a m' strong =
         let m', _ =
           List.fold_left (fun (m', i) byte ->
         let a' = Data.Address.add_offset a (Z.of_int i) in
           (write_in_memory a' m' byte 8 strong check_address_validity), i+1) (m', 0) bytes
         in
         m'
       in
       let m' =
         match addrs with
         | [a] -> copy_byte a m' true
         | _::_  -> List.fold_left (fun m' a -> copy_byte a m' false) m' addrs
         | [] -> raise (Exceptions.Empty "unrel.copy_until")
       in
       len, m'
   

    (* print nb bytes on stdout as raw string *)
    let print_bytes bytes nb =
          let str = Bytes.make nb ' ' in
              List.iteri (fun i c -> Bytes.set str i (D.to_char c)) bytes;
              Log.Stdout.stdout (fun p -> p "%s" (Bytes.to_string str));;

    let print_until m e terminator term_sz upper_bound with_exception pad_options check_address_validity =
      let len, bytes = i_get_bytes e Asm.EQ terminator upper_bound term_sz m with_exception pad_options check_address_validity in
      print_bytes bytes len;
      len, m

    let copy_chars m dst src nb pad_options check_address_validity =
      snd (copy_until m dst src (Asm.Const (Data.Word.of_int Z.zero 8)) 8 nb false pad_options check_address_validity)

    let print_chars m' src nb pad_options check_address_validity =
      (* TODO: factorize with copy_until *)
      let len, bytes = i_get_bytes src Asm.EQ (Asm.Const (Data.Word.of_int Z.zero 8)) nb 8 m' false pad_options check_address_validity
      in
      print_bytes bytes len;
      m', len
       

    let copy_chars_to_register m reg offset src nb pad_options check_address_validity =
     let terminator = Asm.Const (Data.Word.of_int Z.zero 8) in
     let len, bytes = i_get_bytes src Asm.EQ terminator nb 8 m false pad_options check_address_validity in
     let new_v = D.concat bytes in
     let key = Env.Key.Reg reg in
     let new_v' =
       if offset = 0 then new_v
       else
         try let prev = Env.find key m in
             let low = offset*8 in
             D.combine prev new_v low (low*len-1)
         with Not_found -> raise (Exceptions.Empty "unrel.copy_chars_to_register")
     in
     try Env.replace key new_v' m
     with Not_found -> Env.add key new_v m

    let to_int m src _nb _capitalise _pad_option _full_print _word_sz check_address_validity =
      let str =
        try
          let v = value_of_exp m src check_address_validity in
          Z.to_string v
        with _ -> "?"
      in
      str, String.length str
      
    let to_hex m src nb capitalise pad_option full_print _word_sz check_address_validity: string * int =
      let capitalise str =
        if capitalise then String.uppercase_ascii str
        else str
      in
      let vsrc = fst (eval_exp m src check_address_validity) in
      let str_src, str_taint = D.to_strings vsrc in
      let str_src' = capitalise (strip str_src) in
      let sz = String.length str_src' in
      let str' =
        match pad_option with
        | Some (pad, pad_left) ->
           (*word_sz / 8 in*)
           let nb_pad = nb - sz in
           (* pad with the pad parameter if needed *)
           if nb_pad <= 0 then
             if full_print then
               if String.compare str_taint "0x0" = 0 then
                 str_src'
               else
                 Printf.sprintf "%s!%s" str_src' str_taint
             else
               str_src'
           else
             let pad_str = String.make nb_pad pad in
             if pad_left then
               let pad_src = pad_str ^ str_src' in
               if full_print then
                 if String.compare str_taint "0x0" = 0 then
                   pad_src
                 else
                   Printf.sprintf "%s!%s" pad_src (pad_str^str_taint)
               else
                 pad_src
             else
               let pad_src = str_src' ^ pad_str in
               if full_print then
                 if String.compare str_taint "0x0" = 0 then
                   pad_src
                 else
                   Printf.sprintf "%s!%s" pad_src (str_taint^pad_str)
               else
                 pad_src

        | None ->
           if full_print then
             if String.compare str_taint "0x0" = 0 then
               str_src'
             else
               Printf.sprintf "%s!%s" str_src' str_taint
           else
             str_src'
      in
      str', String.length str'

    let copy_hex m' dst src nb capitalise pad_option word_sz check_address_validity: t * int =
        (* TODO generalise to non concrete src value *)
      let _, src_tainted = (eval_exp m' src check_address_validity) in
      let str_src, len = to_hex m' src nb capitalise pad_option false word_sz check_address_validity in
      let vdst = fst (eval_exp m' dst check_address_validity) in
      let dst_addrs = Data.Address.Set.elements (D.to_addresses vdst) in
      match dst_addrs with
      | [dst_addr] ->
         let znb = Z.of_int nb in
         let rec write m' o =
           if Z.compare o znb < 0 then
             let c = String.get str_src (Z.to_int o) in
             let dst = Data.Address.add_offset dst_addr o in
             let i' = Z.of_int (Char.code c) in
             let r = D.of_word (Data.Word.of_int i' 8) in
             let v' =
               match src_tainted, D.taint_sources r with
               | Taint.U, Taint.U -> r
               | _, Taint.U -> D.span_taint r src_tainted
               | _, _ -> D.taint r
             in
             write (write_in_memory dst m' v' 8 true check_address_validity) (Z.add o Z.one)
           else
             m'
         in
         write m' Z.zero, len
      | [] -> raise (Exceptions.Empty "unrel.copy_hex")
      | _  -> Env.empty, len (* TODO could be more precise *)

    (* TODO: factorize owth copy_hex *)
    let copy_int m' dst src nb capitalise pad_option word_sz check_address_validity: t * int =
      let _, src_tainted = (eval_exp m' src check_address_validity) in
      let str_src, len = to_int m' src nb capitalise pad_option false word_sz check_address_validity in
      let vdst = fst (eval_exp m' dst check_address_validity) in
      let dst_addrs = Data.Address.Set.elements (D.to_addresses vdst) in
      match dst_addrs with
      | [dst_addr] ->
         let znb = Z.of_int nb in
         let rec write m' o =
           if Z.compare o znb < 0 then
             let c = String.get str_src (Z.to_int o) in
             let dst = Data.Address.add_offset dst_addr o in
             let i' = Z.of_int (Char.code c) in
             let r = D.of_word (Data.Word.of_int i' 8) in
             let v' =
               match src_tainted, D.taint_sources r with
               | Taint.U, Taint.U -> r
               | _, Taint.U -> D.span_taint r src_tainted
               | _, _ -> D.taint r
             in
             write (write_in_memory dst m' v' 8 true check_address_validity) (Z.add o Z.one)
           else
             m'
         in
         write m' Z.zero, len
      | [] -> raise (Exceptions.Empty "unrel.copy_int")
      | _  -> Env.empty, len (* TODO could be more precise *)

            
    let print_hex m' src nb capitalise pad_option word_sz check_address_validity: t * int =      
      let str, len = to_hex m' src nb capitalise pad_option false word_sz check_address_validity in
      (* str is already stripped in hex *)
      Log.Stdout.stdout (fun p -> p "%s" str);
      m', len


    let print_int m' src nb capitalise pad_option word_sz check_address_validity =
      let str, len = to_int m' src nb capitalise pad_option false word_sz check_address_validity in
      Log.Stdout.stdout (fun p -> p "%s" str);
      m', len
      
    let copy m' dst arg sz check_address_validity: t =
    (* TODO: factorize pattern matching of dst with Interpreter.sprintf and with Unrel.copy_hex *)
    (* plus make pattern matching more generic for register detection *)
      let v = fst (eval_exp m' arg check_address_validity) in
      let addrs = fst (eval_exp m' dst check_address_validity) in
      match Data.Address.Set.elements (D.to_addresses addrs) with
      | [a] -> write_in_memory a m' v sz true check_address_validity
      | _::_ as l -> List.fold_left (fun m a -> write_in_memory a m v sz false check_address_validity) m' l
      | [ ] -> raise (Exceptions.Empty "Unrel.copy")
    

    (* display (char) arg on stdout as a raw string *)
    let print m' arg _sz check_address_validity: unit =
      let str = strip (D.to_string (fst (eval_exp m' arg check_address_validity))) in
      let str' =
        if String.length str <= 2 then
          String.make 1 (Char.chr (Z.to_int (Z.of_string_base 16 str)))
        else raise (Exceptions.Empty "Unrel.print")
      in
      Log.Stdout.stdout (fun p -> p "%s" str')
      

   
  end


