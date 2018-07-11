(*
    This file is part of BinCAT.
    Copyright 2014-2018 - Airbus

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

(* k-set of Unrel *)
module Make(D: Unrel.T) =
  struct
    module U = Unrel.Make(D)
    module USet = Set.Make(struct type t = U.t let compare = U.total_order end)
    type t =
      | BOT
      | Val of USet.t

    let init () = USet.singleton Unrel.empty
                
    let bot = BOT
            
    let is_bot m = m = BOT

    let imprecise_exn r =
      raise (Exceptions.too_many_concrete_elements (Printf.sprintf "value of register %s is too much imprecise" (Register.name r)))
      
    let value_of_register m r =
      match m with
      | BOT -> raise (Exceptions.Empty (Printf.sprintf "unrel.value_of_register:  environment is empty; can't look up register %s" (Register.name r)))
      | Val m' ->
         let v = USet.fold (fun u prev ->
                     let v' = Unrel.value_of_register u r in
                     match prev with
                     | None -> Some v'
                     | Some v ->
                        if Z.compare z z' = 0 then prev
                        else imprecise_exn r
                   ) m' None
         in
           match v with
           | None -> imprecise_exn r
           | Some v' -> v'

         
    let string_of_register m r =
      match m with
      | BOT ->  raise (Exceptions.Empty (Printf.sprintf "string_of_register: environment is empty; can't look up register %s" (Register.name r)))
      | Val m' -> USet.fold (fun acc u -> (Unrel.value_of_register u)^acc) "" m'

    let forget m = USet.map Unrel.forget

    let is_subset m1 m2 =
      match m1, m2 with
      | BOT, _ -> true
      | _, BOT -> false
      | Val m1', Val m2' ->
         USet.for_all (fun u1 ->
             USet.exists (fun u2 -> Unrel.is_subset u1 u2) m2) m1'

    let remove_register r m =
      match m with
      | Val m' -> Val (USet.map (Unrel.remove_register r) m')
      | BOT -> BOT

    let forget_lval lv m check_address_validity =
       match m with
      | BOT -> BOT
      | Val m' -> Val (USet.map (fun u -> Unrel.forget_lval lv u check_address_validity) m')
                
    let add_register r m =
      match m with
      | BOT -> Unrel.add_register r (Unrel.empty)
      | Val m' -> Val (USet.map (Unrel.add_register r) m')

    let to_string m =
      match m with
      | BOT    -> ["_"]
      | Val m' -> USet.fold (fun u acc -> (Unrel.to_string u) ^ acc) m' []

    let imprecise_value_of_exp e =
      raise (Exceptions.too_many_concrete_elements (Printf.sprintf "concretisation of expression %s is too much imprecise" (Asm.string_of_exp e true)))
      
    let value_of_exp m e check_address_validity =
      match m with
      | BOT -> raise (Exceptions.Empty "unrels.value_of_exp: environment is empty")
      | Val m' -> let v = USet.fold (fun u prev ->
                     let v' = Unrel.value_of_exp u e check_address_validity in
                     match prev with
                     | None -> Some v'
                     | Some v ->
                        if Z.compare z z' = 0 then prev
                        else imprecise_value_of_exp e
                   ) m' None
         in
           match v with
           | None -> imprecise_value_of_exp r
           | Some v' -> v'

    let set dst src m check_address_validity: (t * Taint.Set.t) =
      match m with
      | BOT    -> BOT, Taint.Set.singleton Taint.U
      | Val m' ->
         let taint = ref (Taint.Set.empty) in
         let m2 = USet.map (fun u ->
                      let u', t = Unrel.set dst src u check_address_validity in
                      taint := Taint.S.add !taint t) m'
         in
         Val m2, !taint
         
    let set_lval_to_addr lv addrs m check_address_validity =
      match m with
      | BOT -> BOT, Taint.BOT
      | Val m' ->
         let m' =
           (* check if resulting size would not exceed the kset bound *)
           if (USet.cardinal m') + (List.length addrs) > !Config.kset_bound then
             merge m'
           else m'
         in
         let taint = ref (Taint.Set.empty) in
         let m2 =
           List.fold_left (fun acc a ->
               let m' =
                 USet.map (fun u ->
                     let u', t = Unrel.set_lval_to_addr lv a u check_address_validity in
                     taint := Taint.Set.add !taint t) m'
               in
               USet.join acc m'
             ) USet.empty addrs
         in
         Val m2, !taint

    let merge m =
      let ulist = Uset.elements m in
      match ulist with
      | [] -> USet.empty
      | u::tl -> USet.singleton (List.fold_left (acc u -> Unrel.join acc u) u tl)
         
    let join m1 m2 =
      match m1, m2 with
      | BOT, m | m, BOT -> m
      | Val m1', Val m2' ->
         let m = USet.join m1' m2' in
         (* check if the size of m exceeds the threshold *)
         if USet.cardinal m > !Config.kset_bound then
           Val (USet.join (merge m1' ) (merge m2'))
         else
           Val m'

    let meet m1 m2 =
      let bot = ref false in
      let add_one_meet m u1 u2 =
        try
          USet.add Unrel.meet u1 u2 m
        with Exceptions.Empty _ ->
          bot_nb := true;
          m'
      in
      match m1, m2 with
      | BOT, m | m, BOT -> BOT
      | Val m1', Val m2' ->
         let m' =
           USet.fold (fun u1 m' ->
               let mm = USet.fold (add_one_meet m' u1) m2' USet.empty in
               USet.join mm m'
             ) m1' USet.empty
         in
         let card = USet.cardinal m' in
         if card > !Config.kset_bound then
           Val (merge m')
         else
           (* check if result is BOT *)
           if card = 0 && !bot then
             BOT
           else
             Val m'

    let widen m1 m2 =
      match m1, m2 with
      | BOT, m | m, BOT  -> m
      | Val m1', Val m2' ->
         let mm1 = merge m1' in
         let mm2 = merge m2' in
         let u' =
           match USet.elements mm1, USet.elements mm2 with
               | [], _ | _, [] -> Unrel.empty
               | u1::_, u2::_ -> Unrel.widen u1 u2
         in
         Val u'

            
    let fold_on_taint m f =
      match m with
      | BOT -> BOT,  Taint.Set.singleton Taint.BOT
      | Val m' ->
         let m', t' =
           USet.fold (fun u (m, t) ->
               let u', t' = f u in
               Uset.add m u, Taint.Set.add t' t) m' (USet.empty, Taint.Set.empty)
         in
         Val m', t'
         
    let set_memory_from_config a r conf nb m: t * Taint.Set.t = 
      if nb > 0 then
        fold_on_taint (Unrel.set_mmeory_from_config a r conf)
      else
        m, Taint.Set.singleton Taint.U

   
         
    let set_register_from_config r region conf m = fold_on_taint (Unrel.set_register_from_config r region conf) m
         
    let taint_register_mask reg taint m = fold_on_taint (Unrel.taint_register_mask reg taint) m

    let span_taint_to_register reg taint m = fold_on_taint (Unrel.span_taint_to_register reg taint) m

    let taint_address_mask a taints m = fold_on_taint (Unrel.taint_address_mask a taints) m

    let span_taint_to_addr a t m = fold_on_taint (Unrel.span_taint_to_addr a t) m

    let compare m check_address_validity e1 op e2 =
      match m with
      | BOT -> BOT, Taint.Set.singleton Taint.BOT
      | Val m' ->
         let bot = ref false in
         let mres, t = USet.fold (fun u (m', t) ->
                        try
                          let ulist', tset' = Unrel.compare u check_validity e1 op e2 in
                          List.fold_left (fun m' u -> USet.add m' u) m' ulist', tset'
                          with Empty _ ->
                            bot := true;
                            m', t) m' (USet.empty, Taint.Set.singleton Taint.U) 
         in
         let card = USet.cardinal mres in
         if !bot && card = 0 then
           BOT, Taint.Set.singleton Taint.BOT
         else
           if card > !Config.kset_bound then
             Val (merge mres), Taint.Set.fold Taint.logor t Taint.U
           else
             Val mres, t

    let mem_to_addresses m e check_address_validity =
      match m with
      | BOT -> raise (Exceptions.Empty (Printf.sprintf "Environment is empty. Can't evaluate %s" (Asm.string_of_exp e true)))
      | Val m' ->
         USet.fold (fun u (addrs, t) ->
             let addrs', t' = mem_to_addresses u in
             Data.Address.Set.join addrs addrs addrs', Taint.Set.add t' t) m' (Data.Address.Set.empty, Taint.Set.singleton Taint.U)

    let taint_sources e m check_address_validity =
      match m with
      | BOT -> Taint.Set.singleton Taint.BOT
      | Val m' ->  USet.fold (fun u t -> Taint.Set.join t (Unrel.taint_sources e u check_address_validity)) m' Taint.Set.empty

    let get_offset_from e cmp terminator upper_bound sz m check_address_validity =
        match m with
      | BOT -> raise (Exceptions.Empty "Unrels.get_offset_from: environment is empty")
      | Val m' ->
         let res =
           Uset.fold (fun u o ->
               let o' = Unrel.get_offset_from e cmp terminator upeer_bound sz u check_address_validity in
               match o' with
               | None -> o
               | Some o' ->
                  if Z.compare o o' = 0 then Some o
                  else raise (Exceptions.Empty "Unrels.get_offset_from: different offsets found")) m' None
         in
         match res with
         | Some o -> o
         | _ -> raise (Exceptions.Empty "Unrels.get_offset_from: undefined offset")
            
    let get_bytes e cmp terminator (upper_bound: int) (sz: int) (m: t) check_address_validity =
          match m with
      | BOT -> raise (Exceptions.Empty "Unrels.get_bytes: environment is empty")
      | Val m' ->
         let res =
           USet.fold (fun u acc ->
             let bytes, len = Unrel.get_bytes e cmp terminator upper_bound sz u chack_address_validity in
             match acc with
             | None -> Some (bytes, len)
             | Some (bytes', len') ->
                if len = len' then
                  if Bytes.equal bytes bytes' then
                    acc
                  else
                    raise (Exceptions.Empty "Unrels.get_bytes: incompatible set of bytes to return")
                else
                  raise (Exceptions.Empty "Unrels.get_bytes: incompatible set of bytes to return")       
             ) m' None
         in
         match res with
         | Some r -> r
         | None -> raise (Exceptions.Empty "Unrels.get_bytes: undefined bytes to compute")

    let copy m dst arg sz check_address_validity =
      match m with
      | Val m' -> Val (USet.map (fun u -> Unrel.copy u dst arg sz check_address_validity))
      | BOT -> BOT

    let print m arg sz check_address_validity =
      match m with
      | Val m' -> USet.iter (fun u -> Unrel.print u arg sz check_address_validity); m
      | BOT -> Log.Stdout.stdout (fun p -> p "_"); m

    let print_hex m src nb capitalise pad_option word_sz check_address_validity =
      match m with
      | BOT -> Log.Stdout.stdout (fun p -> p "_"); m, raise (Exceptions.Empty "Unrels.print_hex: environment is empty")
      | Val m' ->
         match USet.elements m' with
         | [u] ->
            let u', len = Unrel.print_hex u src nb capitalise pad_option word_sz check_address_validity in
            Val (USet.singleton u'), len
         | _ -> raise (Exceptions.Too_many_concrete_elements "Unrel.print_hex: implemented only for one unrel only")

    let copy_until m' dst e terminator term_sz upper_bound with_exception pad_options check_address_validity =
       match m with
       | BOT -> 0, BOT
       | Val m' ->
          match USet.elements m' with
          | [u] ->
             let u', len = Unrel.copy_until u src nb capitalise pad_option word_sz check_address_validity in
             Val (USet.singleton u'), len
         | _ -> raise (Exceptions.Too_many_concrete_elements "Unrel.copy_until: implemented only for one unrel only")

    let print_until m e terminator term_sz upper_bound with_exception pad_options check_address_validity =
      match m with
       | BOT -> Log.Stdout.stdout (fun p -> p "_"); 0, BOT
       | Val m' ->
          match USet.elements m' with
          | [u] ->
             let len, u' = Unrel.print_until u e terminator term_sz upper_bound with_exception pad_options check_address_validity in
             len, Val (USet.singleton u')
          | _ -> raise (Exceptions.Too_many_concrete_elements "Unrel.print_until: implemented only for one unrel only")

    let copy_chars m dst src nb pad_options check_address_validity =
      match m with
      | BOT -> BOT
      | Val m' -> Val (USet.map (fun u -> Unrel.copy_chars u dst src nb pad_options check_address_validity) m')

    let print_chars m' src nb pad_options check_address_validity =
      match m with
      | Val m' -> Val (USet.map (fun u -> Unrel.print_chars u src nb pad_options chack_address_validity) m')
      | BOT -> Log.Stdout.stdout (fun p -> p "_"); BOT

    let copy_register r dst src =
        match dst, src with
        | Val dst', Val src' -> Val (Uset.fold (fun u1 acc ->
                                         let acc' = USet.map (fun u2 -> Unrel.copy_register r u1 u2) src' in
                                         Uset.join acc' acc)
                                         dst' USet.empty)
        | BOT, Val src' ->
           let v = Env.find k src' in Val (let m = Env.empty in Env.add k v m)
        | _, _ -> BOT
  end
