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

module L = Log.Make(struct let name = "unrels" end)
         
(* k-set of Unrel *)
module Make(D: Unrel.T) =
  struct
    module U = Unrel.Make(D)
    type ut = U.t * Log.History.t

    type t =
      | BOT
      | Val of ut list

    let init () = Val [U.empty, Log.History.new_ [] ""]
                
    let bot = BOT
            
    let is_bot m = m = BOT

    let imprecise_exn r =
      raise (Exceptions.Too_many_concrete_elements (Printf.sprintf "value of register %s is too much imprecise" (Register.name r)))
      
    let value_of_register m r =
      match m with
      | BOT -> raise (Exceptions.Empty (Printf.sprintf "unrel.value_of_register:  environment is empty; can't look up register %s" (Register.name r)))
      | Val m' ->
         let v = List.fold_left (fun prev (u, _) ->
                     let v' = U.value_of_register u r in
                     match prev with
                     | None -> Some v'
                     | Some v ->
                        if Z.compare v v' = 0 then prev
                        else imprecise_exn r
                   ) None m'
         in
           match v with
           | None -> imprecise_exn r
           | Some v' -> v'

         
    let string_of_register m r =
      match m with
      | BOT ->  raise (Exceptions.Empty (Printf.sprintf "string_of_register: environment is empty; can't look up register %s" (Register.name r)))
      | Val m' -> List.fold_left (fun acc (u, _) -> (U.string_of_register u r)^acc) "" m'

    let forget m =
      match m with
      | BOT -> BOT
      | Val m' -> Val (List.map (fun (u, ids) -> U.forget u, ids) m')

    let is_subset m1 m2 =
      match m1, m2 with
      | BOT, _ -> true
      | _, BOT -> false
      | Val m1', Val m2' ->
         List.for_all (fun (u1, _ids2) ->
             List.exists (fun (u2, _ids1) -> U.is_subset u1 u2) m2') m1'

    let remove_register r m =
      match m with
      | Val m' -> Val (List.map (fun (u, ids) -> U.remove_register r u, ids) m')
      | BOT -> BOT

    let forget_lval lv m check_address_validity =
       match m with
      | BOT -> BOT
      | Val m' -> Val (List.map (fun (u, ids) -> U.forget_lval lv u check_address_validity, ids) m')
                
    let add_register r m w =
      match m with
      | BOT -> BOT
      | Val m' -> Val (List.map (fun (u, id) -> U.add_register r u w, id) m')

    let to_string m id =
      match m with
      | BOT    -> ["_"]
      | Val m' ->
         List.fold_left (fun acc (u, id') ->
                              let msg = Log.History.get_msg id' in
                              (Printf.sprintf "\n[node %d - unrel %d]\ndescription =  %s" id id' msg)::((U.to_string u)@acc)
                             ) [] m'

    let imprecise_value_of_exp e =
      raise (Exceptions.Too_many_concrete_elements (Printf.sprintf "concretisation of expression %s is too much imprecise" (Asm.string_of_exp e true)))
      
    let value_of_exp m e check_address_validity =
      match m with
      | BOT -> raise (Exceptions.Empty "unrels.value_of_exp: environment is empty")
      | Val m' -> let v = List.fold_left (fun prev (u, _) ->
                     let v' = U.value_of_exp u e check_address_validity in
                     match prev with
                     | None -> Some v'
                     | Some v ->
                        if Z.compare v v' = 0 then prev
                        else imprecise_value_of_exp e
                   ) None m'
         in
           match v with
           | None -> imprecise_value_of_exp e
           | Some v' -> v'

                             
    (* auxiliary function that will join all set elements *)
    let merge m =
      L.info2 (fun p -> p "threshold on unrel number is exceeded: merging all the unrels into one (join)");
      match m with
      | [] -> []
      | u::tl ->
         let u', pred = List.fold_left (fun (u', pred) (u, id) -> U.join u' u, id::pred) (fst u, [snd u]) tl in
         [u', Log.History.new_ pred "merge"]
                           
               
    let set dst src m check_address_validity: (t * Taint.Set.t) =
      L.debug2 (fun p -> p "set %s <- %s" (Asm.string_of_lval dst true) (Asm.string_of_exp src true));
      match m with
      | BOT    -> BOT, Taint.Set.singleton Taint.BOT
      | Val m' ->
         let bot = ref false in
         let mres, t = List.fold_left (fun (m', t) (u, msg) ->
                           try
                             let u', t' = U.set dst src u check_address_validity in
                             (u', Log.History.new_ [msg] "")::m', Taint.Set.add t' t
                           with _ ->
                             bot := true;
                             m', t)  ([], Taint.Set.empty) m'
         in
         let card = List.length mres in
         if !bot && card = 0 then
             BOT, Taint.Set.singleton Taint.BOT
         else
           Val mres, t
         
  
               
    let set_lval_to_addr lv addrs m check_address_validity =
      match m with
      | BOT -> BOT, Taint.Set.singleton Taint.BOT
      | Val m' ->
         let m' =
           (* check if resulting size would not exceed the kset bound *)
           if (List.length m') + (List.length addrs) > !Config.kset_bound then
               merge m'
           else m'
         in
         let taint = ref (Taint.Set.singleton Taint.U) in
         let m2 =
           List.fold_left (fun acc (a, msg) ->
               let m' =
                 List.map (fun (u, prev_id) ->
                     let u', t = U.set_lval_to_addr lv a u check_address_validity in                     
                     taint := Taint.Set.add t !taint;
                     let id = Log.History.new_ [prev_id] msg in
                     u', id) m'
               in
               acc @ m'
             ) [] addrs
         in
         Val m2, !taint

  
    let remove_duplicates m1 m2 =
      let one_check ulist (u, id) =
        if List.exists (fun (u', _id') -> U.is_subset u' u && U.is_subset u u') ulist then
          ulist
        else
          (u, id)::ulist
      in
      let filter m =
        match m with
        | [] -> []
        | v1::tl -> List.fold_left one_check [v1] tl
      in
      let m1' = filter m1 in
      let m2' = filter m2 in
      List.fold_left one_check m1' m2'
      
    let join m1 m2 =
      match m1, m2 with
      | BOT, m | m, BOT -> m
      | Val m1, Val m2 ->
         let m1' = List.map (fun (m, id) -> m, Log.History.new_ [id] "") m1 in
         let m2' = List.map (fun (m, id) -> m, Log.History.new_ [id] "") m2 in
         let m = remove_duplicates m1' m2' in
         (* check if the size of m exceeds the threshold *)
         if List.length m > !Config.kset_bound then
           Val (merge (m1'@m2'))
         else
           Val m

    let meet m1 m2 =
      let bot = ref false in
      let add_one_meet m u1 u2 =
        try
          let u' = U.meet (fst u1) (fst u2) in
          if List.exists (fun (u, _) -> U.is_subset u' u && U.is_subset u u') m then m
          else
            let id = Log.History.new_ [snd u1; snd u2] "meet" in
              (u', id)::m
        with Exceptions.Empty _ ->
          bot := true;
          m
      in
      match m1, m2 with
      | BOT, _ | _, BOT -> BOT
      | Val m1', Val m2' ->
         let m' =
           List.fold_left (fun m' u1 -> List.fold_left (fun m u2 -> (add_one_meet m u1 u2)) m' m2') [] m1'
         in
         let card = List.length m' in
         if card > !Config.kset_bound then
           Val (merge m')
         else
           (* check if result is BOT *)
           if card = 0 && !bot then
             BOT
           else
             Val m'

    let widen prev_m m =
      L.analysis (fun p -> p "************************ widening ************\n\n\n");
      match prev_m, m with
      | BOT, m | m, BOT  -> m
      | Val prev_m', Val m' ->
         let mm1 = merge prev_m' in
         let mm2 = merge m' in
         match mm1, mm2 with
         | [], _ | _, [] -> Val ([])
         | (u1, id1)::_, (u2, id2)::_ ->
            Val ([U.widen u1 u2, Log.History.new_ [id1 ; id2] "widen"])


            
    let fold_on_taint m f =
      match m with
      | BOT -> BOT,  Taint.Set.singleton Taint.BOT
      | Val m' ->
         let m', t' =
           List.fold_left (fun (m, t) (u, id)  ->
               let u', t' = f u in
               (u', id)::m, Taint.Set.add t' t) ([], Taint.Set.singleton Taint.U) m'
         in
         Val m', t'
         
    let set_memory_from_config a conf nb m check_address_validity: t * Taint.Set.t = 
      if nb > 0 then
        fold_on_taint m (U.set_memory_from_config a conf nb check_address_validity)
      else
        m, Taint.Set.singleton Taint.U

         
    let set_register_from_config r conf m = fold_on_taint m (U.set_register_from_config r conf)
         
    let taint_register_mask reg taint m = fold_on_taint m (U.taint_register_mask reg taint)

    let span_taint_to_register reg taint m = fold_on_taint m (U.span_taint_to_register reg taint)

    let taint_address_mask a taints m = fold_on_taint m (U.taint_address_mask a taints)

    let span_taint_to_addr a t m = fold_on_taint m (U.span_taint_to_addr a t)

    let taint_lval lv taint m check_address_validity = fold_on_taint m (U.taint_lval lv taint check_address_validity)
                              
    let compare m check_address_validity e1 op e2 =
      L.debug2 (fun p -> p "compare: %s %s %s" (Asm.string_of_exp e1 true) (Asm.string_of_cmp op) (Asm.string_of_exp e2 true));
      match m with
      | BOT -> BOT, Taint.Set.singleton Taint.BOT
      | Val m' ->
         let bot = ref false in
         let mres, t = List.fold_left (fun (m', t) (u, msgs) ->
                           try                            
                             let ulist', tset' = U.compare u check_address_validity e1 op e2 in
                             List.fold_left (fun  m' u -> (u, msgs)::m') m' ulist', Taint.Set.singleton tset'
                           with Exceptions.Empty _ ->
                             bot := true;
                             m', t) ([], Taint.Set.singleton Taint.U) m'
         in
         let card = List.length mres in
         if !bot && card = 0 then
           BOT, Taint.Set.singleton Taint.BOT
         else
           if card > !Config.kset_bound then
             Val (merge mres), Taint.Set.singleton (Taint.Set.fold Taint.logor t Taint.U)
           else
             Val mres, t

    let mem_to_addresses m e check_address_validity =
      L.debug2 (fun p -> p "mem_to_addresses %s" (Asm.string_of_exp e true));
      match m with
      | BOT -> raise (Exceptions.Empty (Printf.sprintf "Environment is empty. Can't evaluate %s" (Asm.string_of_exp e true)))
      | Val m' ->
         List.fold_left (fun (addrs, t) u ->
             try
               let addrs', t' = U.mem_to_addresses (fst u) e check_address_validity in
               Data.Address.Set.union addrs addrs', Taint.Set.add t' t
             with _ -> addrs, t) (Data.Address.Set.empty, Taint.Set.singleton Taint.U) m' 

    let taint_sources e m check_address_validity =
      match m with
      | BOT -> Taint.Set.singleton Taint.BOT
      | Val m' ->  List.fold_left (fun t u -> Taint.Set.add (U.taint_sources e (fst u) check_address_validity) t) (Taint.Set.singleton Taint.U) m'

    let get_offset_from e cmp terminator upper_bound sz m check_address_validity =
        match m with
      | BOT -> raise (Exceptions.Empty "Unrels.get_offset_from: environment is empty")
      | Val m' ->
         let res =
           List.fold_left (fun o u ->
               let o' = U.get_offset_from e cmp terminator upper_bound sz (fst u) check_address_validity in
               match o with
               | None -> Some o'
               | Some o ->
                  if o = o' then Some o
                  else raise (Exceptions.Empty "Unrels.get_offset_from: different offsets found")) None m'
         in
         match res with
         | Some o -> o
         | _ -> raise (Exceptions.Empty "Unrels.get_offset_from: undefined offset")
            
    let get_bytes e cmp terminator (upper_bound: int) (sz: int) (m: t) check_address_validity =
          match m with
      | BOT -> raise (Exceptions.Empty "Unrels.get_bytes: environment is empty")
      | Val m' ->
         let res =
           List.fold_left (fun acc u ->
             let len, bytes = U.get_bytes e cmp terminator upper_bound sz (fst u) check_address_validity in
             match acc with
             | None -> Some (len, bytes)
             | Some (len', bytes') ->
                if len = len' then
                  if Bytes.equal bytes bytes' then
                    acc
                  else
                    raise (Exceptions.Empty "Unrels.get_bytes: incompatible set of bytes to return")
                else
                  raise (Exceptions.Empty "Unrels.get_bytes: incompatible set of bytes to return")       
             ) None m'
         in
         match res with
         | Some r -> r
         | None -> raise (Exceptions.Empty "Unrels.get_bytes: undefined bytes to compute")

    let copy m dst arg sz check_address_validity =
      match m with
      | Val m' -> Val (List.map (fun (u, msg) -> U.copy u dst arg sz check_address_validity, msg) m')
      | BOT -> BOT

    let copy_hex m dst src nb capitalise pad_option word_sz check_address_validity =
      match m with
      | Val m' ->
         let m, n =
           List.fold_left (fun (acc, n) (u, msg) ->
               let u', n' = U.copy_hex u dst src nb capitalise pad_option word_sz check_address_validity in
               let nn =
                 match n with
                 | None -> Some n'
                 | Some n  ->
                    if n = n' then Some n' 
                    else raise (Exceptions.Empty "diffrent lengths of  bytes copied in Unrels.copy_hex")
               in
               (u', msg)::acc, nn
             )  ([], None) m'
         in
         begin
           match n  with
           | Some n' -> Val m, n'
           | None -> raise (Exceptions.Empty "uncomputable length of  bytes copied in Unrels.copy_hex")
         end
      | BOT -> BOT, 0

    let copy_int m dst src nb capitalise pad_option word_sz check_address_validity =
      match m with
      | Val m' ->
         let m, n =
           List.fold_left (fun (acc, n) (u, msg) ->
               let u', n' = U.copy_int u dst src nb capitalise pad_option word_sz check_address_validity in
               let nn =
                 match n with
                 | None -> Some n'
                 | Some n  ->
                    if n = n' then Some n' 
                    else raise (Exceptions.Empty "diffrent lengths of  bytes copied in Unrels.copy_int")
               in
               (u', msg)::acc, nn
             )  ([], None) m'
         in
         begin
           match n  with
           | Some n' -> Val m, n'
           | None -> raise (Exceptions.Empty "uncomputable length of  bytes copied in Unrels.copy_int")
         end
      | BOT -> BOT, 0
             
    let print m arg sz check_address_validity =
      match m with
      | Val m' -> List.iter (fun (u, _) -> U.print u arg sz check_address_validity) m'; m
      | BOT -> Log.Stdout.stdout (fun p -> p "_"); m

    let print_hex m src nb capitalise pad_option word_sz check_address_validity =
      match m with
      | BOT -> Log.Stdout.stdout (fun p -> p "_"); m, raise (Exceptions.Empty "Unrels.print_hex: environment is empty")
      | Val m' ->
         match m' with
         | [(u, msg)] ->
            let u', len = U.print_hex u src nb capitalise pad_option word_sz check_address_validity in
            Val ([u', msg]), len
         | _ -> raise (Exceptions.Too_many_concrete_elements "U.print_hex: implemented only for one unrel only")

    let print_int m src nb capitalise pad_option word_sz check_address_validity =
      match m with
      | BOT -> Log.Stdout.stdout (fun p -> p "_"); m, raise (Exceptions.Empty "Unrels.print_int: environment is empty")
      | Val m' ->
         match m' with
         | [(u, msg)] ->
            let u', len = U.print_int u src nb capitalise pad_option word_sz check_address_validity in
            Val ([u', msg]), len
         | _ -> raise (Exceptions.Too_many_concrete_elements "U.print_hex: implemented only for one unrel only")

    let copy_until m dst e terminator term_sz upper_bound with_exception pad_options check_address_validity =
       match m with
       | BOT -> 0, BOT
       | Val m' ->
          match m' with
          | [(u, msg)] ->
             let len, u' = U.copy_until u dst e terminator term_sz upper_bound with_exception pad_options check_address_validity in
             len, Val ([u', msg])
         | _ -> raise (Exceptions.Too_many_concrete_elements "U.copy_until: implemented only for one unrel only")

    let print_until m e terminator term_sz upper_bound with_exception pad_options check_address_validity =
      match m with
       | BOT -> Log.Stdout.stdout (fun p -> p "_"); 0, BOT
       | Val m' ->
          match m' with
          | [(u, msg)] ->
             let len, u' = U.print_until u e terminator term_sz upper_bound with_exception pad_options check_address_validity in
             len, Val ([u', msg])
          | _ -> raise (Exceptions.Too_many_concrete_elements "U.print_until: implemented only for one unrel only")

    let copy_chars m dst src nb pad_options check_address_validity =
      match m with
      | BOT -> BOT
      | Val m' -> Val (List.map (fun (u, msg) -> U.copy_chars u dst src nb pad_options check_address_validity, msg) m')

    let print_chars m src nb pad_options check_address_validity =
      match m with
      | BOT ->
         Log.Stdout.stdout (fun p -> p "_");
         BOT, 0
         
      | Val ([u, msg]) ->
         let u', len = U.print_chars u src nb pad_options check_address_validity in
         Val ([u', msg]), len

      | _ -> raise (Exceptions.Too_many_concrete_elements "U.print_chars: implemented only for one unrel only")
         
     

    let copy_register r dst src =
      match src with
      | Val src' ->
         begin
           let dst' =
             match dst with
             | Val dst' -> dst'
             | BOT -> []
           in
           Val (List.fold_left (fun acc (u1,  msg1) ->
                    let acc' = List.map (fun (u2, _) -> U.copy_register r u1 u2, msg1) src' in
                    acc' @ acc)
                  [] dst' )
         end
      | BOT -> BOT

    let get_taint v m check_address_validity =
      match m with
      | BOT -> Taint.BOT
      | Val m' -> List.fold_left (fun prev_t (u, _log) ->
                      let t = U.get_taint v u check_address_validity in
                    Taint.join prev_t t) Taint.U m'
  end
