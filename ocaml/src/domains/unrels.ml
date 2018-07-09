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
         
    let set_lval_to_addr lv a m check_address_validity =
      match m with
      | BOT -> BOT, Taint.Set.singleton Taint.BOT
      | Val m' ->
         let taint = ref (Taint.Set.empty) in
         let m2 = USet.map (fun u ->
                      let u', t = Unrel.set_lval_to_addr lv a u check_address_validity in
                      taint := Taint.Set.add !taint t) m'
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
               | [], [u] | [u], [] -> Unrel.empty
               | u1::_, u2::_ -> Unrel.widen u1 u2
         in
         Val u'
  end
