(*
    This file is part of BinCAT.
    Copyright 2014-2020 - Airbus

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

module L = Log.Make(struct let name = "pointer" end)

module A = Data.Address
         
module Make (V: Vector.T) =
  (struct
    type t =
      | BOT
      | Val of (A.region * V.t) (** a pointer is a pair (r, o) where r is the region it points-to and o an offset in that region *)
      | TOP
             
    let bot = BOT
    let top = TOP
    let is_bot p = p = BOT

    let forget p pos =
      match p with
      | BOT  -> BOT
      | TOP  -> TOP
      | Val (r, v) -> Val (r, V.forget v pos)

    let to_z p =
      match p with
      | BOT -> raise (Exceptions.Empty "pointer.to_z: undefined")
      | TOP -> raise (Exceptions.Too_many_concrete_elements "pointer.to_z: imprecise")
      | Val (_r, v) -> V.to_z v

    let to_char p =
      match p with
      | BOT  -> raise (Exceptions.Empty "pointer.to_z: undefined")
      | TOP  -> raise (Exceptions.Too_many_concrete_elements "pointer.to_char: imprecise")
      | Val (_r, v) -> V.to_char v

    let to_string p =
      match p with
      | BOT -> "B0x_"
      | TOP -> "T0x?"
      | Val (r, o) -> Printf.sprintf "%s%s" (A.string_of_region r) (V.to_string o)


    let to_strings p =
      match p with
        | BOT -> "B0x_", "_"
        | TOP -> "T0x?", "?"
        | Val (r, o) ->
           let s, t = V.to_strings o in
           Printf.sprintf "%s%s" (A.string_of_region r) s, t
                      
    let untaint p =
      match p with
      | TOP | BOT  -> p
      | Val (r, o) -> Val (r, V.untaint o)

    let taint p =
      match p with
      | TOP | BOT  -> p
      | Val (r, o) -> Val (r, V.taint o)

    let span_taint p t =
      match p with
      | TOP | BOT  -> p
      | Val (r, o) -> Val (r, V.span_taint o t)
         
    let join p1 p2 =
      match p1, p2 with
      | BOT, p | p, BOT -> p
      | TOP, _ | _, TOP -> TOP
      | Val (r1, o1), Val (r2, o2) ->
         match r1, r2 with
         | A.Global, r | r, A.Global -> Val (r, V.join o1 o2)
         | r1, r2 ->
            if r1 = r2 then Val (r1, V.join o1 o2)
            else BOT

    let widen p1 p2 =
      match p1, p2 with
      | p, BOT | BOT, p -> p
      | TOP, _ | _, TOP -> TOP
      | Val (r1, o1), Val (r2, o2) ->
         match r1, r2 with
         | A.Global, r | r, A.Global ->
            Val (r, V.widen o1 o2)
         | r1, r2 ->
            if r1 = r2 then Val (r1, V.widen o1 o2)
            else BOT


                    
        let of_config c n =
          let r =
            match c with
            | Config.Content (ru, _) -> Data.Address.region_from_config ru
            | Config.CMask ((ru, _), _) -> Data.Address.region_from_config ru
            | Config.Bytes (ru, _) -> Data.Address.region_from_config ru
            | Config.Bytes_Mask ((ru, _), _) -> Data.Address.region_from_config ru
          in
          Val (r, V.of_config c n)

    let meet p1 p2 =
      match p1, p2 with
      | TOP, p | p, TOP      -> p
      | BOT, _ | _, BOT -> BOT
      | Val (r1, o1), Val (r2, o2) ->
         match r1, r2 with
         | A.Global, r | r, A.Global ->
            Val (r, V.meet o1 o2)
         | r1, r2 ->
            if r1 = r2 then
              try Val (r1, V.meet o1 o2)
              with _ -> BOT
            else BOT
              
    let unary op p =
      match p with
      | BOT  -> BOT
      | TOP  -> TOP
      | Val (r, o) ->
         try Val (r, V.unary op o)
         with _ -> BOT
           
    let binary op p1 p2 =
      match p1, p2 with
      | BOT, _ | _, BOT      -> BOT
      | TOP, _ | _, TOP      -> TOP
      | Val (r1, o1), Val (r2, o2) ->
         match r1, r2 with
         | A.Global, r | r, A.Global ->
            begin
              try Val (r, V.binary op o1 o2)
              with
              | Exceptions.Error _ as e -> raise e
              | _ -> BOT
            end
         | r1, r2                ->
            try
              if r1 = r2 then Val (r1, V.binary op o1 o2)
              else BOT
            with Exceptions.Too_many_concrete_elements _ -> TOP
              
              
    let of_word w = Val (A.Global, V.of_word w)
      
    let of_addr (r, w): t = Val (r, V.of_word w)
      
    let compare p1 op p2 =
      match p1, p2 with
      | BOT, BOT -> op = Asm.EQ || op = Asm.LEQ
      | BOT, _  -> op = Asm.LEQ || op = Asm.LT
      | _, BOT  -> false
      | _, TOP | TOP, _  -> true
      | Val (r1, o1), Val (r2, o2) ->
         if r1 = r2  then V.compare o1 op o2
         else
           if op = Asm.NEQ then true
           else false
           
    let to_addresses p =
      match p with
      | BOT  -> raise (Exceptions.Empty "pointer.to_addresses: undefined pointer")
      | TOP  -> raise (Exceptions.Too_many_concrete_elements "pointer.to_addresses: imprecise pointer")
      | Val (r, o) -> V.to_addresses r o
         
    let is_subset p1 p2 =
      match p1, p2 with
      | BOT, _ | _, TOP -> true
      | _, BOT | TOP, _  -> false
      | Val (r1, o1), Val (r2, o2) ->
         if r1 = r2 then V.is_subset o1 o2
         else false
           
    let taint_of_config taint n prev: t * Taint.t =
      match prev with
      | Val (r, o) ->
         let o', taint' = V.taint_of_config taint n (Some o) in
         Val (r, o'), taint'
      | _      -> prev, Taint.BOT
        

    let combine p1 p2 l u =
      L.debug2 (fun p -> p "Pointer.combine between %s and %s" (to_string p1) (to_string p2));
      match p1, p2 with
      | BOT, _ | _, BOT  -> BOT
      | TOP, _ | _, TOP  -> TOP
      | Val (r1, o1), Val (r2, o2) ->
         if r1 = r2 then 
           Val (r1, V.combine o1 o2 l u)
         else BOT
           
    let extract p l u =
      match p with
      | BOT | TOP  -> p
      | Val (r, o) ->
         try
           Val (r, V.extract o l u)
         with _ -> BOT

    let from_position p i len =
      L.debug2 (fun x -> x "Pointer.from_position %s %d %d" (to_string p) i len);
      match p with
      | BOT | TOP -> p
      | Val (r, o) ->
         try
           Val (r, V.from_position o i len)
         with _ -> BOT

    let of_repeat_val v v_len nb =
      match v with
      | BOT -> BOT
      | TOP -> TOP
      | Val (region, offset) ->
         let newoffset = V.of_repeat_val offset v_len nb in
         Val (region, newoffset)

         
    let rec concat l =
      L.debug2 (fun p -> p "concat len %d" (List.length l));
      match l with
      | [ ] -> BOT
      | [v] -> v           
      | v::l' ->
         let v' = concat l' in
         match v, v' with
         | BOT, _ | _, BOT -> BOT
         | TOP, _ | _, TOP -> TOP
         | Val (r1, o1), Val (r2, o2) ->
            if r1 = r2 then
              Val (r1, V.concat o1 o2)
            else BOT
             
    let get_minimal_taint p =
      match p with
      | TOP -> Taint.TOP
      | BOT -> Taint.BOT
      | Val (_, o) -> V.get_minimal_taint o

    let taint_sources p =
      match p with
      | TOP -> Taint.TOP
      | BOT ->  Taint.BOT
      | Val (_, o) -> V.taint_sources o


    let get_taint p =
      match p with
      | TOP -> Taint.TOP
      | BOT ->  Taint.BOT
      | Val (_, o) -> V.get_taint o

    let forget_taint p =
      match p with
      | TOP | BOT -> p
      | Val (r, o) -> Val (r, V.forget_taint o)
                        
    end: Unrel.T)
