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

module L = Log.Make(struct let name = "heap" end)
         
module Status =
  struct
    type t =
      | BOT (* undefined *)
      | A (* allocated *)
      | F (* freed *)
      | TOP (* unknown status *)
          
    let to_string s =
      match s with
      | BOT -> "_"
      | A -> "A"
      | F -> "F"
      | TOP -> "?"
         
         
    let leq s1 s2 =
      match s1, s2 with
      | TOP, TOP
      | A, A
      | F, F
      | A, TOP
      | F, TOP
      | BOT, _ -> true
      | _, _  -> false

    let join s1 s2 =
      match s1, s2 with
      | A, A -> A
      | F, F -> F
      | BOT, s | s, BOT -> s
      | _, _ -> TOP

    let meet s1 s2 =
      match s1, s2 with
      | A, A -> A
      | F, F -> F
      | TOP, s | s, TOP -> s
      | _, _ -> BOT  
  end
    
module Key =
struct
  type t = Data.Address.heap_id_t
  let compare = compare
end
  
module Map = MapOpt.Make(Key) (* a key not in the map means its status is BOT *)
  
type t =
  | BOT
  | Val of Status.t Map.t

let init () = Val (Map.empty)

let forget m =
  match m with
  | BOT -> BOT
  | Val m' -> Val (Map.map (fun _ -> Status.TOP) m')

let is_bot m = m = BOT

let is_subset m1 m2 =
  match m1, m2 with
  | BOT, _ -> true
  | _, BOT -> false
  | Val m1', Val m2' ->
     try
       Map.iteri (fun k v1 ->
         try
           let v2 = Map.find k m2' in
           if not (Status.leq v1 v2) then
             raise Exit
         with Not_found -> raise Exit) m1';
       true
     with Exit -> false

let to_string m =
  match m with
  | BOT -> ["_"]
  | Val m' ->
     Map.fold (
       fun addr_id status acc ->
         let status' = Status.to_string status in
         let _, sz = Data.Address.get_heap_region addr_id in
     ("H"^(string_of_int addr_id)^"[0, "^(Z.to_string sz)^"]="^status')::acc
     ) m' []

let check_status m addr =
  match m with
  | BOT -> raise (Exceptions.Use_after_free (Data.Address.to_string addr))
  | Val m' ->
     try
       match addr with
       | Data.Address.Heap (id, _), _ ->
          let status = Map.find id m' in
          if status <> Status.A then
            begin
              let str_addr = Data.Address.to_string addr in
              L.analysis (fun p -> p "Use after free on pointer %s" str_addr); 
              raise (Exceptions.Use_after_free str_addr)
            end
       | _ -> ()
     with _ ->
       let str_addr = Data.Address.to_string addr in
       L.analysis (fun p -> p "Use after free on pointer %s"str_addr); 
       raise (Exceptions.Use_after_free str_addr)

let fold apply m1 m2 is_join =
   match m1, m2 with
   | BOT, m | m, BOT -> m
   | Val m1', Val m2' ->
      Val (Map.fold (fun k v2 m' ->
          try
            let v' = Map.find k m' in
            Map.replace k (apply v' v2) m'
          with Not_found ->
                if is_join then
                  Map.add k v2 m'
                else raise (Exceptions.Empty "Heap.fold")
      ) m2' m1')

let join m1 m2 = fold Status.join m1 m2 true
let meet m1 m2 = fold Status.meet m1 m2 false
let widen = join

let alloc m id =
  match m with
  | BOT -> Val (Map.add id Status.A Map.empty)  
  | Val m' -> Val (Map.add id Status.A m')


let dealloc m id =
  match m with
  | BOT -> raise (Exceptions.Empty "Heap.dealloc failed")
  | Val m' ->
     try
       let status = Map.find id m' in
       if status = Status.A then
         Val (Map.replace id Status.F m')
       else
         raise Exceptions.Double_free 
     with Not_found -> raise (Exceptions.Error
                                (Printf.sprintf "unknown heap id %d to deallocate" id))

let weak_dealloc m ids =
  match m with
  | BOT -> raise (Exceptions.Empty "Heap.dealloc failed")
  | Val m' ->
     Val (List.fold_left (fun m' id ->
       try
         let status = Map.find id m' in
         if status = Status.A then
           Map.replace id (Status.join status Status.F) m'
         else
           raise Exceptions.Double_free 
       with Not_found -> raise (Exceptions.Error
                                (Printf.sprintf "unknown heap id %d to weak deallocate" id))
     ) m' ids) 
       
     
