(*
    This file is part of BinCAT.
    Copyright 2014-2022 - Airbus

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

module Status = Core_heap.Status
              
module Key =
struct
  type t = Data.Address.heap_id_t
  let compare = compare
  let to_string addr_id =
    let _, sz = Data.Address.get_heap_region addr_id in
    "H"^(string_of_int addr_id)^"[0, "^(Z.to_string sz) ^ "]="
  let string_of_id = string_of_int
end
  
include Core_heap.Make(Key)
      
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



     
