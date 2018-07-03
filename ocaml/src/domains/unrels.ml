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
  (struct
    module U = Unrel.Make(D)
    module USet = Set.Make(struct type t = U.t let compare = U.total_order end)
    type t =
      | BOT
      | Val of USet.t

    let init () = BOT
                
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
         begin
           match v with
           | None -> imprecise_exn r
         end
         
    let string_of_register m r =
      match m with
      | BOT ->  raise (Exceptions.Empty (Printf.sprintf "string_of_register: environment is empty; can't look up register %s" (Register.name r)))
      | Val m' -> USet.fold (fun acc u -> (Unrel.value_of_register u)^acc) "" m'
             
  end: Domain.T)
