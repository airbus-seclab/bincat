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

module T =
struct
  type t = { name: string ; sz : int ; is_sp: bool; id : int }
  let compare v1 v2 = v1.id - v2.id
end

let cid = ref 0
include T
module Set = Set.Make(T)

(* contains currently used registers *)
let registers = ref (Set.empty)

let clear () =
  registers := Set.empty;
  cid := 0

let imake name size is_sp =
  let  v = { name = name ; sz = size ; is_sp = is_sp ; id = !cid } in
  registers := Set.add v !registers;
  cid := !cid + 1;
  v
let make ~name ~size = imake name size false

let make_sp ~name ~size = imake name size true

let equal v1 v2 = compare v1 v2 = 0

let fresh_name () = "_bincat_tmp_"^(string_of_int !cid)

let remove r = registers := Set.remove r !registers

let name r = r.name

let size r = r.sz

let used () = Set.elements !registers

let of_name name =  
  try Set.choose (Set.filter (fun r -> r.name = name) !registers)
  with Not_found ->
    raise (Exceptions.Error
             (Printf.sprintf "Register %s not found" name))

let is_stack_pointer r = r.is_sp

let stack_pointer () = Set.choose (Set.filter (fun r -> r.is_sp) !registers)
