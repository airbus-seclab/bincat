(*
    This file is part of BinCAT.
    Copyright 2014-2018 - Airbus Group

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

type status =
  | A (* allocated *)
  | F (* freed *)
  | TOP (* unknown status *)

module Key =
struct
  type t = Data.Address.heap_id_t
  let compare = compare
end
  
module Map = MapOpt.Make(Key)
  
type t =
  | BOT
  | Val of status Map.t

let init () = Val (Map.empty)
