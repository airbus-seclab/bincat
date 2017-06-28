(*
    This file is part of BinCAT.
    Copyright 2014-2017 - Airbus Group

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

(** abstract data type for type reconstruction *)

(** abstract data type *)
type t =
    | T of TypedC.typ
    | UNKNOWN
  

let to_string t =
  match t with
  | T t' -> TypedC.string_of_typ t'
  | UNKNOWN -> "?"
     
let typ_of_npk npk_t = T npk_t

let join t1 t2 =
  match t1, t2 with
   | T t1', T t2' when TypedC.equals_typ t1' t2' -> t1  
   | _ , _ -> UNKNOWN
     
let meet t1 t2 =
  match t1, t2 with
  | T t1', T t2' when TypedC.equals_typ t1' t2' -> t1
  | UNKNOWN, t | t, UNKNOWN -> t
  | _, _ -> raise (Exceptions.Empty "types.meet")

let is_subset t1 t2 =
  match t1, t2 with
  | T t1', T t2' when TypedC.equals_typ t1' t2' -> true
  | _, UNKNOWN -> true
  | _, _ -> false
