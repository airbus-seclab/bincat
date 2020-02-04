(*
    This file is part of BinCAT.
    Copyright 2014-2019 - Airbus

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
module Class =
  struct
    type offset = int
    type t =  {
    allocator: A.t option;
    constructor: A.t option;
    destructor: A.t option;
    vtable: (offset * A.t) list;
    members: (offset * Types.t) list;
      }
    let equal c1 c2 =
      let eq v1 v2
            match v1, v2 with
            | None, _ | _, None -> true
            | Some a1, Some a2 -> A.equal a1 a2
      in
      let eq_mem_list l1 l2 =
        try
          List.for_all2 (fun (o1, t1) (o2, t2) ->
              o1 = o2 && Types.equal t1 t2) l1 l2
        with _ -> false
      in
      let eq_vtables v1 v2 =
        try
          List.for_all2 (fun (o1, a1) (o2, a2) ->
              o1 = o2 && A.equal a1 a2) v1 v2
      in
      eq c1.allocator c2.allocator &&
        eq c1.construtor c2.constructor &&
          eq c1.destructor c2.destructor &&
            eq_vtables c1.vtable c2.table &&
              eq_list c1.members c2.members

    let to_string c =
      let str_of_opt a str =
        str ^": "^
          (match a with
           | None -> "?"
           | Some a -> A.to_string a
          )^"; "
      in
      let str_of_vtable vtable =
        "vtable (offset: address): "^
          (List.fold_left (fun s (o, a) ->
             (string_of_int o)^": "^(A.to_string a)^" "^s) "" vtable)
      in
      let str_of_mem members =
        "members (offset: type)"^
          (List.fold_left (fun s (o, t) ->
           (string_of_int o)^": "^(Types.to_string t)^" "^s) "" members
          )
      "{" ^ (str_of_opt c.allocator "allocator")^
        (str_of_opt c.destructor "constructor")^
          (str_of_opt c.destructor "destructor")^
        (str_of_vtable c.vtable)^(str_of_mem c.members)"}"
  end

(** abstract data type *)
type t =
  | C of TypedC.typ
  | CPP of Class.t
  | BOT
  | UNKNOWN


let to_string t =
  match t with
  | C t' -> TypedC.string_of_typ t'
  | BOT -> "_"
  | UNKNOWN -> "?"

let typ_of_npk npk_t = T npk_t

let join t1 t2 =
  match t1, t2 with
  | BOT, t | t, BOT -> t
  | C t1', C t2' when TypedC.equals_typ t1' t2' -> t1
  | _ , _ -> UNKNOWN

let meet t1 t2 =
  match t1, t2 with
  | BOT, _ | _, BOT -> BOT
  | C t1', C t2' when TypedC.equals_typ t1' t2' -> t1
  | UNKNOWN, t | t, UNKNOWN -> t
  | _, _ -> raise (Exceptions.Empty "types.meet")

let is_subset t1 t2 =
  match t1, t2 with
  | BOT, _ -> true
  | _, BOT -> false
  | C t1', C t2' -> TypedC.equals_typ t1' t2'
  | C _, CPP _ -> true
  | CPP c1, CPP c2 -> Class.equal c1 c2
  | _, UNKNOWN -> true
  | _, _ -> false

let equal t1 t2 =
  match t1, t2 with
  | BOT, BOT -> true
  | UNKNOWN, UNKNOWN -> false
  | C t1, C t2 -> TypedC.equals_typ t1 t2
  | _, _ -> false
