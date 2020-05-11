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

module A = Data.Address
module T = TypedC
         
(** offset type in a structure *)
type offset = int


(** abstract data type for type reconstruction *)
module Class =
  struct
  
    type t =  {
    allocator: A.t option;
    constructor: A.t option;
    destructor: A.t option;
    vtable: (offset * A.t) list;
    members: (offset * T.typ) list;
      }
            
    let equal c1 c2 =
      let eq v1 v2 =
            match v1, v2 with
            | None, _ | _, None -> true
            | Some a1, Some a2 -> A.equal a1 a2
      in
      let eq_mem_list l1 l2 =
        try
          List.for_all2 (fun (o1, t1) (o2, t2) ->
              o1 = o2 && T.equals_typ t1 t2) l1 l2
        with _ -> false
      in
      let eq_vtables v1 v2 =
        try
          List.for_all2 (fun (o1, a1) (o2, a2) ->
              o1 = o2 && A.equal a1 a2) v1 v2
        with _ -> false
      in
      eq c1.allocator c2.allocator &&
        eq c1.constructor c2.constructor &&
          eq c1.destructor c2.destructor &&
            eq_vtables c1.vtable c2.vtable &&
              eq_mem_list c1.members c2.members

    let to_string c =
      let of_opt a =
          match a with
          | None -> "?"
          | Some a -> A.to_string a
      in
      let of_vtable vtable =
          List.fold_left (fun s (o, a) ->
              (string_of_int o)^": "^(A.to_string a)^" "^s) "" vtable
      in
      let of_members members =
        List.fold_left (fun s (o, t) ->
            (string_of_int o)^": "^(T.string_of_typ t)^" "^s) "" members
      in
      "{"
      ^ "allocator: "^ (of_opt c.allocator) ^";\n"
      ^ "constructor: " ^ (of_opt c.constructor) ^";\n"
      ^ "destructor: " ^ (of_opt c.destructor) ^";\n"
      ^ "vtable: " ^ (of_vtable c.vtable) ^";\n"
      ^ "members: " ^ (of_members c.members) ^ "}"
  end

(** abstract data type *)
type t =
  | C of T.typ
  | CPP of Class.t
  | BOT
  | UNKNOWN

(** type of function signatures *)
type ftyp = (t * string) list option * t (** arg types, return type *)
          
let to_string t =
  match t with
  | C t' -> T.string_of_typ t'
  | CPP c -> Class.to_string c
  | BOT -> "_"
  | UNKNOWN -> "?"

let join t1 t2 =
  match t1, t2 with
  | BOT, t | t, BOT -> t
  | C t1', C t2' when T.equals_typ t1' t2' -> t1
  | _ , _ -> UNKNOWN

let meet t1 t2 =
  match t1, t2 with
  | BOT, _ | _, BOT -> BOT
  | C t1', C t2' when T.equals_typ t1' t2' -> t1
  | UNKNOWN, t | t, UNKNOWN -> t
  | _, _ -> raise (Exceptions.Analysis (Exceptions.Empty "types.meet"))

let is_subset t1 t2 =
  match t1, t2 with
  | BOT, _ -> true
  | _, BOT -> false
  | C t1', C t2' -> T.equals_typ t1' t2'
  | C _, CPP _ -> true
  | CPP c1, CPP c2 -> Class.equal c1 c2
  | _, UNKNOWN -> true
  | _, _ -> false

let equal t1 t2 =
  match t1, t2 with
  | BOT, BOT -> true
  | UNKNOWN, UNKNOWN -> false
  | C t1, C t2 -> T.equals_typ t1 t2
  | _, _ -> false

(** data structure for the typing rules of import functions *)
let typing_rules : (string, ftyp) Hashtbl.t = Hashtbl.create 5

let reset () =
  Hashtbl.reset typing_rules;;
