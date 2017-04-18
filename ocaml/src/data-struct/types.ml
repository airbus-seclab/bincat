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
  | TInt of int
  | TPTR
  | TStruct of field list * size_t
  | TUNKNOWN
      
and field = offset * t

and size_t = int

and offset = int
  
(** string conversion *)

let rec to_string t =
  match t with
  | TInt 8 -> "BYTE"
  | TInt 16 -> "WORD"
  | TInt 32 -> "DWORD"
  | TPTR -> "PTR"
  | TInt n -> "Int"^(string_of_int n)
  | TStruct (fields, _) -> "{" ^ List.fold_left (fun acc field -> (string_of_field field)^";"^acc) "" fields ^ "}"
  | TUNKNOWN -> ""  

and string_of_field (offset, typ) = (string_of_int offset)^": "^(to_string typ)
  
  (** convert a typ to its pointer counterpart if it is not a basic type *)
  let to_ptr typ =
    match typ with
    | TStruct _ -> TPTR
    | _ -> typ

  let rec identical typ1 typ2 =
    match typ1, typ2 with
    | TInt n1, TInt n2 when n1 = n2 -> true
    | TPTR, TPTR -> true
    | TStruct (s1, sz1) , TStruct (s2, sz2) ->
       if sz1 <> sz2 then
	 false
       else
	 begin
	   try
	     List.for_all2 (fun (o1, t1) (o2, t2) -> o1 = o2 && (identical t1 t2)) s1 s2
	   with _-> false
	 end
    | _, _ -> false	 
       
(** join *)
  let join_of_struct fields1 fields2 =
    List.map2 (fun (o1, t1) (o2, t2) ->
      if o1 = o2 then
	if identical t1 t2 then (o1, t1) else (o1, TUNKNOWN)
      else
	raise Exit) fields1 fields2
      
let join t1 t2 =
  match t1, t2 with
  | TInt n1, TInt n2 when n1 = n2 -> t1
  | TPTR, TPTR -> t1 
  | TStruct (fields1, sz1), TStruct (fields2, _) ->
     begin
       try TStruct (join_of_struct fields1 fields2, sz1) with _ -> TUNKNOWN
     end
  | _, _ -> TUNKNOWN
     
(** meet *)
let meet_of_struct fields1 fields2 =
  try
    List.map2 (fun (o1, t1) (o2, t2) ->
      if o1 = o2 && identical t1 t2 then (o1, t1) else raise Exceptions.Empty) fields1 fields2
  with _ -> raise Exceptions.Empty
      
let meet t1 t2 =
  match t1, t2 with
  | TInt n1, TInt n2 when n1 = n2 -> t1
  | TPTR, TPTR -> t1 
  | TStruct (fields1, sz1), TStruct (fields2, _) -> TStruct (meet_of_struct fields1 fields2, sz1)
  | _, _ -> raise Exceptions.Empty

let subset t1 t2 =
  match t1, t2 with
  | TUNKNOWN, TUNKNOWN -> true
  | _, _ -> identical t1 t2


let typ_of_npk npk_t =
  match npk_t with
  | TypedC.Int (_sign, sz) -> TInt sz
 (* | Newspeak.Scalar Newspeak.Ptr -> TPTR
    | Newspeak.Region (s, z) -> TStruct (List.map (fun (o, t) -> o, typ_of_npk t) s, z)*)
  | _ -> TUNKNOWN
     
