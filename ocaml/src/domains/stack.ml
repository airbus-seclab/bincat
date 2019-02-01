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


module L = Log.Make(struct let name = "stack" end)

type stack_frame = Interval.t option (* None is TOP *)


type t =
  | S of stack_frame list (* stack of stack frames *)
  | BOT
  | TOP

let init () = S []

let is_bot s = s = BOT
                     
let add_stack_frame d (v: Z.t option) =
  let stack_frame =
    match v with
    | Some v -> Some (Interval.singleton v)
    | None -> None
  in
  satck_frame::d

let remove_stack_frame d = List.tl d

let forget_stack_pointer d = None::(List.tl d)

let string_of_stack_frame s =
  match s with
  | Some i -> Interval.to_string i
  | None -> "[ -oo ; +oo "

let equal_stack_frame s1 s2 =
  match s1, s2 with
  | None, None ->
  | Some i1, Some i2 -> Interval.equal i1 i2 = 0
                      
let to_string d =
 match s with
 | TOP -> "?"
 | BOT -> "_"
 | S i ->
    let s =
      List.fold_left (fun s i -> (string_of_stack_frame)^" | "^s) " ]" (List.rev d)
    in
    "[ " ^ s

let normalize l u =
  if Z.compare l u < 0 then Some (l, u)
  else None
  
let update_stack_frame d bound =
  match v with
  | None -> TOP::(List.tl d)
  | Some bound ->
     let stack_frame' =
       match List.hd d with
       | None -> None
       | Some (l, u) ->
          if !Config.stack = Config.Decreasing then normalize bound u
             else normalize l bound
     in
     stack_frame'::(List.tl d)

let check_write d base_address len = 
                                       
let join d1 d2 = if List.for_all2 equal_stack_frame d1 d2 then d1 else TOP

let meet d1 d2 = if List.for_all2 equal_stack_frame d1 d2 then d1 else TOP

let widen = join
