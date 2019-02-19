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


module L = Log.Make(struct let name = "abstractStack" end)

module I = Interval
         
type frame = I.t 

type t =
  | BOT
  | TOP
  | Frames of frame list (* stack of stack frames *)

let make_frame v =
  if !Config.stack = Config.Decreasing then
    I.upper_singleton v
  else I.lower_singleton v
  
let init () = TOP

let is_bot s = s = BOT

let is_subset d1 d2 =
  match d1, d2 with
  | _, TOP -> true
  | TOP, _ -> false
  | BOT, BOT  -> true
  | _, BOT | BOT, _ -> false
  | Frames f1, Frames f2 ->
     try
       List.for_all2 I.contains f1 f2
     with _ -> false

let add_stack_frame d (v: Z.t option): t =
  match d with
  | TOP | BOT -> Frames [make_frame v]
  | Frames d ->
     let stack_frame = make_frame v in
     Frames (stack_frame::d)

let remove_stack_frame d =
  match d with
  | BOT -> raise (Exceptions.Empty "remove_stack_frame on undefined stack")
  | TOP -> TOP
  | Frames d -> Frames (List.tl d)
    
let forget_stack_frame d =
   match d with
  | BOT -> raise (Exceptions.Empty "forget_stack_frame on undefined stack")
  | TOP -> TOP
  | Frames d -> Frames (I.inf::(List.tl d))


let to_string d =
  [
    match d with
    | TOP -> "?"
    | BOT -> "_"
    | Frames i ->
       let s =
         List.fold_left (fun s i -> (I.to_string i)^" :: "^s) " ]" (List.rev i)
       in
       "[ " ^ s
 ]
  

let check_frame w len f =
  L.debug2 (fun p -> p "check_frame with frame=%s" (I.to_string f));
  let w' = Data.Word.to_int w in
  let wi = I.of_bounds w' (Z.add w' (Z.of_int (len-1))) in
  if I.contains wi f then
    ()
  else
    L.abort (fun p -> p "stack overflow: trying to read/write %d byte(s) from %s (current stack frame is in %s)"
                             len  (Data.Word.to_string w) (I.to_string f))
             
let check_overflow (d: t) (a: Data.Address.t): unit =
  let len = !Config.address_sz / 8 in
  L.debug2 (fun p -> p "check_overflow at %s (len=%d)" (Data.Address.to_string a) len);
  match d with
  | TOP -> L.analysis (fun p -> p "possible stack overflow")
  | BOT -> L.abort (fun p -> p "tried to read/write into an undefined stack")
  | Frames d ->
     match a with
     | Data.Address.Global, w -> check_frame w len (List.hd d)
     | _ -> ()
         
let join d1 d2 =
  match d1, d2 with
  | TOP, _ | _, TOP -> TOP
  | BOT, d | d, BOT -> d
  | Frames d1, Frames d2 -> if List.for_all2 I.equal d1 d2 then Frames d1 else TOP (* TODO: could be more precise *)

let meet d1 d2 =
  match d1, d2 with
  | TOP, d | d, TOP -> d
  | BOT, _ | _, BOT -> BOT
  | Frames d1, Frames d2 -> if List.for_all2 I.equal d1 d2 then Frames d1 else BOT

let widen = join
