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

module I = Interval
         
type frame = I.t option (* None is TOP *)

type t =
  | BOT
  | TOP
  | Frames of frame list (* stack of stack frames *)

let init () = Frames []

let is_bot s = s = BOT

let is_subset d1 d2 =
  match d1, d2 with
  | _, TOP -> true
  | TOP, _ -> false
  | BOT, BOT  -> true
  | _, BOT | BOT, _ -> false
  | Frames f1, Frames f2 ->
     try
       List.for_all2 (fun f1 f2 ->
           match f1, f2 with
           | _, None -> true
           | None, _ -> false
           | Some i1, Some i2 -> I.is_included i1 i2) f1 f2
     with _ -> false
             
let add_stack_frame d (v: Z.t option) =
  let stack_frame =
    match v with
    | Some v -> Some (I.singleton v)
    | None -> None
  in
  stack_frame::d

let remove_stack_frame d =
  match d with
  | BOT -> raise (Exceptions.Empty "remove_stack_frame on undefined stack")
  | TOP -> TOP
  | Frames d -> Frames (List.tl d)
    
let forget_stack_frame d =
   match d with
  | BOT -> raise (Exceptions.Empty "forget_stack_frame on undefined stack")
  | TOP -> TOP
  | Frames d -> Frames (None::(List.tl d))

let string_of_stack_frame s =
  match s with
  | Some i -> I.to_string i
  | None -> "[ -oo ; +oo "

let equal_stack_frame s1 s2 =
  match s1, s2 with
  | Some i1, Some i2 -> I.equal i1 i2
  | _, _ -> false
                      
let to_string d =
  [
    match d with
    | TOP -> "?"
    | BOT -> "_"
    | Frames i ->
       let s =
         List.fold_left (fun s i -> (string_of_stack_frame i)^" | "^s) " ]" (List.rev i)
       in
       "[ " ^ s
 ]
  
let normalize l u =
  if Z.compare l u < 0 then Some (l, u)
  else None
  
let update_stack_frame (d: t) (bound: Z.t): t =
  match d with
  | BOT -> raise (Exceptions.Empty "update_stack_frame on undefined stack")
  | TOP -> TOP
  | Frames d ->
     let stack_frame' =
       match List.hd d with
       | None -> None
       | Some (l, u) ->
          if !Config.stack = Config.Decreasing then normalize bound u
          else normalize l bound
     in
     Frames (stack_frame'::(List.tl d))

let check_overflow (d: t) (a: Data.Address.t) (len: int): unit =
  match d with
  | TOP -> L.analysis (fun p -> p "possible stack overflow")
  | BOT -> L.abort (fun p -> p "tried to write into an undefined stack")
  | Frames d ->
     match a with
     | Data.Address.Global, w ->
        begin
          let stack_frame = List.hd d in
          match stack_frame with
          | None -> L.analysis (fun p -> p "possible stack overflow")
          | Some (l, u) ->
             let w' = Data.Word.to_int w in
             if Z.compare l w' <= 0 && Z.compare w' u <= 0 then
               let legal_len = (Z.to_int (Z.sub u l)) + 1 in
               if legal_len >= len then
                 ()
               else
                 L.abort (fun p -> p "stack overflow: trying to write %d bytes from %s (current stack frame is only %d byte width)"
                                     len  (Data.Word.to_string w) legal_len)
             else ()
        end
     | _ -> ()
                                       
let join d1 d2 =
  match d1, d2 with
  | TOP, _ | _, TOP -> TOP
  | BOT, d | d, BOT -> d
  | Frames d1, Frames d2 -> if List.for_all2 equal_stack_frame d1 d2 then Frames d1 else TOP (* TODO: could be more precise *)

let meet d1 d2 =
  match d1, d2 with
  | TOP, d | d, TOP -> d
  | BOT, _ | _, BOT -> BOT
  | Frames d1, Frames d2 -> if List.for_all2 equal_stack_frame d1 d2 then Frames d1 else BOT

let widen = join
