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

(* Log module for init_check *)

module L = Log.Make(struct let name = "init_check" end)

open Config

(* checkers for both init state creation and further overrides *)

let check_content content_sz taint_sz msg =
  let msg' = if String.compare msg "" = 0 then msg else "for register "^msg in
  if content_sz > taint_sz then
    L.abort (fun p -> p "Illegal initialisation/override %s" msg')

let check_mask content_sz mask taint_sz msg =
  let msg' = if String.compare msg "" = 0 then msg else "for register "^msg in
  if content_sz > taint_sz || (Z.numbits mask) > taint_sz then
        L.abort (fun p -> p "Illegal initialization/override %s" msg')

(* checks whether the provided value is compatible with the capacity of the parameter of type Register *)
let check_register_init r (c, t) =
  let sz   = Register.size r in
  let name = Register.name r in
  begin
    match c with
    | Some Content c    -> check_content (Z.numbits c) sz name
    | Some CMask (b, m) -> check_mask (Z.numbits b) m sz name
    | Some _ -> L.abort (fun p -> p "Illegal memory init \"|xx|\" spec used for register")
    | None -> ()
  end;
  List.iter (fun t -> 
    match t with
    | Taint (c, _taint_src)    -> check_content (Z.numbits c) sz name
    | TMask (b, m, _taint_src) -> check_mask (Z.numbits b) m sz name
    | _ -> ()) t


let check_mem (c, taints): unit =
  let taint_sz = ref 0 in
  let compute_sz () =
    let compute t =
      match t with
      | Taint_all _ | Taint_none  -> ()
      | Taint (t', _) | TMask (t', _, _) ->
         let n = Z.numbits t' in
         if !taint_sz = 0 then
           taint_sz := n
         else if !taint_sz <> n then L.abort (fun p -> p "Illegal taint source list (different sizes)") 
      | TBytes (s, _) | TBytes_Mask (s, _, _) ->
         let n = (String.length s)*4 in
         if !taint_sz = 0 then
           taint_sz := n
         else if !taint_sz <> n then L.abort (fun p -> p "Illegal taint source list (different sizes)")
    in
    List.iter compute taints
  in
  compute_sz();
  match c with
  | None -> if !taint_sz > 8 then L.abort (fun p -> p "Illegal taint override, byte only without value override") ;
  | Some (Content ct) -> check_content (Z.numbits ct) !taint_sz ""
  | Some (CMask (ct, m)) -> check_mask (Z.numbits ct) m !taint_sz ""
  | Some (Bytes s) -> check_content ((String.length s)*4) !taint_sz ""
  | Some (Bytes_Mask (s, n)) ->  check_mask ((String.length s)*4) n !taint_sz ""
