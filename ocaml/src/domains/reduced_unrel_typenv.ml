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

(** reduced product Unrel x TypEnv *)
(** signature is of type Domain.T *)

module L = Log.Make(struct let name = "reduced_unrel_typenv" end)

module Make(D: Unrel.T) =
(struct
  module U = Unrel.Make(D)
  module T = Typenv

  type t = U.t * T.t

  let init () = U.init (), T.init ()

  let bot = U.BOT, T.BOT

  let forget (uenv, tenv) = U.forget uenv, T.forget tenv

  let is_bot (uenv, _tenv) = U.is_bot uenv

  let is_subset (uenv1, tenv1) (uenv2, tenv2) =
    U.is_subset uenv1 uenv2 && T.is_subset tenv1 tenv2

  let remove_register r (uenv, tenv) = U.remove_register r uenv, T.remove_register r tenv

  let forget_lval lv (uenv, tenv) =
    let tenv' =
      match lv with
      | Asm.V (Asm.T r)  | Asm.V (Asm.P (r, _, _)) -> T.remove_register r tenv
      | _ -> let addrs, _ = U.mem_to_addresses uenv (Asm.Lval lv) in
         T.remove_addresses addrs tenv
    in
    U.forget_lval lv uenv, tenv'

  let add_register r (uenv, tenv) = U.add_register r uenv, T.add_register r tenv

  let to_string (uenv, tenv) id = (U.to_string uenv id) @ (T.to_string tenv)

  let value_of_register (uenv, _tenv) r = U.value_of_register uenv r

  let string_of_register (uenv, tenv) r = [U.string_of_register uenv r ; T.string_of_register tenv r]

  let value_of_exp (uenv, _tenv) e = U.value_of_exp uenv e

  let type_of_exp tenv uenv e =
    match e with
    | Asm.Lval (Asm.V (Asm.P (_r, _, _))) -> Types.UNKNOWN
    | Asm.Lval (Asm.V (Asm.T r)) -> T.of_key (Env.Key.Reg r) tenv
    | Asm.Lval (Asm.M (e, _sz)) ->
       begin
     try
       let addrs, _ = U.mem_to_addresses uenv e in
       match Data.Address.Set.elements addrs with
       | [a] -> T.of_key (Env.Key.Mem a) tenv
       | _ -> Types.UNKNOWN
     with Exceptions.Too_many_concrete_elements _ -> Types.UNKNOWN
       end
    | _ -> Types.UNKNOWN

  let set_type (lv: Asm.lval) (typ: Types.t) ((uenv, tenv): t): t =
    L.debug (fun p -> p "set_type %s %s" (Asm.string_of_lval lv true) (Types.to_string typ));
   let tenv' =
     match lv with
     | Asm.V (Asm.T r) -> if typ = Types.UNKNOWN then T.forget_register r tenv else T.set_register r typ tenv
     | Asm.V (Asm.P (r, _, _)) -> T.forget_register r tenv
     | Asm.M (e, _sz) ->
        try
      let addrs, _ = U.mem_to_addresses uenv e in
      match Data.Address.Set.elements addrs with
      | [a] -> L.debug (fun p -> p "at %s: inferred type is %s" (Data.Address.to_string a) (Types.to_string typ)); if typ = Types.UNKNOWN then T.forget_address a tenv else T.set_address a typ tenv
      | l -> List.fold_left (fun tenv' a -> T.forget_address a tenv') tenv l
    with Exceptions.Too_many_concrete_elements _ -> T.forget tenv
   in
   uenv, tenv'

  let set (lv: Asm.lval) (e: Asm.exp) ((uenv, tenv): t): t*Taint.t =
    let uenv', b = U.set lv e uenv in
    try
      let typ = type_of_exp tenv uenv e in
      let _, tenv' = set_type lv typ (uenv, tenv) in
      (uenv', tenv'), b
    with _ -> set_type lv Types.UNKNOWN (uenv', tenv), b

  let char_type uenv tenv dst =
     let typ = Types.T (TypedC.Int (Newspeak.Signed, 8)) in
     try
       let addrs, _ = U.mem_to_addresses uenv dst in
       match Data.Address.Set.elements addrs with
       | [a] -> if typ = Types.UNKNOWN then T.forget_address a tenv else T.set_address a typ tenv
       | l ->  List.fold_left (fun tenv' a -> T.forget_address a tenv') tenv l (* TODO: replace by a weak update *)
     with Exceptions.Too_many_concrete_elements _ -> T.top

  let copy (uenv, tenv) dst src sz: t =
    U.copy uenv dst src sz, char_type uenv tenv dst

  let join (uenv1, tenv1) (uenv2, tenv2) = U.join uenv1 uenv2, T.join tenv1 tenv2

  let meet (uenv1, tenv1) (uenv2, tenv2) = U.meet uenv1 uenv2, T.meet tenv1 tenv2

  let widen (uenv1, tenv1) (uenv2, tenv2) = U.widen uenv1 uenv2, T.widen tenv1 tenv2

  let set_memory_from_config a c n (uenv, tenv) =
    let uenv', taint = U.set_memory_from_config a c n uenv in
    (uenv', tenv), taint

  let set_register_from_config register (c: Config.cvalue option * Config.tvalue list) (uenv, tenv) =
    let uenv', taint = U.set_register_from_config register c uenv in
    (uenv', tenv), taint

  let taint_register_mask r c (uenv, tenv): t * Taint.t =
    let uenv', taint = U.taint_register_mask r c uenv in
    (uenv', tenv), taint

  let span_taint_to_register register taint (uenv, tenv) =
    let uenv', taint' = U.span_taint_to_register register taint uenv in
    (uenv', tenv), taint'

  let taint_address_mask a c (uenv, tenv) =
    let uenv', taint = U.taint_address_mask a c uenv in
    (uenv', tenv), taint

  let span_taint_to_addr a taint (uenv, tenv) =
    let uenv', taint' = U.span_taint_to_addr a taint uenv in
    (uenv', tenv), taint'

  let compare (uenv, tenv) e1 cmp e2 =
    let uenv', b = U.compare uenv e1 cmp e2 in
    (uenv', tenv), b

  let mem_to_addresses (uenv, _tenv) e = U.mem_to_addresses uenv e

  let taint_sources e (uenv, _tenv) = U.taint_sources e uenv


  let get_offset_from addr cmp terminator upper_bound sz (uenv, _tenv) =
    U.get_offset_from addr cmp terminator upper_bound sz uenv

  let get_bytes addr cmp terminator upper_bound term_sz (uenv, _tenv) =
    U.get_bytes addr cmp terminator upper_bound term_sz uenv


  let print (uenv, _tenv) src sz: t =
    U.print uenv src sz, T.top

  let copy_hex (uenv, _tenv) dst src sz capitalise pad_option word_sz: t * int =
    let uenv', len = U.copy_hex uenv dst src sz capitalise pad_option word_sz in
    (uenv', T.top), len

  let print_hex (uenv, tenv) src sz capitalise pad_option word_sz: t * int =
    let uenv', len = U.print_hex uenv src sz capitalise pad_option word_sz in
    (uenv', tenv), len

  let copy_chars (uenv, tenv) dst src sz pad_options =
    let tenv' = char_type uenv tenv dst in
    U.copy_chars uenv dst src sz pad_options, tenv'


  let print_chars (uenv, _tenv) src sz pad_options =
    U.print_chars uenv src sz pad_options, T.top

  let copy_until (uenv, tenv) dst arg terminator term_sz upper_bound with_exception pad_options =
    let len, uenv' = U.copy_until uenv dst arg terminator term_sz upper_bound with_exception pad_options in
    let tenv' = char_type uenv tenv dst in
    len, (uenv', tenv')

  let print_until (uenv, _tenv) arg terminator term_sz upper_bound with_exception pad_options =
    let len, uenv' = U.print_until uenv arg terminator term_sz upper_bound with_exception pad_options in
    len, (uenv', T.top)


  let copy_register r (uenv, tenv) (usrc, tsrc) =
    U.copy_register r uenv usrc, T.set_register r (type_of_exp tsrc usrc (Asm.Lval (Asm.V (Asm.T r)))) tenv
 end:
   Domain.T)
