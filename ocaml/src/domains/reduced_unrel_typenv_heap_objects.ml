(*
    This file is part of BinCAT.
    Copyright 2014-2022 - Airbus

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

(** reduced product Unrel x TypEnv x Heap *)
(** signature is of type Domain.T *)

module L = Log.Make(struct let name = "reduced_unrel_typenv_heap" end)

module Make(D: Unrel.T) =
(struct
  module U = Unrels.Make(D)
  module T = Typenv
  module H = Abstract_heap
  module O = Abstract_objects
           
  type t = U.t * T.t * H.t * O.t

  let init () = U.init (), T.init (), H.init (), O.init()

  let bot = U.BOT, T.BOT, H.BOT, O.BOT

  let forget (uenv, tenv, henv, oenv) = U.forget uenv, T.forget tenv, H.forget henv, O.forget oenv

  let is_bot (uenv, tenv, henv, oenv) = U.is_bot uenv || T.is_bot tenv || H.is_bot henv || O.is_bot oenv

  let is_subset (uenv1, tenv1, henv1, oenv1) (uenv2, tenv2, henv2, oenv2) =
    U.is_subset uenv1 uenv2 && T.is_subset tenv1 tenv2 && H.is_subset henv1 henv2 && O.is_subset oenv1 oenv2

  let remove_register r (uenv, tenv, henv, oenv) = U.remove_register r uenv, T.remove_register r tenv, henv, oenv

  let forget_lval lv (uenv, tenv, henv, oenv) =
    let tenv' =
      match lv with
      | Asm.V (Asm.T r)
      | Asm.V (Asm.P (r, _, _)) -> T.remove_register r tenv
      | _ ->
         let addrs, _ = U.mem_to_addresses uenv (Asm.Lval lv) (H.check_status henv) in
         T.remove_addresses addrs tenv
    in
    U.forget_lval lv uenv (H.check_status henv), tenv', henv, oenv

  let add_register r (uenv, tenv, henv, oenv) w = U.add_register r uenv w, T.add_register r tenv, henv, oenv

  let to_string (uenv, tenv, henv, oenv) id = (U.to_string uenv id) @ (T.to_string tenv) @ (H.to_string henv) @(O.to_string oenv)

  let value_of_register (uenv, _tenv, _henv, _oenv) r = U.value_of_register uenv r

  let string_of_register (uenv, tenv, _henv, _oenv) r = [U.string_of_register uenv r ; T.string_of_register tenv r]

  let value_of_exp (uenv, _tenv, henv, _oenv) e = U.value_of_exp uenv e (H.check_status henv)

  let type_of_exp tenv uenv henv e =
    match e with
    | Asm.Lval (Asm.V (Asm.P (_r, _, _))) -> Types.UNKNOWN
    | Asm.Lval (Asm.V (Asm.T r)) -> T.of_key (Env.Key.Reg r) tenv
    | Asm.Lval (Asm.M (e, _sz)) ->
       begin
         try
         let addrs, _ = U.mem_to_addresses uenv e (H.check_status henv) in
         match Data.Address.Set.elements addrs with
         | [a] -> T.of_key (Env.Key.Mem a) tenv
         | _ -> Types.UNKNOWN
       with Exceptions.Too_many_concrete_elements _ -> Types.UNKNOWN
       end
    | _ -> Types.UNKNOWN


  let set_type (lv: Asm.lval) (typ: Types.t) ((uenv, tenv, henv, oenv): t): t =
    L.debug (fun p -> p "set_type %s %s" (Asm.string_of_lval lv true) (Types.to_string typ));
   let tenv' =
     match lv with
     | Asm.V (Asm.T r) -> if typ = Types.UNKNOWN then T.forget_register r tenv else T.set_register r typ tenv
     | Asm.V (Asm.P (r, _, _)) -> T.forget_register r tenv
     | Asm.M (e, _sz) ->
        try
      let addrs, _ = U.mem_to_addresses uenv e (H.check_status henv) in
      match Data.Address.Set.elements addrs with
      | [a] -> L.debug (fun p -> p "at %s: inferred type is %s" (Data.Address.to_string a) (Types.to_string typ));
               if typ = Types.UNKNOWN then T.forget_address a tenv else T.set_address a typ tenv
               
      | l -> List.fold_left (fun tenv' a -> T.forget_address a tenv') tenv l
        with Exceptions.Too_many_concrete_elements _ -> T.forget tenv
   in
   uenv, tenv', henv, oenv

  let set (lv: Asm.lval) (e: Asm.exp) ((uenv, tenv, henv, oenv): t): t*Taint.Set.t =
    let uenv', b = U.set lv e uenv (H.check_status henv) in
    let typ = type_of_exp tenv uenv henv e in
    let _, tenv', _, oenv' = set_type lv typ (uenv', tenv, henv, oenv) in
    (uenv', tenv', henv, oenv'), b


  let set_lval_to_addr (lv: Asm.lval) (addrs: (Data.Address.t * string) list) ((uenv, tenv, henv, oenv): t): t*Taint.Set.t =
    let uenv', b = U.set_lval_to_addr lv addrs uenv (H.check_status henv) in
    try
      let buf_typ =
        match addrs with
        | [] -> raise Exit
        | (addr, _)::tl ->
           let t = T.of_key (Env.Key.Mem addr) tenv in
           if List.for_all (fun (a, _) ->
                  let t' = T.of_key (Env.Key.Mem a) tenv in
                  Types.equal t t') tl then
             t
           else raise Exit
      in
      let ptr_typ =
        match buf_typ with
        | Types.T t -> Types.T (TypedC.Ptr t)
        | t ->  t (* TODO: could be more precise: we know it is a pointer *)
      in    
      let _, tenv', _, oenv' = set_type lv ptr_typ (uenv', tenv, henv, oenv) in
      (uenv', tenv', henv, oenv'), b
    with _ -> set_type lv Types.UNKNOWN (uenv', tenv, henv, oenv), b
      
  let char_type uenv tenv henv _oenv dst =
     let typ = Types.T (TypedC.Int (Newspeak.Signed, 8)) in
     try
       let addrs, _ = U.mem_to_addresses uenv dst (H.check_status henv) in
       match Data.Address.Set.elements addrs with
       | [a] -> if typ = Types.UNKNOWN then T.forget_address a tenv else T.set_address a typ tenv
       | l ->  List.fold_left (fun tenv' a -> T.forget_address a tenv') tenv l (* TODO: replace by a weak update *)
     with Exceptions.Too_many_concrete_elements _ -> T.top

  let copy (uenv, tenv, henv, oenv) dst src sz: t =
    U.copy uenv dst src sz (H.check_status henv), char_type uenv tenv henv oenv dst, henv, oenv

  let join (uenv1, tenv1, henv1, oenv1) (uenv2, tenv2, henv2, oenv2) = U.join uenv1 uenv2, T.join tenv1 tenv2, H.join henv1 henv2, O.join oenv1 oenv2

  let meet (uenv1, tenv1, henv1, oenv1) (uenv2, tenv2, henv2, oenv2) = U.meet uenv1 uenv2, T.meet tenv1 tenv2, H.meet henv1 henv2, O.meet oenv1 oenv2

  let widen (uenv1, tenv1, henv1, oenv1) (uenv2, tenv2, henv2, oenv2) = U.widen uenv1 uenv2, T.widen tenv1 tenv2, H.widen henv1 henv2, O.widen oenv1 oenv2

  let set_memory_from_config a c n (uenv, tenv, henv, oenv) =
    let uenv', taint = U.set_memory_from_config a c n uenv (H.check_status henv) in
    (uenv', tenv, henv, oenv), taint

  let set_register_from_config register (c: Config.cvalue option * Config.tvalue list) (uenv, tenv, henv, oenv) =
    let uenv', taint = U.set_register_from_config register c uenv in
    (uenv', tenv, henv, oenv), taint

  let taint_register_mask r c (uenv, tenv, henv, oenv): t * Taint.Set.t =
    let uenv', taint = U.taint_register_mask r c uenv in
    (uenv', tenv, henv, oenv), taint

  let span_taint_to_register register taint (uenv, tenv, henv, oenv) =
    let uenv', taint' = U.span_taint_to_register register taint uenv in
    (uenv', tenv, henv, oenv), taint'

  let taint_address_mask a c (uenv, tenv, henv, oenv) =
    let uenv', taint = U.taint_address_mask a c uenv in
    (uenv', tenv, henv, oenv), taint

  let taint_lval lv taint (uenv, tenv, henv, oenv) =
    let uenv', taint' = U.taint_lval lv taint uenv (H.check_status henv) in
    (uenv', tenv, henv, oenv), taint'
    
  let span_taint_to_addr a taint (uenv, tenv, henv, oenv) =
    let uenv', taint' = U.span_taint_to_addr a taint uenv in
    (uenv', tenv, henv, oenv), taint'

  let compare (uenv, tenv, henv, oenv) e1 cmp e2 =
    let uenv', b = U.compare uenv (H.check_status henv) e1 cmp e2 in
    (uenv', tenv, henv, oenv), b

  let mem_to_addresses (uenv, _tenv, henv, _oenv) e = U.mem_to_addresses uenv e (H.check_status henv)

  let taint_sources e (uenv, _tenv, henv, _oenv) = U.taint_sources e uenv (H.check_status henv)


  let get_offset_from addr cmp terminator upper_bound sz (uenv, _tenv, henv, _oenv) =
    U.get_offset_from addr cmp terminator upper_bound sz uenv (H.check_status henv)

  let get_bytes addr cmp terminator upper_bound term_sz (uenv, _tenv, henv, _oenv) =
    U.get_bytes addr cmp terminator upper_bound term_sz uenv (H.check_status henv)


  let print (uenv, _tenv, henv, oenv) src sz: t = U.print uenv src sz (H.check_status henv), T.top, henv, oenv

  let copy_hex (uenv, _tenv, henv, oenv) dst src sz capitalise pad_option word_sz: t * int =
    let uenv', len = U.copy_hex uenv dst src sz capitalise pad_option word_sz (H.check_status henv) in
    (uenv', T.top, henv, oenv), len

  let print_hex (uenv, tenv, henv, oenv) src sz capitalise pad_option word_sz: t * int =
    let uenv', len = U.print_hex uenv src sz capitalise pad_option word_sz (H.check_status henv) in
    (uenv', tenv, henv, oenv), len

    let copy_int (uenv, _tenv, henv, oenv) dst src sz capitalise pad_option word_sz: t * int =
    let uenv', len = U.copy_int uenv dst src sz capitalise pad_option word_sz (H.check_status henv) in
    (uenv', T.top, henv, oenv), len

  let print_int (uenv, tenv, henv, oenv) src sz capitalise pad_option word_sz: t * int =
    let uenv', len = U.print_int uenv src sz capitalise pad_option word_sz (H.check_status henv) in
    (uenv', tenv, henv, oenv), len

  let copy_chars (uenv, tenv, henv, oenv) dst src sz pad_options =
    let tenv' = char_type uenv tenv henv oenv dst in
    U.copy_chars uenv dst src sz pad_options (H.check_status henv), tenv', henv, oenv


  let print_chars (uenv, _tenv, henv, oenv) src sz pad_options =
    let uenv', len = U.print_chars uenv src sz pad_options (H.check_status henv) in
    (uenv', T.top, henv, oenv), len

  let copy_until (uenv, tenv, henv, oenv) dst arg terminator term_sz upper_bound with_exception pad_options =
    let len, uenv' = U.copy_until uenv dst arg terminator term_sz upper_bound with_exception pad_options (H.check_status henv) in
    let tenv' = char_type uenv tenv henv oenv dst in
    len, (uenv', tenv', henv, oenv)

  let print_until (uenv, _tenv, henv, oenv) arg terminator term_sz upper_bound with_exception pad_options =
    let len, uenv' = U.print_until uenv arg terminator term_sz upper_bound with_exception pad_options (H.check_status henv) in
    len, (uenv', T.top, henv, oenv)


  let copy_register r (uenv, tenv, henv, oenv) (usrc, tsrc, hsrc, _osrc) =
    U.copy_register r uenv usrc, T.set_register r (type_of_exp tsrc usrc hsrc (Asm.Lval (Asm.V (Asm.T r)))) tenv, henv, oenv

  let allocate_on_heap (uenv, tenv, henv, oenv) id = uenv, tenv, H.alloc henv id, oenv

  let allocate_object (uenv, tenv, henv, oenv) id = uenv, tenv, henv, O.alloc oenv id
                                                  
  let deallocate (uenv, tenv, henv, oenv) addr = uenv, tenv, H.dealloc henv addr, oenv

                                              
  let weak_deallocate (uenv, tenv, henv, oenv) addrs = uenv, tenv, H.weak_dealloc henv addrs, oenv

  let get_taint lv (uenv, _tenv, henv, _oenv) = U.get_taint lv uenv (H.check_status henv)
end: Domain.T)
