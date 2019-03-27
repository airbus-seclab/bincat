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

(** reduced product Unrel x TypEnv x Heap x AbstractStack *)
(** signature is of type Domain.T *)

module L = Log.Make(struct let name = "reduced_unrel_typenv_heap" end)

module Make(D: Unrel.T) =
(struct
  module U = Unrels.Make(D)
  module T = Typenv
  module H = Heap
  module S = AbstractStack
           
  type t = U.t * T.t * H.t * S.t

  let init v = U.init (), T.init (), H.init (), S.init v

  let bot = U.BOT, T.BOT, H.BOT, S.BOT

  let forget (uenv, tenv, henv, senv) = U.forget uenv, T.forget tenv, H.forget henv, senv

  let is_bot (uenv, tenv, henv, senv) = U.is_bot uenv || T.is_bot tenv || H.is_bot henv || S.is_bot senv

  let is_subset (uenv1, tenv1, henv1, senv1) (uenv2, tenv2, henv2, senv2) =
    U.is_subset uenv1 uenv2 && T.is_subset tenv1 tenv2 && H.is_subset henv1 henv2 && S.is_subset senv1 senv2

  let remove_register r (uenv, tenv, henv, senv) = U.remove_register r uenv, T.remove_register r tenv, henv, senv

  let imake_stack_frame (uenv, tenv, henv, senv) =
    let v =
      try
        let v = U.value_of_register uenv (Register.stack_pointer()) in
        if !Config.stack = Config.Decreasing then
          Some (Z.sub v Z.one)
        else
          Some (Z.add v Z.one) 
      with _ -> None
    in
    (uenv, tenv, henv, S.add_stack_frame senv v)
    
  let make_first_stack_frame d = imake_stack_frame d
    
    
  let call d = imake_stack_frame d

  let ret (uenv, tenv, henv, senv) = uenv, tenv, henv, S.remove_stack_frame senv

  let check_address henv senv a =
    H.check_status henv a;
    S.check_overflow senv a

  let forget_lval lv (uenv, tenv, henv, senv): t =
    let tenv', is_stack_register =
      match lv with
      | Asm.V (Asm.T r)
      | Asm.V (Asm.P (r, _, _)) -> T.remove_register r tenv, true
      | _ ->
         let addrs, _ = U.mem_to_addresses uenv (Asm.Lval lv) (check_address henv senv) in
         T.remove_addresses addrs tenv, false
    in
    let senv' =
      if is_stack_register then S.forget_stack_frame senv else senv
    in
    U.forget_lval lv uenv (check_address henv senv), tenv', henv, senv'

  let add_register r (uenv, tenv, henv, senv) = U.add_register r uenv, T.add_register r tenv, henv, senv

  let to_string (uenv, tenv, henv, senv) id = (U.to_string uenv id) @ (T.to_string tenv) @ (H.to_string henv) @ (S.to_string senv)

  let value_of_register (uenv, _tenv, _henv, _senv) r = U.value_of_register uenv r

  let string_of_register (uenv, tenv, _henv, _senv) r = [U.string_of_register uenv r ; T.string_of_register tenv r]

  let value_of_exp (uenv, _tenv, henv, senv) e = U.value_of_exp uenv e (check_address henv senv)

  let type_of_exp tenv uenv henv senv e =
    match e with
    | Asm.Lval (Asm.V (Asm.P (_r, _, _))) -> Types.UNKNOWN
    | Asm.Lval (Asm.V (Asm.T r)) -> T.of_key (Env.Key.Reg r) tenv
    | Asm.Lval (Asm.M (e, _sz)) ->
       begin
         try
         let addrs, _ = U.mem_to_addresses uenv e (check_address henv senv) in
         match Data.Address.Set.elements addrs with
         | [a] -> T.of_key (Env.Key.Mem a) tenv
         | _ -> Types.UNKNOWN
       with Exceptions.Analysis (Exceptions.Too_many_concrete_elements _) -> Types.UNKNOWN
       end
    | _ -> Types.UNKNOWN


  let set_type (lv: Asm.lval) (typ: Types.t) ((uenv, tenv, henv, senv): t): t =
    L.debug (fun p -> p "set_type %s %s" (Asm.string_of_lval lv true) (Types.to_string typ));
   let tenv' =
     match lv with
     | Asm.V (Asm.T r) -> if typ = Types.UNKNOWN then T.forget_register r tenv else T.set_register r typ tenv
     | Asm.V (Asm.P (r, _, _)) -> T.forget_register r tenv
     | Asm.M (e, _sz) ->
        try
      let addrs, _ = U.mem_to_addresses uenv e (check_address henv senv) in
      match Data.Address.Set.elements addrs with
      | [a] -> L.debug (fun p -> p "at %s: inferred type is %s" (Data.Address.to_string a) (Types.to_string typ));
               if typ = Types.UNKNOWN then T.forget_address a tenv else T.set_address a typ tenv
               
      | l -> List.fold_left (fun tenv' a -> T.forget_address a tenv') tenv l
        with Exceptions.Analysis (Exceptions.Too_many_concrete_elements _) -> T.forget tenv
   in
   uenv, tenv', henv, senv

  let set (lv: Asm.lval) (e: Asm.exp) ((uenv, tenv, henv, senv): t): t*Taint.Set.t =
    let uenv', b = U.set lv e uenv (check_address henv senv) in
    let typ = type_of_exp tenv uenv henv senv e in
    let _, tenv', _, _ = set_type lv typ (uenv', tenv, henv, senv) in
    (uenv', tenv', henv, senv), b


  let set_lval_to_addr (lv: Asm.lval) (addrs: (Data.Address.t * Log.msg_id_t) list) ((uenv, tenv, henv, senv): t): t*Taint.Set.t =
    let uenv', b = U.set_lval_to_addr lv addrs uenv (check_address henv senv) in
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
      let _, tenv', _, _ = set_type lv ptr_typ (uenv', tenv, henv, senv) in
      (uenv', tenv', henv, senv), b
    with _ -> set_type lv Types.UNKNOWN (uenv', tenv, henv, senv), b
      
  let char_type uenv tenv henv senv dst =
     let typ = Types.T (TypedC.Int (Newspeak.Signed, 8)) in
     try
       let addrs, _ = U.mem_to_addresses uenv dst (check_address henv senv) in
       match Data.Address.Set.elements addrs with
       | [a] -> if typ = Types.UNKNOWN then T.forget_address a tenv else T.set_address a typ tenv
       | l ->  List.fold_left (fun tenv' a -> T.forget_address a tenv') tenv l (* TODO: replace by a weak update *)
     with (Exceptions.Analysis (Exceptions.Too_many_concrete_elements _)) -> T.top

  let copy (uenv, tenv, henv, senv) dst src sz: t =
    U.copy uenv dst src sz (check_address henv senv), char_type uenv tenv henv senv dst, henv, senv

  let join (uenv1, tenv1, henv1, senv1) (uenv2, tenv2, henv2, senv2) = U.join uenv1 uenv2, T.join tenv1 tenv2, H.join henv1 henv2, S.join senv1 senv2

  let meet (uenv1, tenv1, henv1, senv1) (uenv2, tenv2, henv2, senv2) = U.meet uenv1 uenv2, T.meet tenv1 tenv2, H.meet henv1 henv2, S.meet senv1 senv2

  let widen (uenv1, tenv1, henv1, senv1) (uenv2, tenv2, henv2, senv2) = U.widen uenv1 uenv2, T.widen tenv1 tenv2, H.widen henv1 henv2, S.widen senv1 senv2

  let set_memory_from_config a c n (uenv, tenv, henv, senv) =
    let uenv', taint = U.set_memory_from_config a c n uenv (check_address henv senv) in
    (uenv', tenv, henv, senv), taint

  let set_register_from_config r (c: Config.cvalue option * Config.tvalue list) (uenv, tenv, henv, senv): t* Taint.Set.t =
    let uenv', taint = U.set_register_from_config r c uenv in
    (uenv', tenv, henv, senv), taint

  let taint_register_mask r c (uenv, tenv, henv, senv): t * Taint.Set.t =
    let uenv', taint = U.taint_register_mask r c uenv in
    (uenv', tenv, henv, senv), taint

  let span_taint_to_register register taint (uenv, tenv, henv, senv) =
    let uenv', taint' = U.span_taint_to_register register taint uenv in
    (uenv', tenv, henv, senv), taint'

  let taint_address_mask a c (uenv, tenv, henv, senv) =
    let uenv', taint = U.taint_address_mask a c uenv in
    (uenv', tenv, henv, senv), taint

  let span_taint_to_addr a taint (uenv, tenv, henv, senv) =
    let uenv', taint' = U.span_taint_to_addr a taint uenv in
    (uenv', tenv, henv, senv), taint'

  let compare (uenv, tenv, henv, senv) e1 cmp e2 =
    let uenv', b = U.compare uenv (H.check_status henv) e1 cmp e2 in
    (uenv', tenv, henv, senv), b

  let mem_to_addresses (uenv, _tenv, henv, senv) e = U.mem_to_addresses uenv e (check_address henv senv)

  let taint_sources e (uenv, _tenv, henv, senv) = U.taint_sources e uenv (check_address henv senv)


  let get_offset_from addr cmp terminator upper_bound sz (uenv, _tenv, henv, senv) =
    U.get_offset_from addr cmp terminator upper_bound sz uenv (check_address henv senv)

  let get_bytes addr cmp terminator upper_bound term_sz (uenv, _tenv, henv, senv) =
    U.get_bytes addr cmp terminator upper_bound term_sz uenv (check_address henv senv)


  let print (uenv, _tenv, henv, senv) src sz: t = U.print uenv src sz (check_address henv senv), T.top, henv, senv

  let copy_hex (uenv, _tenv, henv, senv) dst src sz capitalise pad_option word_sz: t * int =
    let uenv', len = U.copy_hex uenv dst src sz capitalise pad_option word_sz (check_address henv senv) in
    (uenv', T.top, henv, senv), len

  let print_hex (uenv, tenv, henv, senv) src sz capitalise pad_option word_sz: t * int =
    let uenv', len = U.print_hex uenv src sz capitalise pad_option word_sz (check_address henv senv) in
    (uenv', tenv, henv, senv), len

  let copy_chars (uenv, tenv, henv, senv) dst src sz pad_options =
    let tenv' = char_type uenv tenv henv senv dst in
    U.copy_chars uenv dst src sz pad_options (check_address henv senv), tenv', henv, senv


  let print_chars (uenv, _tenv, henv, senv) src sz pad_options =
    let uenv', len = U.print_chars uenv src sz pad_options (check_address henv senv) in
    (uenv', T.top, henv, senv), len

  let copy_until (uenv, tenv, henv, senv) dst arg terminator term_sz upper_bound with_exception pad_options =
    let len, uenv' = U.copy_until uenv dst arg terminator term_sz upper_bound with_exception pad_options (check_address henv senv) in
    let tenv' = char_type uenv tenv henv senv dst in
    len, (uenv', tenv', henv, senv)

  let print_until (uenv, _tenv, henv, senv) arg terminator term_sz upper_bound with_exception pad_options =
    let len, uenv' = U.print_until uenv arg terminator term_sz upper_bound with_exception pad_options (check_address henv senv) in
    len, (uenv', T.top, henv, senv)


  let copy_register r (uenv, tenv, henv, senv) (usrc, tsrc, hsrc, ssrc) =
    U.copy_register r uenv usrc, T.set_register r (type_of_exp tsrc usrc hsrc ssrc (Asm.Lval (Asm.V (Asm.T r)))) tenv, henv, senv

  let allocate_on_heap (uenv, tenv, henv, senv) id = uenv, tenv, H.alloc henv id, senv

  let deallocate (uenv, tenv, henv, senv) addr = uenv, tenv, H.dealloc henv addr, senv

  let weak_deallocate (uenv, tenv, henv, senv) addrs = uenv, tenv, H.weak_dealloc henv addrs, senv
 end: Domain.T)
