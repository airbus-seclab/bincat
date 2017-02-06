(** reduced product Unrel x TypEnv *)
(** signature is of type Domain.T *)

module Make(D: Unrel.T) =
(struct
  module U = Unrel.Make(D)
  module T = Typenv

  type t = U.t * T.t

  let init () = U.init (), T.init ()

  let bot = U.BOT, T.BOT

  let forget (uenv, tenv) = U.forget uenv, T.forget tenv

  let is_bot (uenv, _tenv) = U.is_bot uenv

  let subset (uenv1, tenv1) (uenv2, tenv2) =
    U.subset uenv1 uenv2 && T.subset tenv1 tenv2

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

  let to_string (uenv, tenv) = (U.to_string uenv) @ (T.to_string tenv)
    
  let value_of_register (uenv, _tenv) r = U.value_of_register uenv r

  let string_of_register (uenv, tenv) r = [U.string_of_register uenv r ; T.string_of_register tenv r]
    
  let value_of_exp (uenv, _tenv) e = U.value_of_exp uenv e
    
  let set_type (lv: Asm.lval) (typ: Types.t) ((uenv, tenv): t): t =
   let tenv' =
     match lv with
     | Asm.V (Asm.T r) -> if typ = Types.TUNKNOWN then T.forget_register r tenv else T.set_register r typ tenv
     | Asm.V (Asm.P (r, _, _)) -> T.forget_register r tenv
     | Asm.M (e, _sz) ->
	try
	  let addrs, _ = U.mem_to_addresses uenv e in
	  match Data.Address.Set.elements addrs with
	  | [a] -> if typ = Types.TUNKNOWN then T.forget_address a tenv else T.set_address a typ tenv
	  | l -> List.fold_left (fun tenv' a -> T.forget_address a tenv') tenv l
	with Exceptions.Enum_failure -> T.forget tenv
   in
   uenv, tenv'
     
  let set (lv: Asm.lval) (e: Asm.exp) ((uenv, tenv): t): t*bool =
    let uenv', b = U.set lv e uenv in
    try
      let typ = T.of_exp e tenv in
      let _, tenv' = set_type lv typ (uenv, tenv) in
      (uenv', tenv'), b
    with _ -> set_type lv Types.TUNKNOWN (uenv', tenv), b
       
  let join (uenv1, tenv1) (uenv2, tenv2) = U.join uenv1 uenv2, T.join tenv1 tenv2

  let meet (uenv1, tenv1) (uenv2, tenv2) = U.meet uenv1 uenv2, T.meet tenv1 tenv2

  let widen (uenv1, tenv1) (uenv2, tenv2) = U.widen uenv1 uenv2, T.widen tenv1 tenv2

  let set_memory_from_config a r c n (uenv, tenv) =
    U.set_memory_from_config a r c n uenv, tenv

  let set_register_from_config register region c  (uenv, tenv) =
    U.set_register_from_config register region c uenv, tenv

  let taint_register_mask r c (uenv, tenv) = U.taint_register_mask r c uenv, tenv

  let taint_address_mask a c (uenv, tenv) = U.taint_address_mask a c uenv, tenv
    
  let compare (uenv, tenv) e1 cmp e2 =
    let uenv', b = U.compare uenv e1 cmp e2 in
    (uenv', tenv), b

  let mem_to_addresses (uenv, _tenv) e = U.mem_to_addresses uenv e

  let is_tainted e (uenv, _tenv) = U.is_tainted e uenv
       

  let get_offset_from addr cmp terminator upper_bound sz (uenv, _tenv) =
    U.get_offset_from addr cmp terminator upper_bound sz uenv

  let get_bytes addr cmp terminator upper_bound term_sz (uenv, _tenv) =
    U.get_bytes addr cmp terminator upper_bound term_sz uenv

  let copy (uenv, _tenv) dst src sz: t =
    U.copy uenv dst src sz, T.top

  let print (uenv, _tenv) src sz: t =
    U.print uenv src sz, T.top

  let copy_hex (uenv, _tenv) dst src sz capitalise pad_char pad_left word_sz: t =
    U.copy_hex uenv dst src sz capitalise pad_char pad_left word_sz, T.top

  let print_hex (uenv, tenv) src sz capitalise pad_char pad_left word_sz: t =
    U.print_hex uenv src sz capitalise pad_char pad_left word_sz, tenv
   
  let copy_chars (uenv, _tenv) dst src sz pad_options =
    U.copy_chars uenv dst src sz pad_options, T.top

  let print_chars (uenv, _tenv) src sz pad_options =
    U.print_chars uenv src sz pad_options, T.top
      
  let copy_until (uenv, _tenv) dst arg terminator term_sz upper_bound with_exception pad_options =
    let len, uenv' = U.copy_until uenv dst arg terminator term_sz upper_bound with_exception pad_options in
    len, (uenv', T.top)

  let print_until (uenv, _tenv) arg terminator term_sz upper_bound with_exception pad_options =
    let len, uenv' = U.print_until uenv arg terminator term_sz upper_bound with_exception pad_options in
    len, (uenv', T.top)

  let copy_register r (uenv, _tenv) (usrc, _tsrc) =
    U.copy_register r uenv usrc, T.top
 end:
   Domain.T)
