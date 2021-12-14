(*
    This file is part of BinCAT.
    Copyright 2014-2021 - Airbus

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

(** vector lifting of a value_domain.
Binary operations are supposed to apply on operands of the same length *)


module L = Log.Make(struct let name = "vector" end)


(** signature of value domain *)
module type Val =
sig
    (** abstract data type *)
    type t

    (** top *)
    val top: t

    (** comparison to top *)
    val is_top: t -> bool

    (** forget the content while preserving the taint *)
    val forget: t -> t

    (** conversion to value of type Z.t. May raise an exception *)
    val to_z: t -> Z.t

    (** int conversion. May raise an exception *)
    val to_int: t -> int

    (** conversion of the taint value of the parameter into a Z value. May raise an exception *)
    val taint_to_z: t -> Z.t

    (** conversion from Z.t value *)
    val of_z: Z.t -> t

    (** taint the given value from Z.t value *)
    val taint_of_z: Z.t -> t -> Taint.Src.id_t -> t

    (** abstract join *)
    val join: t -> t -> t

    (** logical or on taint component only 
        this function should only be called when the value of the 
        two parameters are the same. No check done *)
    val taint_logor: t -> t -> t
      
    (** abstract meet *)
    val meet: t -> t -> t

    (** widening *)
    val widen: t -> t -> t

    (** char conversion *)
    val to_char: t -> char

    (** string conversion *)
    val to_string: t -> string

    (** char conversion of the taint *)
    val char_of_taint: t -> char

    (** string conversion of the taint *)
    val string_of_taint: t -> string

    (** add operation. The optional return value is None when no carry
    occurs in the result and Some c with c the carry value otherwise *)
    val add: t -> t -> t * (t option)

    (** sub operation. The optional return value is None when no borrow
    occurs and Some b with b the borrow value otherwise *)
    val sub: t -> t -> t * (t option)

    (** xor operation *)
    val xor: t -> t -> t

    (** logical and *)
    val logand: t -> t -> t

    (** logical or *)
    val logor: t -> t -> t

    (** bit not *)
    val lognot: t -> t

    (** untaint *)
    val untaint: t -> t

    (** taint *)
    val taint: t -> t

    (** update taint *)
    val update_taint: Taint.t -> t -> t

    (** set bit *)
    val set_bit: t -> t

    (** clear bit *)
    val clear_bit: t -> t

    (** update bit *)
    val update_bit: Bit.t -> t -> t

    (** abstract value of 1 *)
    val one: t

    (** comparison to one *)
    val is_one: t -> bool

    (** abstract value of 0 *)
    val zero: t

    (** comparison to zero *)
    val is_zero: t -> bool

    (** strictly less than comparison *)
    val lt: t -> t -> bool

    (** strictly less than comparison *)
    val lt_multibit_helper: t -> t -> (bool option)

    (** greater than or equal to comparison *)
    val geq: t -> t -> bool

    (** check whether the first abstract value is included in the second one *)
    val is_subset: t -> t -> bool

    (** comparison *)
    val compare: t -> Asm.cmp -> t -> bool

    (** undefine the taint of the given value *)
    val forget_taint_src: t -> Taint.Src.id_t -> t

    (** returns the taint value of the given parameter *)
    val get_taint: t -> Taint.t

    (** forget the taint of the given value *)
    val forget_taint: t -> t
end

(** signature of vector *)
module type T =
sig
    (** abstract data type *)
    type t
      
    (** top on sz bit-width *)
    val top: int -> t

    (** returns length *)
    val size: t -> int

    (** forgets the content while preserving the taint *)
    val forget: t -> (int * int) option -> t
    (** the forget operation is bounded to bits from l to u if the second parameter is Some (l, u) *)

    (** value conversion. May raise an exception *)
    val to_z: t -> Z.t

    (** char conversion. May raise an exception *)
    val to_char: t -> char

    (** abstract join *)
    val join: t -> t -> t

    (** abstract meet *)
    val meet: t -> t -> t

    (** widening *)
    val widen: t -> t -> t

    (** string conversion *)
    val to_string: t -> string

    (** string conversion (value string, taint string) *)
    val to_strings: t -> string * string

    (** binary operation *)
    val binary: Asm.binop -> t -> t -> t

    (** unary operation *)
    val unary: Asm.unop -> t -> t

    (** untaint *)
    val untaint: t -> t

    (** taint *)
    val taint: t -> t

    (** span taint *)
    val span_taint: t -> Taint.t -> t

    (** conversion from word *)
    val of_word: Data.Word.t -> t

    (** comparison *)
    val compare: t -> Asm.cmp -> t -> bool

    (** conversion to a set of addresses *)
    val to_addresses: Data.Address.region -> t -> Data.Address.Set.t

    (** check whether the first argument is included in the second one *)
    val is_subset: t -> t -> bool

    (** conversion from a config value.
    The integer parameter is the size in bits of the config value *)
    val of_config: Config.cvalue -> int -> t

    (** conversion from a tainting value.
        The value option is a possible previous init.
        The computed taint is also returned *)
    val taint_of_config: Config.tvalue list -> int -> t option -> t * Taint.t

    (** [combine v1 v2 l u] computes v1[l, u] <- v2 *)
    val combine: t -> t -> int -> int -> t

    (** return the value corresponding to bits l to u may raise an exception if range bits exceeds the capacity of the vector *)
    val extract: t -> int -> int -> t

    (** [from_position v i len] returns the sub-vector v[i]...v[i-len-1] may raise an exception if i > |v| or i-len-1 < 0 *)
    val from_position: t -> int -> int -> t

    (** [of_repeat_val v v_len nb] returns the concatenation of pattern v having length v_len, nb times *)
    val of_repeat_val: t -> int -> int -> t

    (** returns the concatenation of the two given vectors *)
    val concat: t -> t -> t

    (** returns the minimal taint value of the given parameter *)
    val get_minimal_taint: t -> Taint.t

    (** returns the taint value of the given parameter *)
    val taint_sources: t -> Taint.t

    (** return the taint of the given argument *)
    val get_taint: t -> Taint.t

    (** forget the taint of the given argument *)
    val forget_taint: t -> t
end

module Make(V: Val) =
  (struct
    type t = V.t array (** bit order is big endian, ie v[0] is the most significant bit and v[Array.length v - 1] the least significant *)
      
    let top sz = Array.make sz V.top

    let exists p v =
      try
        Array.iter (fun b -> if p b then raise Exit) v;
        false
      with Exit -> true
        
    let exist2 p v1 v2 =
      let n = min (Array.length v1) (Array.length v2) in
      try
        for i = 0 to n-1 do
          if p v1.(i) v2.(i) then raise Exit
        done;
        false
      with
      | Exit -> true
      | _    -> false
         
         
    let for_all2 p v1 v2 =
      try
        for i = 0 to (Array.length v1)-1 do
          if not (p v1.(i) v2.(i)) then raise Exit
        done;
        true
      with
      | _-> false
         
    let v_to_z conv v =
      let z = ref Z.zero in
      for i = 0 to (Array.length v) - 1 do
        let n = conv v.(i) in
        z := Z.add n (Z.shift_left !z 1)
      done;
      !z
            
    let to_char (v: t): char =
      let l = Array.length v in
      if l <> 8 then
        L.abort (fun p -> p "attempting to convert a vector of size %i into a char" l)
      else
        begin
          let c = ref 0 in
          for i = 0 to 7 do
            c := (V.to_int v.(i)) + ((!c) lsl 1)
          done;
          Char.chr !c
        end
          
    let size v = Array.length v
      
    let to_z v = v_to_z V.to_z v
    (* this function may raise an exception if one of the bits cannot be converted into a Z.t integer (one bit at BOT or TOP) *)
    let to_word conv v = Data.Word.of_int (v_to_z conv v) !Config.address_sz
      
    let extract_strings v =
      let v' =
        if exists V.is_top v then
          let v_bytes = Bytes.create (Array.length v) in
          let set_char = (fun i c -> Bytes.set v_bytes i (V.to_char c)) in
          Array.iteri set_char v ;
          "0b"^Bytes.to_string v_bytes
        else
          Data.Word.to_string (to_word V.to_z v)
      in
      let taint_bytes = Bytes.create (Array.length v) in
      let t =
        try
          let all = ref true in
          let r = to_word (fun v -> let t = V.taint_to_z v in if Z.compare t Z.one <> 0 then all := false; t) v in
          if !all then
            "ALL"
          else
            Data.Word.to_string r
        with _ ->
          let set_taint_char = (fun i c -> Bytes.set taint_bytes i (V.char_of_taint c)) in
          Array.iteri set_taint_char v;
          "0b"^Bytes.to_string taint_bytes
      in
      v', t
        
    let to_string v =
      let v', t = extract_strings v in
      if String.compare t "0x0" == 0 then v'
      else Printf.sprintf "%s!%s" v' t

    let map2 f v1 v2 =
      let n = Array.length v1 in
      let n2 = Array.length v2 in
      if n <> n2 then
        L.abort (fun p -> p "map2 on vectors of different sizes (v1=%s(%i) v2=%s(%i)"
          (to_string v1) n (to_string v2) n2)
      else
        let v = Array.make n V.top in
        for i = 0 to n-1 do
          v.(i) <- f v1.(i) v2.(i)
        done;
        v
          
    let to_strings v = extract_strings v
      
    let concat v1 v2 = Array.append v1 v2
      
    let join v1 v2 = map2 V.join v1 v2
      
    let meet v1 v2 = map2 V.meet v1 v2
      
    let widen v1 v2 = map2 V.widen v1 v2
        
    (* common utility to add and sub *)
    let core_add_sub op v1 v2 =
      let n = Array.length v1 and lv2 = (Array.length v2) in
      if n <> lv2 then
        L.abort (fun p -> p "code_add_sub vectors of different sizes (v1=%s(%i) v2=%s(%i))"
          (to_string v1) n (to_string v2) lv2)
      else
        let v = Array.make n V.zero in
        let carry_borrow = ref None in
        for i = n-1 downto 0 do
          let c =
            (* add the carry/borrow if present *)
            match !carry_borrow with
            | None -> v.(i) <- v1.(i); None
            | Some b' -> let b', c' = op v1.(i) b' in v.(i) <- b'; c'
          in
          (* compute the ith bit of the result with the ith bit of the operand *)
          let b, c' = op v.(i) v2.(i) in
          v.(i) <- b;
          (* update the new carry/borrow *)
          match c with
          | Some _ -> carry_borrow := c
          | None   -> carry_borrow := c' (* correct as we know that we cannot have both cpred = Some ... and c' = Some ... *)
        done;
        v
          
          
    let lt_core v1 v2 final is_signed =
      let lv1 = Array.length v1 in
      let lv2 = Array.length v2 in
      if lv1 <> lv2 then
        L.abort (fun p -> p "lt_core : comparing vectors of different sizes (v1:%i, v2:%i)" lv1 lv2)
      else
        let rec rec_lt v1 v2 i =
          if i >= lv1 then final
          else
            let nxt = V.lt_multibit_helper v1.(i) v2.(i) in
            match nxt with
            | Some b -> b
            | None -> rec_lt v1 v2 (i+1)
        in
        (* check whether v1 and v2 have the same sign *)
        if not is_signed then
          rec_lt v1 v2 0
        else
          (* correct as the comparison is performed only on bit values and not their taints, 
             see Reduced_bit_taing.compare *)
          if V.compare v1.(0) Asm.EQ v2.(0) then
            rec_lt v1 v2 0
          else
            (* signs are different *)
            V.is_one v1.(0)
          
    let lt v1 v2 is_signed = lt_core v1 v2 false is_signed
    let leq v1 v2 is_signed = lt_core v1 v2 true is_signed
    let gt v1 v2 = lt v2 v1 false
    let geq v1 v2 is_signed = leq v2 v1 is_signed

    let compare v1 op v2 =
      L.debug2 (fun p -> p "compare %s %s %s" (to_string v1) (Asm.string_of_cmp op) (to_string v2));
      if (Array.length v1) != (Array.length v2) then
        L.abort (fun p -> p "BAD Vector.compare(%s,%s,%s) len1=%i len2=%i"
          (to_string v1) (Asm.string_of_cmp op) (to_string v2)
          (Array.length v1) (Array.length v2));
      match op with
      | Asm.EQ  -> for_all2 (fun b1 b2 -> V.compare b1 op b2) v1 v2
      | Asm.NEQ -> exist2 (fun b1 b2 -> V.compare b1 op b2) v1 v2
      | Asm.LT -> lt v1 v2 false
      | Asm.LEQ -> leq v1 v2 false
      | Asm.GT -> gt v1 v2
      | Asm.GEQ -> geq v1 v2 false
      | Asm.LTS -> lt v1 v2 true
      | Asm.GES -> geq v1 v2 true
         
    let add v1 v2 =
      let res = core_add_sub V.add v1 v2 in
      L.debug2 (fun p -> p "add(%s, %s) = %s"
        (to_string v1) (to_string v2) (to_string res));
      res
        
    let sub v1 v2 = core_add_sub V.sub v1 v2
      
    let xor v1 v2 =
      let res = map2 V.xor v1 v2 in
      L.debug2 (fun p -> p "xor(%s, %s) = %s"
        (to_string v1) (to_string v2) (to_string res));
      res
        
    let lognot v = Array.map V.lognot v
      
    let neg v =
      let n = Array.length v in
      let one = Array.make n V.zero in
      one.(n-1) <- V.one;
      add (lognot v) one
        
    let logand v1 v2 =
      let lv1 = (Array.length v1) and lv2 = (Array.length v2) in
      if lv1 <> lv2 then
        L.abort (fun p -> p "logand vectors of different sizes (v1=%s(%i) v2=%s(%i))"
          (to_string v1) lv1 (to_string v2) lv2)
      else
        let res = map2 V.logand v1 v2 in
        L.debug2 (fun p -> p "logand(%s, %s)=%s"
          (to_string v1) (to_string v2) (to_string res));
        res

    let logor v1 v2 =
      let lv1 = (Array.length v1) and lv2 = (Array.length v2) in
      if lv1 <> lv2 then
        L.abort (fun p -> p "logor vectors of different sizes (v1=%s(%i) v2=%s(%i))"
          (to_string v1) lv1 (to_string v2) lv2)
      else
        let res = map2 V.logor v1 v2 in
        L.debug2 (fun p -> p "logor(%s, %s)=%s"
          (to_string v1) (to_string v2) (to_string res));
        res
          
    let sign_extend v i =
      let n = Array.length v in
      if n >= i then
        v
      else
        begin
          let sign = v.(0) in
          let o    = i - n in
          let v' =
            if V.is_zero sign then Array.make i V.zero
            else Array.make i V.one
          in
          for j = 0 to n-1 do
            v'.(j+o) <- v.(j)
          done;
          v'
        end
          
    let truncate v new_sz =
      let sz = Array.length v in
      L.debug (fun p -> p "truncate((%d)%s, %d)" sz (to_string v) new_sz);
      if sz < new_sz then
        L.abort (fun p -> p "truncate cannont truncate v=(%d)%s to %d bits"
          sz (to_string v) new_sz)
      else
        let res = Array.make new_sz V.zero in
        for i = 0 to new_sz-1 do
          res.(i) <- v.(i+sz-new_sz)
        done;
        res
          
    let zero_extend v new_sz =
      let sz = Array.length v in
      L.debug2 (fun p -> p "zero_extend((%d)%s, %d)" sz (to_string v) new_sz);
      if new_sz < sz then
        L.abort (fun p -> p "zero_extend cannont extend v=(%d)%s to %d bits"
          sz (to_string v) new_sz)
      else
        let o  = new_sz - sz in
        let new_v = Array.make new_sz V.zero in
        for i = 0 to sz-1 do
          new_v.(i+o) <- v.(i)
        done;
        new_v

    let ishl v shift =
      let v_len  = Array.length v      in
      let res = Array.make v_len V.zero in
      let o  = v_len-shift                 in
      for j = 0 to o-1 do
        res.(j) <- v.(shift+j)
      done;
      L.debug2 (fun p -> p "ishl(%s, %d) = %s"
        (to_string v) shift (to_string res));
      res
        
    let ishr v shift pad =
      let v_len = Array.length v in
      let res = Array.make v_len pad in
      for j = 0 to v_len-shift-1 do
        res.(j+shift) <- v.(j)
      done;
      L.debug2 (fun p -> p "ishr(%s, %d) = %s"
        (to_string v) shift (to_string res));
      res
        
    let irotate v shift =
      let v_len = Array.length v in
      let res = Array.make v_len V.zero in
      for j = 0 to v_len-1 do
        res.(j) <- v.((j+shift) mod v_len)
      done;
      L.debug2 (fun p -> p "irotate(%s,%d)=%s"
        (to_string v) shift (to_string res));
      res
        
        
    let shift_count_to_int v =
      let z_shift_count = to_z v in
      try
        Z.to_int z_shift_count
      with Z.Overflow ->
        raise (Exceptions.Too_many_concrete_elements
                 (Printf.sprintf "vector.shr: shift count overflow: %s"
                    (Z.to_string z_shift_count)))
          
          
    let shl v1 v2 =
      let shift_count = shift_count_to_int v2 in
      ishl v1 shift_count
        
    let shr v1 v2 =
      let shift_count = shift_count_to_int v2 in
      ishr v1 shift_count V.zero (* pad with zero *)
        
    let _ashr v1 v2 =
      let shift_count = shift_count_to_int v2 in
      ishr v1 shift_count v1.(0) (* pad with high bit *)
        
    let _rol v1 v2 =
      let shift_count = shift_count_to_int v2 in
      irotate v1 shift_count
        
    let _ror v1 v2 =
      let shift_count = shift_count_to_int v2 in
      irotate v1 (-shift_count)


    let mul v2 v1 =
      let n   = Array.length v1 in
      let nn   = 2*n in
      let v2_ext = zero_extend v2 nn    in
      let res = ref (Array.make nn V.zero) in
      
      for i = 0 to n-1 do
        let v2_ext_shift = ishl v2_ext (n-i-1) in
        let v2_ext_shift_mul = Array.map (V.logand v1.(i)) v2_ext_shift in
        res := add !res v2_ext_shift_mul
      done;
      !res
        
    let imul v1 v2 =
      L.debug2 (fun p -> p "imul((%d)%s, (%d)%s)"
        (Array.length v1) (to_string v1) (Array.length v2) (to_string v2));
      let v1_len = Array.length v1 in
      let v2_len = Array.length v2 in
      let long_v1 = sign_extend v1 (v1_len*2) in
      let long_v2 = sign_extend v2 (v2_len*2) in
      let fullres = mul long_v1 long_v2 in
      L.debug2 (fun p -> p "imul fullres = %s" (to_string fullres));
      let res = Array.sub fullres (v1_len*2) (v1_len*2) in
      L.debug2 (fun p -> p "imul return %s" (to_string res));
      res
        
    (** return v1 / v2, modulo of v1 / v2 *)
    let core_div v1 v2 =
      let lv1   = Array.length v1    in
      let lv2   = Array.length v2    in
      if lv1 < lv2 then
        L.abort (fun p -> p "core_div : dividing a vector by a bigger vector is not supported (v1=%s(%i) v2=%s(%i))"
          (to_string v1) lv1 (to_string v2) lv2)
      else
        begin
          (* find most significant bit to 1 and check that v2 is not zero *)
          let v2_ext = if lv1 > lv2 then zero_extend v2 lv1 else v2 in
          let msb1 = ref 0 in
          while (!msb1 < lv1) && (V.is_zero v2_ext.(!msb1)) do
            msb1 := !msb1+1;
          done;
          if !msb1 = lv1 then
            L.abort (fun p -> p "core_div((%d)%s, (%d)%s): Division by zero"
              (Array.length v1) (to_string v1)
              (Array.length v2) (to_string v2)
            )
          else
            let quo = Array.make lv1 V.zero in
            let rem = ref v1 in
            for i = !msb1 downto 0 do
              let sv2 = ishl v2_ext i in
              if geq !rem sv2 false then
                begin
                  rem := sub !rem sv2;
                  quo.(lv1-i-1) <- V.one;
                end
            done;
            rem := truncate !rem lv2;
            L.debug2 (fun p -> p "core_div((%d)%s, (%d)%s) = (%d)%s rem=(%d)%s"
              (Array.length v1) (to_string v1)
              (Array.length v2) (to_string v2)
              (Array.length quo) (to_string quo)
              (Array.length !rem) (to_string !rem));
            quo,!rem
        end
          
    let is_neg v1 =
      V.is_one v1.(0) || V.is_top v1.(0)

    let core_idiv v1 v2 =
      let is_neg_v1 = is_neg v1 in
      let is_neg_v2 = is_neg v2 in
      let v1' = if is_neg_v1 then neg v1 else v1 in
      let v2' = if is_neg_v2 then neg v2 else v2 in
      let quo,rem = core_div v1' v2' in
      let quo' = if is_neg_v1 <> is_neg_v2 then (neg quo) else quo in
      let rem' = if is_neg_v1 then (neg rem) else rem in
      L.debug2 (fun p -> p "core_idiv (%d)%s, (%d)%s = (%d)%s mod=(%d)%s"
        (Array.length v1) (to_string v1)
        (Array.length v2) (to_string v2)
        (Array.length quo') (to_string quo')
        (Array.length rem') (to_string rem'));
      quo',rem'

    let div v1 v2 = fst (core_div v1 v2)
    let modulo v1 v2 = snd (core_div v1 v2)
    let idiv v1 v2 = fst (core_idiv v1 v2)
    let imodulo v1 v2 = snd (core_idiv v1 v2)


    let binary op v1 v2 =
      match op with
      | Asm.Add -> add v1 v2
      | Asm.Sub -> sub v1 v2
      | Asm.Xor -> xor v1 v2
      | Asm.And -> logand v1 v2
      | Asm.Or  -> logor v1 v2
      | Asm.IMul -> imul v1 v2
      | Asm.IDiv -> idiv v1 v2
      | Asm.Mul -> mul v1 v2
      | Asm.Div -> div v1 v2
      | Asm.Mod -> modulo v1 v2
      | Asm.IMod -> imodulo v1 v2
      | Asm.Shl -> shl v1 v2
      | Asm.Shr -> shr v1 v2
         
         
    let unary op v =
      match op with
      | Asm.Not       -> lognot v
      | Asm.SignExt i -> sign_extend v i
      | Asm.ZeroExt i -> let res = zero_extend v i in L.debug2 (fun p -> p
        "zero_extend new length : %d" (Array.length res)); res
        
    let untaint v = Array.map V.untaint v
      
    let taint v = Array.map V.taint v
      
    let span_taint v t = Array.map (V.update_taint t) v
      
    let get_minimal_taint v =
      Array.fold_left (fun acc v -> Taint.min acc (V.get_taint v)) Taint.U v
        
        
    let nth_of_z_as_val v i = if Z.testbit v i then V.one else V.zero
    let nth_of_z v i = if Z.testbit v i then Z.one else Z.zero
        

    (* real implementation of 'of_word' *)
    let of_word_real w =
      let sz = Data.Word.size w    in
      let w' = Data.Word.to_int w  in
      let r  = Array.make sz V.top in
      let n' = sz-1 in
      for i = 0 to n' do
        r.(n'-i) <- nth_of_z_as_val w' i
      done;
      r

    (* Hashtbl to memoize "of_word" *)
    let const_htbl = ref (Hashtbl.create 1000)

    (* memoized version, see 'of_word_real' *)
    let of_word w =
      try
        begin
          let value = Hashtbl.find !const_htbl w in
          value
        end
      with Not_found -> begin
          let r = of_word_real w in
          Hashtbl.add !const_htbl w r;
          r
     end
        
    let to_addresses r v =
      Data.Address.Set.singleton (r, to_word V.to_z v)
      
    let is_subset v1 v2 = for_all2 V.is_subset v1 v2
      
    let of_config c n =
      let v  = Array.make n V.top in
      let n' = n-1                in
      begin
        match c with
        | Config.Bytes (_, b)         ->
           let get_byte s i = (Z.of_string_base 16 (String.sub s (i/4) 1)) in
           for i = 0 to n' do
             v.(n'-i) <- nth_of_z_as_val (get_byte b (n'-i)) (i mod 4)
           done;
        | Config.Bytes_Mask ((_, b), m) ->
           let get_byte s i = (Z.of_string_base 16 (String.sub s (i/4) 1)) in
           for i = 0 to n' do
             if Z.testbit m i then
               v.(n'-i) <- V.top
             else
               v.(n'-i) <- nth_of_z_as_val (get_byte b (n'-i)) (i mod 4)
           done;
        | Config.Content (_, c)         ->
           for i = 0 to n' do
             v.(n'-i) <- nth_of_z_as_val c i
           done
        | Config.CMask ((_, c), m) ->
           for i = 0 to n' do
             if Z.testbit m i then
               v.(n'-i) <- V.top
             else
               v.(n'-i) <- nth_of_z_as_val c i
           done
      end;
      v

    let taint_of_config taints n (prev: t option): t * Taint.t =
      let v =
        match prev with
        | Some v' -> Array.copy v'
        | None    -> Array.make n V.top
      in
      let n' = n-1 in
      let set_one_taint (is_first: bool) (t: Config.tvalue): Taint.t =
        match t with
        | Config.TBytes (b, tid) ->
           let get_byte s i = (Z.of_string_base 16 (String.sub s (i/4) 1)) in
           for i = 0 to n' do
             let v' = V.taint_of_z (nth_of_z (get_byte b (n'-i)) (i mod 4)) v.(n'-i) tid in
             if is_first then
               v.(n'-i) <- v'
             else
               v.(n'-i) <- V.taint_logor v.(n'-i) v'
           done;
           Taint.S (Taint.SrcSet.singleton (Taint.Src.Tainted tid)) 
             
        | Config.TBytes_Mask (b, m, tid) ->
           let get_byte s i = (Z.of_string_base 16 (String.sub s (i/4) 1)) in
           for i = 0 to n' do           
             if Z.testbit m i then
               let v' = V.forget_taint_src v.(n'-i) tid in
               if is_first then
                 v.(n'-i) <- v'
               else
                 v.(n'-i) <- V.taint_logor v.(n'-i) v'
             else
               let v' = V.taint_of_z (nth_of_z (get_byte b (n'-i)) (i mod 4)) v.(n'-i) tid in
               if is_first then
                 v.(n'-i) <- v'
               else
                 v.(n'-i) <- V.taint_logor v.(n'-i) v'
           done;
           Taint.S (Taint.SrcSet.singleton (Taint.Src.Tainted tid))
             
        | Config.Taint (b, tid) ->
           for i = 0 to n' do
             let v' = V.taint_of_z (nth_of_z b i) v.(n'-i) tid in
               if is_first then
                 v.(n'-i) <- v'
               else
                 v.(n'-i) <- V.taint_logor v.(n'-i) v'
           done;
          if Z.compare b Z.zero = 0 then Taint.U
          else Taint.S (Taint.SrcSet.singleton (Taint.Src.Tainted tid))
            
        | Config.Taint_all tid ->
           let n' =n-1 in
           for i = 0 to n' do
             let v' = V.taint_of_z Z.one v.(n'-i) tid in
             if is_first then
               v.(n'-i) <- v'
             else
               v.(n'-i) <- V.taint_logor v.(n'-i) v'
           done;
           Taint.S (Taint.SrcSet.singleton (Taint.Src.Tainted tid))
             
        | Config.Taint_none ->
           let n' =n-1 in
           for i = 0 to n' do
             let v' = V.untaint v.(n'-i) in
             if is_first then
               v.(n'-i) <- v'
             else
               v.(n'-i) <- V.taint_logor v.(n'-i) v'
           done;
           Taint.U
             
        | Config.TMask (b, m, tid) ->
           let n' = n-1 in
           for i = 0 to n' do
             let bnth = nth_of_z b i in
             let mnth = nth_of_z m i in
             if Z.compare mnth Z.zero = 0 then
               let v' = V.taint_of_z bnth v.(n'-i) tid in
               if is_first then
                 v.(n'-i) <- v'
               else
                 v.(n'-i) <- V.taint_logor v.(n'-i) v'
             else
               let v' = V.forget_taint_src v.(n'-i) tid in
               if is_first then
                 v.(n'-i) <- v' 
               else
               v.(n'-i) <- V.taint_logor v.(n'-i) v'
           done;
           if Z.compare m Z.zero = 0 then
             if Z.compare b Z.zero = 0 then Taint.U
             else Taint.S (Taint.SrcSet.singleton (Taint.Src.Tainted tid))
           else Taint.S (Taint.SrcSet.singleton (Taint.Src.Maybe tid))
      in
      if List.length taints > 0 then
        let taint0 = set_one_taint true (List.hd taints) in
        let taint' = List.fold_left (fun prev_t t -> Taint.logor prev_t (set_one_taint false t)) taint0 (List.tl taints) in
        v, taint'
      else
        v, Taint.U
        
    let forget v opt =
      L.debug (fun (p: ('a, unit, string) format -> 'a) ->
        match opt with
        | None -> p "Forget vector [%s(%d)] (all bits)%0.0i%0.0i" (to_string v) (Array.length v) 0 0
        | Some (l,u) -> p "Forget vector [%s(%d)] bits %i -> %i " (to_string v) (Array.length v) l u
      );
      let v' = Array.copy v in
        match opt with
      | Some (l, u) ->
         let n = (Array.length v')-1 in
         for i = l to u do
           v'.(n-i) <- V.forget v'.(n-i)
         done;
         v'
      | None -> Array.map V.forget v'

    (** copy bits from v2 to bits from low to up of v1,
        vectors can be of different sizes *)
    let combine v1 v2 low up =
      L.debug2 (fun p -> p "combine(%s(%d)[%d:%d] <- %s(%d))"
        (to_string v1) (Array.length v1)  low up (to_string v2) (Array.length v2));
      let sz2 = Array.length v2 in
      if sz2 <> up-low+1 then
        L.abort (fun p -> p "combine: source is %d bits while it is supposed to fit into %d bits (from bit %i to %i)"
          sz2 (up-low+1) low up)
      else
        if low > up then L.abort (fun p -> p "combine : low=%i > up=%i" low up)
        else
          let sz1 = Array.length v1 in
          if up >= sz1 then
            L.abort (fun p -> p "combine : writing out of v1: up=%i >= length(v1)=%i" up sz1)
            else
            begin
              let v = Array.copy v1 in
              let j = ref 0 in
              for i = (sz1-1-up) to (sz1-1-low) do
                v.(i) <- v2.(!j);
                j := !j+1;
              done;
              v
            end

        let extract v low up =
          L.debug2 (fun p -> p "extract(%s, %d, %d), sz : %d" (to_string v) low up (Array.length v));
          let v' = Array.make (up-low+1) V.top in
          let n  = Array.length v in
          let o  = n-up - 1 in
          for i = o to n-low-1 do
            v'.(i-o) <- v.(i)
          done;
          v'

        let from_position v l len =
          let n = Array.length v in
          Array.sub v (n-l-1) len


        let of_repeat_val v v_len nb =
          let access_mod idx = v.(idx mod v_len) in
          let v_array = Array.init (nb*v_len) access_mod in
          v_array

        let taint_sources v =
          Array.fold_left (fun acc elt -> Taint.logor acc (V.get_taint elt)) (Taint.U) v

        let get_taint = taint_sources

        let forget_taint v =
          Array.map (V.update_taint Taint.TOP) v       
          
    end: T)
