(** vector lifting of a value_domain *)
(** binary operations are supposed to apply on operands of the same length *)

(** signature of value domain *)
module type Val =
sig
    (** abstract data type *)
    type t
    (** top *)
    val top: t
    (** returns true whenever the bit may be tainted *)
    val is_tainted: t -> bool
    (** comparison to top *)
    val is_top: t -> bool
    (** conversion to value of type Z.t. May raise an exception *)
    val to_z: t -> Z.t
    (** conversion of the taint value of the parameter into a Z value. May raise an exception *)
    val taint_to_z: t -> Z.t
    (** conversion from Z.t value *)
    val of_z: Z.t -> t
    (** taint the given value from Z.t value *)
    val taint_of_z: Z.t -> t -> t
    (** abstract join *)
    val join: t -> t -> t
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
    (** add operation. The optional return value is None when no carry *)
    (** occurs in the result and Some c with c the carry value otherwise *)
    val add: t -> t -> t * (t option)
    (** sub operation. The optional return value is None when no borrow *)
    (** occurs and Some b with b the borrow value otherwise *)
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
    (** weak taint *)
    val weak_taint: t -> t
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
    (** greater than or equal to comparison *)
    val geq: t -> t -> bool
    (** check whether the first abstract value is included in the second one *)
    val subset: t -> t -> bool
    (** comparison *)
    val compare: t -> Asm.cmp -> t -> bool
    (** undefine the taint of the given value *)
    val forget_taint: t -> t
end

(** signature of vector *)
module type T =
sig
    (** abstract data type *)
    type t
    (** top on sz bit-width *)
    val top: int -> t
    (** returns true whenever at least one bit may be tainted *)
    val is_tainted: t -> bool
    (** value conversion. May raise an exception *)
    val to_z: t -> Z.t
    (** abstract join *)
    val join: t -> t -> t
    (** abstract meet *)
    val meet: t -> t -> t
    (** widening *)
    val widen: t -> t -> t
    (** string conversion *)
    val to_string: t -> string
    (** binary operation *)
    val binary: Asm.binop -> t -> t -> t
    (** unary operation *)
    val unary: Asm.unop -> t -> t
    (** untaint *)
    val untaint: t -> t
    (** taint *)
    val taint: t -> t
    (** weak taint *)
    val weak_taint: t -> t
    (** conversion from word *)
    val of_word: Data.Word.t -> t
    (** comparison *)
    val compare: t -> Asm.cmp -> t -> bool
    (** conversion to a set of addresses *)
    val to_addresses: Data.Address.region -> t -> Data.Address.Set.t
    (** check whether the first argument is included in the second one *)
    val subset: t -> t -> bool
    (** conversion from a config value *)
    (** the integer parameter is the size in bits of the config value *)
    val of_config: Config.cvalue -> int -> t
    (** conversion from a tainting value *)
    (** the value option is a possible previous init *)
    val taint_of_config: Config.tvalue -> int -> t option -> t
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
end

module Make(V: Val) =
    (struct
        type t = V.t array (** bit order is big endian, ie v[0] is the most significant bit and v[Array.length v - 1] the least significant *)

        let top sz = Array.make sz V.top

        let exists p v =
            try
                for i = 0 to (Array.length v) - 1 do
                    if p v.(i) then raise Exit
                done;
                false
            with Exit -> true

        let map2 f v1 v2 =
            let n = min (Array.length v1) (Array.length v2) in
            let v = Array.make n V.top                      in
            for i = 0 to n-1 do
                v.(i) <- f v1.(i) v2.(i)
            done;
            v

        let for_all2 p v1 v2 =
            try
                for i = 0 to (Array.length v1)-1 do
                    if not (p v1.(i) v2.(i)) then raise Exit
                done;
                true
            with
            | _-> false

        let for_all p v =
            try
                for i = 0 to (Array.length v) -1 do
                    if not (p v.(i)) then raise Exit
                done;
                true
            with _ -> false

        let v_to_z conv v =
            try
                let z = ref Z.zero in
                for i = 0 to (Array.length v) - 1 do
                    let n = conv v.(i) in
                    z := Z.add n (Z.shift_left !z 1)
                done;
                !z
            with _ -> raise Exceptions.Concretization

    let to_z v = v_to_z V.to_z v 
    (* this function may raise an exception if one of the bits cannot be converted into a Z.t integer (one bit at BOT or TOP) *)
    let to_word conv v = Data.Word.of_int (v_to_z conv v) (Array.length v)

    let to_string v =
        let v' =
            if exists V.is_top v then
                let v_bytes = Bytes.create (Array.length v) in
                let set_char = (fun i c -> Bytes.set v_bytes i (V.to_char c)) in
                Array.iteri set_char v ;
                "0b"^Bytes.to_string v_bytes
            else
                Data.Word.to_string (to_word V.to_z v)
        in
        let taint_bytes = Bytes.create ((Array.length v)) in
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
        if String.compare t "0x0" == 0 then v'
        else Printf.sprintf "%s!%s" v' t


        let join v1 v2 = map2 V.join v1 v2

        let meet v1 v2 = map2 V.meet v1 v2

        let widen v1 v2 =
            if Z.compare (to_z v1) (to_z v2) <> 0 then
                raise Exceptions.Enum_failure
            else v1

        (* common utility to add and sub *)
        let core_add_sub op v1 v2 =
            let n = Array.length v1     in
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

        let add v1 v2 = core_add_sub V.add v1 v2
        let sub v1 v2 = core_add_sub V.sub v1 v2

        let xor v1 v2 = map2 V.xor v1 v2
        let logand v1 v2 = map2 V.logand v1 v2
        let logor v1 v2 = map2 V.logor v1 v2

        let zero_extend v new_sz =
            let sz = Array.length v in
            if new_sz <= sz then
                v
            else
                let o  = new_sz - sz              in
                let new_v = Array.make new_sz V.zero in
                for i = 0 to sz-1 do
                    new_v.(i+o) <- v.(i)
                done;
                new_v

        let ishl v i =
            let n  = Array.length v        in
            let v' = Array.make n V.zero in
            let o  = n-i                 in
            for j = 0 to o-1 do
                v'.(j) <- v.(i+j)
            done;
            v'

        let shl v1 v2 =
            try
                let i = Z.to_int (to_z v2) in
                ishl v1 i
            with _ -> raise Exceptions.Enum_failure

        let shr v n =
            Log.debug (Printf.sprintf "Vector.shr(%s,%s)" (to_string v) (to_string n));
            let v_len = Array.length v in
            try
                let n_i = Z.to_int (to_z n) in
                Log.debug (Printf.sprintf "Vector: %d" n_i);
                let v' = Array.make v_len V.zero in
                for j = 0 to v_len-n_i-1 do
                    v'.(j+n_i) <- v.(j)
                done;
                v'

            with
              _ -> raise Exceptions.Enum_failure

        let mul v1 v2 =
            let n   = 2*(Array.length v1) in
            let v   = Array.make n V.zero in
            let v2' = zero_extend v2 n    in
            let rec loop i v =
                if i = 0 then
                    v
                else
                    let v' =
                        if V.is_one v1.(i) then add v (ishl v2' i)
                        else v
                    in
                    loop (i-1) v'
            in
            loop (n-1) v

        (** returns true whenever v1 >= v2 *)
        exception Res of bool
        let geq v1 v2 =
            try
                for i = 0 to (Array.length v1) - 1 do
                    if V.lt v1.(i) v2.(i) then raise (Res false)
                    else
                    if V.lt v2.(i) v1.(i) then raise (Res true)
                done;
                true
            with Res b -> b

        (** return v1 / v2, modulo of v1 / v2 *)
        let core_div v1 v2 =
            (* check first that v2 is not zero *)
            if for_all V.is_zero v2 then
                Log.error "Division by zero"
            else
                let n   = Array.length v1     in
                let v   = Array.make n V.zero in
                let one = Array.make n V.one  in
                let rec loop v r =
                    if geq r v2 then
                        loop (add v one) (sub r v2)
                    else
                        v, r
                in
                loop v v1


        let div v1 v2 = fst (core_div v1 v2)

        let modulo v1 v2 = snd (core_div v1 v2)

        let binary op v1 v2 =
            match op with
            | Asm.Add -> add v1 v2
            | Asm.Sub -> sub v1 v2
            | Asm.Xor -> xor v1 v2
            | Asm.And -> logand v1 v2
            | Asm.Or  -> logor v1 v2
            | Asm.Mul -> mul v1 v2
            | Asm.Div -> div v1 v2
            | Asm.Mod -> modulo v1 v2
            | Asm.Shl -> shl v1 v2
            | Asm.Shr -> shr v1 v2



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

        let unary op v =
            match op with
            | Asm.Not       -> Array.map V.lognot v
            | Asm.SignExt i -> sign_extend v i
            | Asm.ZeroExt i -> zero_extend v i

        let untaint v = Array.map V.untaint v

        let taint v = Array.map V.taint v

        let weak_taint v = Array.map V.weak_taint v

        let nth_of_z_as_val v i = if Z.testbit v i then V.one else V.zero
        let nth_of_z v i = if Z.testbit v i then Z.one else Z.zero

        let of_word w =
            let sz = Data.Word.size w	   in
            let w' = Data.Word.to_int w  in
            let r  = Array.make sz V.top in
            let n' =sz-1 in
            for i = 0 to n' do
                r.(n'-i) <- nth_of_z_as_val w' i 
            done;
            r

        let to_addresses r v = Data.Address.Set.singleton (r, to_word V.to_z v)

        let subset v1 v2 = for_all2 V.subset v1 v2

        let of_config c n =
            let v  = Array.make n V.top in
            let n' = n-1                in
            begin
                match c with
                | Config.Bytes b         ->
                  let get_byte s i = (Z.of_string_base 16 (String.sub s (i/4) 1)) in
                  for i = 0 to n' do
                      v.(n'-i) <- nth_of_z_as_val (get_byte b (n'-i)) (i mod 4)
                  done;
                | Config.Bytes_Mask (b, m) -> 
                  let get_byte s i = (Z.of_string_base 16 (String.sub s (i/4) 1)) in
                  for i = 0 to n' do
                      if Z.testbit m i then
                          v.(n'-i) <- V.top
                      else
                          v.(n'-i) <- nth_of_z_as_val (get_byte b (n'-i)) (i mod 4)
                  done;
                | Config.Content c         ->
                  for i = 0 to n' do
                      v.(n'-i) <- nth_of_z_as_val c i
                  done
                | Config.CMask (c, m) ->
                  for i = 0 to n' do
                      if Z.testbit m i then
                          v.(n'-i) <- V.top
                      else
                          v.(n'-i) <- nth_of_z_as_val c i
                  done
            end;
            v

        let taint_of_config t n (prev: t option) =
            let v =
                match prev with
                | Some v' -> Array.copy v'
                | None    -> Array.make n V.top
            in
            match t with
            | Config.Taint b ->
              let n' =n-1 in
              for i = 0 to n' do
                  v.(n'-i) <- V.taint_of_z (nth_of_z b i) v.(n'-i)
              done;
              v
            | Config.TMask (b, m) ->
              let n' = n-1 in
              for i = 0 to n' do
                  let bnth = nth_of_z b i in
                  let mnth = nth_of_z m i in
                  if Z.compare mnth Z.zero = 0 then
                      v.(n'-i) <- V.taint_of_z bnth v.(n'-i)
                  else
                      v.(n'-i) <- V.forget_taint v.(n'-i)
              done;
              v

        (** copy bits from v2 to bits from low to up of v1,
         *  vectors can be of different sizes *)
        let combine v1 v2 low up =
            Log.debug (Printf.sprintf "Vector.combine : v1 = %s (%d)" (to_string v1) (Array.length v1));
            Log.debug (Printf.sprintf "Vector.combine : v2 = %s (%d)" (to_string v2) (Array.length v2));
            Log.debug (Printf.sprintf "Vector.combine : low = %d, up = %d" low up);
            if low > up || (up-low+1) > (Array.length v2) then
                Log.error "Vector.combine : low > up or length of src < up-low+1 "
            else
                let sz1 = Array.length v1 in
                let sz2 = Array.length v2 in
                if low >= sz1 || up >= sz1 || up-low+1 > sz2 then
                    Log.error "Vector.combine : low or up > vector len"
                else
		  begin
		    let v = Array.copy v1 in
		    let j = ref 0 in
		    for i = (sz1-1-up) to (sz1-1-low) do
		      v.(i) <- v2.(!j);
		      j := !j+1;
		    done;
                    Log.debug (Printf.sprintf "Vector.combine : res = %s" (to_string v));
                    v
		  end
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

        let compare v1 op v2 =
            if (Array.length v1) != (Array.length v2) then
                Log.error (Printf.sprintf "BAD Vector.compare(%s,%s,%s)" (to_string v1) (Asm.string_of_cmp op) (to_string v2));
            match op with
            | Asm.EQ  -> for_all2 (fun b1 b2 -> V.compare b1 op b2) v1 v2
            | Asm.NEQ -> exist2 (fun b1 b2 -> V.compare b1 op b2) v1 v2
            | _       -> true

        let extract v low up =
            (*            Log.debug (Printf.sprintf "Vector.extract %s %d %d" (to_string v) low up);*)
            let v' = Array.make (up-low+1) V.top in
            let n  = Array.length v           in
            let o  = n-up - 1                  in
            for i = o to n-low-1 do
                v'.(i-o) <- v.(i)
            done;
            v'

        let from_position v l len =
            Log.debug (Printf.sprintf "Vector.from_position %s %d %d" (to_string v) l len);
            let n = Array.length v in
            Array.sub v (n-l-1) len


        let is_tainted v = exists V.is_tainted v

        let of_repeat_val v v_len nb =
            let access_mod idx =
                v.(idx mod v_len) in
            let v_array = Array.init (nb*v_len) access_mod in
            v_array

        let concat v1 v2 = Array.append v1 v2
					
    end: T)
