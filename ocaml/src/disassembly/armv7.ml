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

(*
   Decoder for ARMv7
*)
module L = Log.Make(struct let name = "armv7" end)

module Make(Domain: Domain.T)(Stubs: Stubs.T with type domain_t := Domain.t) =
struct

  type ctx_t = unit

  open Data
  open Asm
  open Decodeutils


  (************************************************************************)
  (* Creation of the general purpose registers *)
  (************************************************************************)
  let (register_tbl: (int, Register.t) Hashtbl.t) = Hashtbl.create 16;;
  let r0 = Register.make ~name:"r0" ~size:32;;
  let r1 = Register.make ~name:"r1" ~size:32;;
  let r2 = Register.make ~name:"r2" ~size:32;;
  let r3 = Register.make ~name:"r3" ~size:32;;
  let r4 = Register.make ~name:"r4" ~size:32;;
  let r5 = Register.make ~name:"r5" ~size:32;;
  let r6 = Register.make ~name:"r6" ~size:32;;
  let r7 = Register.make ~name:"r7" ~size:32;;
  let r8 = Register.make ~name:"r8" ~size:32;;
  let r9 = Register.make ~name:"r9" ~size:32;;
  let r10 = Register.make ~name:"r10" ~size:32;;
  let r11 = Register.make ~name:"r11" ~size:32;;
  let r12 = Register.make ~name:"r12" ~size:32;;
  let sp = Register.make ~name:"sp" ~size:32;;
  let lr = Register.make ~name:"lr" ~size:32;;
  let pc = Register.make ~name:"pc" ~size:32;;

  (* execution state registers *)
  let itstate = Register.make ~name:"itstate" ~size:8;;

  (* condition flags are modeled as registers of size 1 *)
  let nflag = Register.make ~name:"n" ~size:1;;
  let zflag = Register.make ~name:"z" ~size:1;;
  let cflag = Register.make ~name:"c" ~size:1;;
  let vflag = Register.make ~name:"v" ~size:1;;
  let tflag = Register.make ~name:"t" ~size:1;;

  let reg n =
    match n with
    | 0 -> r0
    | 1 -> r1
    | 2 -> r2
    | 3 -> r3
    | 4 -> r4
    | 5 -> r5
    | 6 -> r6
    | 7 -> r7
    | 8 -> r8
    | 9 -> r9
    | 10 -> r10
    | 11 -> r11
    | 12 -> r12
    | 13 -> sp
    | 14 -> lr
    | 15 -> pc
    | _ -> L.abort (fun p -> p "Unknown register number %i" n)

  let treg n =
    T (reg n)

  let preg n a b =
    P ((reg n), a, b)

  let n_is_set = Cmp(EQ, Lval (V (T nflag)), const 1 1)
  let z_is_set = Cmp(EQ, Lval (V (T zflag)), const 1 1)
  let c_is_set = Cmp(EQ, Lval (V (T cflag)), const 1 1)
  let v_is_set = Cmp(EQ, Lval (V (T vflag)), const 1 1)
  let n_is_clear = Cmp(EQ, Lval (V (T nflag)), const 0 1)
  let z_is_clear = Cmp(EQ, Lval (V (T zflag)), const 0 1)
  let c_is_clear = Cmp(EQ, Lval (V (T cflag)), const 0 1)
  let v_is_clear = Cmp(EQ, Lval (V (T vflag)), const 0 1)


  let to33bits x = UnOp(ZeroExt 33, x)
  let to33bits_s x = UnOp(SignExt 33, x)

  let nflag_update_exp res_reg = Set(V (T nflag), Lval (V (P (res_reg, 31, 31))))

  let zflag_update_exp res_exp = Set(V (T zflag), TernOp (Cmp(EQ, res_exp, const 0 32),
                                                            const 1 1, const 0 1))

  let vflag_update_exp a b res =
    let bit31 = const 0x80000000 32 in
    Set(V (T (vflag)), TernOp (BBinOp (LogAnd,
                                       Cmp (EQ, BinOp(And, a, bit31),
                                            BinOp(And, b, bit31)),
                                       Cmp (NEQ, BinOp(And, a, bit31),
                                            BinOp(And, res, bit31))),
                               const 1 1, const 0 1))

  let set_cflag_vflag_after_add_with_carry a b carry =
    let tmpregu = Register.make (Register.fresh_name ()) 33 in
    let tmpregs = Register.make (Register.fresh_name ()) 33 in
    [ Set (V (T tmpregu), BinOp(Add, BinOp(Add, to33bits a, to33bits b),
                                to33bits carry)) ;
      Set (V (T tmpregs), BinOp(Add, BinOp(Add, to33bits_s a, to33bits_s b),
                                to33bits carry)) ;
      Set (V (T cflag), Lval (V (P (tmpregu, 32, 32)))) ;
      Set (V (T vflag), TernOp(Cmp(EQ, Lval (V (P (tmpregs, 31, 31))),
                                   Lval (V (P (tmpregs, 32, 32)))),
                               const 0 1, const 1 1)) ;
      Directive(Remove tmpregu) ;
      Directive(Remove tmpregs) ]

  let cflag_update_stmts op a b =
    let tmpreg = Register.make (Register.fresh_name ()) 33 in
    [ Set (V (T tmpreg), BinOp(op, to33bits a, to33bits b)) ;
      Set (V (T cflag), Lval (V (P (tmpreg, 32, 32)))) ;
      Directive (Remove tmpreg) ]

  let cflag_update_stmts_with_carry op a b =
    let tmpreg = Register.make (Register.fresh_name ()) 33 in
    [ Set (V (T tmpreg), BinOp(op, to33bits (Lval (V (T cflag))),
                               BinOp(op, to33bits a, to33bits b))) ;
      Set (V (T cflag), Lval (V (P (tmpreg, 32, 32)))) ;
      Directive (Remove tmpreg) ]


  let asm_cond cc = match cc with
    | 0b0000 -> z_is_set (* EQ - Z set (equal) *)
    | 0b0001 -> z_is_clear (* NE - Z clear (not equal) *)
    | 0b0010 -> c_is_set (* CS - C set (unsigned higher or same) *)
    | 0b0011 -> c_is_clear (* CC - C clear (unsigned lower) *)
    | 0b0100 -> n_is_set (* MI - N set (negative) *)
    | 0b0101 -> n_is_clear (* PL - N clear (positive or zero) *)
    | 0b0110 -> v_is_set (* VS - V set (overflow) *)
    | 0b0111 -> v_is_clear (* VC - V clear (no overflow) *)
    | 0b1000 -> BBinOp(LogAnd, c_is_set, z_is_clear) (* HI - C set and Z clear (unsigned higher) *)
    | 0b1001 -> BBinOp(LogOr, c_is_clear, z_is_set) (* LS - C clear or Z set (unsigned lower or same) *)

    (* GE - N set and V set, or N clear and V clear (greater or equal) *)
    | 0b1010 -> BBinOp(LogOr, BBinOp(LogAnd, n_is_set, v_is_set), BBinOp(LogAnd, n_is_clear, v_is_clear))

    (* LT - N set and V clear, or N clear and V set (less than) *)
    | 0b1011 -> BBinOp(LogOr, BBinOp(LogAnd, n_is_set, v_is_clear), BBinOp(LogAnd, n_is_clear, v_is_set))

    (* GT - Z clear, and either N set and V set, or N clear and V clear (greater than) *)
    | 0b1100 -> BBinOp(LogAnd, z_is_clear,
                       BBinOp(LogOr, BBinOp(LogAnd, n_is_set, v_is_set),
                              BBinOp(LogAnd, n_is_clear, v_is_clear)))
    (* LE - Z set, or N set and V clear, or N clear and V set (less than or equal) *)
    | 0b1101 -> BBinOp(LogOr, z_is_set,
                       BBinOp(LogOr, BBinOp(LogAnd, n_is_set, v_is_clear),
                              BBinOp(LogAnd, n_is_clear, v_is_set)))

    | _ -> L.abort (fun p -> p "Unexpected condiction code %x" cc)


  let op_add rd rn op2_stmt =
    [ Set (V (T rd), BinOp(Add, Lval (V (treg rn)), op2_stmt) ) ],
    [ zflag_update_exp (Lval (V (T rd))) ;
      nflag_update_exp rd ;
      vflag_update_exp (Lval (V (treg rn))) op2_stmt (Lval (V (T rd))) ; ]
    @ cflag_update_stmts Add (Lval (V (treg rn))) op2_stmt

  let op_sub rd rn op2_stmt =
    let tmpreg = Register.make (Register.fresh_name ()) 33 in
    [ Set (V (T rd), BinOp(Sub, Lval (V (treg rn)), op2_stmt) ) ],
    [ zflag_update_exp (Lval (V (T rd))) ;
      nflag_update_exp rd ;
      vflag_update_exp (Lval (V (treg rn))) (UnOp(Not, op2_stmt)) (Lval (V (T rd))) ;
      (* sub is computed witn sub a,b = a+(not b)+1, hence the carry *)
      Set (V (T tmpreg), BinOp(Add, BinOp(Add,
                                          to33bits (Lval (V (treg rn))),
                                          to33bits (UnOp(Not, op2_stmt))),
                               const 1 33)) ;
      Set (V (T cflag), Lval (V (P (tmpreg, 32, 32)))) ;
      Directive (Remove tmpreg) ]

  let op_rsb rd rn op2_stmt =
    let tmpreg = Register.make (Register.fresh_name ()) 33 in
    [ Set (V (T rd), BinOp(Sub, op2_stmt, Lval (V (treg rn)))) ],
    [ zflag_update_exp (Lval (V (T rd))) ;
      nflag_update_exp rd ;
      vflag_update_exp op2_stmt (UnOp(Not, (Lval (V (treg rn))))) (Lval (V (T rd))) ;
      Set (V (T tmpreg), BinOp(Add, BinOp(Add,
                                          to33bits op2_stmt,
                                          to33bits (UnOp(Not, Lval (V (treg rn))))),
                               const 1 33)) ;
      Set (V (T cflag), Lval (V (P (tmpreg, 32, 32)))) ;
      Directive (Remove tmpreg) ]

  let op_eor rd rn op2_stmt =
    [ Set (V (T rd), BinOp(Xor, Lval (V (treg rn)), op2_stmt) ) ],
    [ zflag_update_exp (Lval (V (T rd))) ;
      nflag_update_exp rd ]

  let op_and rd rn op2_stmt =
    [ Set (V (T rd), BinOp(And, Lval (V (treg rn)), op2_stmt) ) ],
    [ zflag_update_exp (Lval (V (T rd))) ;
      nflag_update_exp rd ]

  let op_bic rd rn op2_stmt =
    [ Set (V (T rd), BinOp(And, Lval (V (treg rn)), UnOp(Not, op2_stmt)) ) ],
    [ zflag_update_exp (Lval (V (T rd))) ;
      nflag_update_exp rd ]

  let op_mvn rd op2_stmt =
      [ Set (V (T rd), UnOp(Not, op2_stmt)) ],
      [ zflag_update_exp (Lval (V (T rd))) ;
        nflag_update_exp rd ]

  let op_orr rd rn op2_stmt =
    [ Set (V (T rd), BinOp(Or, Lval (V (treg rn)), op2_stmt) ) ],
    [ zflag_update_exp (Lval (V (T rd))) ;
      nflag_update_exp rd ]



  module Cfa = Cfa.Make(Domain)
               
  module Imports = Armv7Imports.Make(Domain)(Stubs)

  type state = {
    mutable g             : Cfa.t;        (** current cfa *)
    mutable b             : Cfa.State.t;  (** state predecessor *)
    a                     : Address.t;    (** current address to decode *)
    buf                   : string;       (** buffer to decode *)
    endianness            : Config.endianness_t;      (** whether memory access is little endian *)
    thumbmode             : bool;
    itstate               : int option;
  }

  type isn_or_flag_mark_t =
    | MARK_ISN of Asm.stmt
    | MARK_FLAG of Asm.stmt

  let mark_as_isn l =
    List.map (fun i -> MARK_ISN i) l

  let mark_as_flag l =
    List.map (fun i -> MARK_FLAG i) l

  let mark_couple l =
    let li,lf = l in
    (mark_as_isn li) @ (mark_as_flag lf)

  let remove_marks l =
    List.map (function | MARK_ISN x -> x | MARK_FLAG x -> x) l

  let remove_marks_keep_isn l =
    List.filter (function | MARK_ISN _ -> true | MARK_FLAG _ -> false ) l |> remove_marks

  (* fatal error reporting *)
  let error a msg =
    L.abort (fun p -> p "at %s: %s" (Address.to_string a) msg)

  let error_isn a isn msg =
    L.abort (fun p -> p "at %s: isn=%08x %s" (Address.to_string a) isn msg)

  let notimplemented_arm s isn mnemo = L.abort (fun p -> p "at %s: %s (%08x): ARM instruction not implemented yet"
                                                 (Address.to_string s.a) mnemo isn)

  let notimplemented_thumb s isn mnemo = L.abort (fun p -> p "at %s: %s (%04x): thumb instruction not implemented yet"
                                                 (Address.to_string s.a) mnemo isn)

  let string_to_char_list str =
    let len = String.length str in
    let rec process i =
      if i < len then
        (String.get str i)::(process (i+1))
      else
        []
    in
    List.rev (process 0)

  let build_instruction s str =
    match s.endianness with
    | Config.LITTLE ->
        (Char.code (String.get str 0))
        lor ((Char.code (String.get str 1)) lsl 8)
        lor ((Char.code (String.get str 2)) lsl 16)
        lor ((Char.code (String.get str 3)) lsl 24)
    | Config.BIG ->
        (Char.code (String.get str 3))
        lor ((Char.code (String.get str 2)) lsl 8)
        lor ((Char.code (String.get str 1)) lsl 16)
        lor ((Char.code (String.get str 0)) lsl 24)

  let build_thumb16_instruction s str =
    match s.endianness with
    | Config.LITTLE ->
        (Char.code (String.get str 0))
        lor ((Char.code (String.get str 1)) lsl 8)
    | Config.BIG ->
        (Char.code (String.get str 1))
        lor ((Char.code (String.get str 0)) lsl 8)

  let return (s: state) (instruction: int) (stmts: Asm.stmt list): Cfa.State.t * Data.Address.t =
    let isn_size =
      if s.thumbmode && ((((instruction lsr 11) land 0x3) = 0) ||
                           (((instruction lsr 13) land 0x7) != 0b111))
      then 2 (* Thumb 16 bits instruction *)
      else 4 (* Arm or Thumb 32 bits instruction *) in
    s.b.Cfa.State.stmts <- stmts;
    s.b.Cfa.State.bytes <-
      if isn_size = 2 then
        [ Char.chr (instruction land 0xff) ;
          Char.chr ((instruction lsr 8) land 0xff) ; ]
      else
        [ Char.chr (instruction land 0xff) ;
          Char.chr ((instruction lsr 8) land 0xff) ;
          Char.chr ((instruction lsr 16) land 0xff) ;
          Char.chr ((instruction lsr 24) land 0xff) ];
    (*    s.b.Cfa.State.bytes <- string_to_char_list str; *)
    s.b, Data.Address.add_offset s.a (Z.of_int isn_size)

  let ror32 value n =
    (value lsr n) lor ((value lsl (32-n)) land 0xffffffff)

  let single_data_swap _s instruction =
    let rd = (instruction lsr 12) land 0xf in
    let rn = (instruction lsr 16) land 0xf in
    let rm = instruction land 0xf in
    let work_on_byte = instruction land (1 lsl 22) <> 0 in
    let length,src,mem,dst  = if work_on_byte then
        8, (V (preg rm 0 7)), (M (Lval (V (treg rn)), 8)), (V (preg rd 0 7))
      else
        32, (V (treg rm)), M (Lval (V (treg rn)), 32), (V (treg rd)) in
    let stmts =
      if rm = rd then
        let tmpreg = Register.make (Register.fresh_name ()) length in
        [ Set (V (T tmpreg), Lval mem)  ;
          Set (mem, Lval dst) ;
          Set (dst, Lval (V (T tmpreg))) ;
          Directive (Remove tmpreg) ]
      else
        [ Set (dst, Lval mem)  ;
          Set (mem, Lval src)  ] in
    if work_on_byte then
      stmts @ [ Set( V (preg rd 8 31), const 0 24 ) ]
    else
      stmts


  let mul_mla _s instruction =
    let rd = (instruction lsr 16) land 0xf in
    let rn = (instruction lsr 12) land 0xf in
    let rs = (instruction lsr 8) land 0xf in
    let rm = instruction land 0xf in
    let accumulate = instruction land (1 lsl 21) <> 0 in
    let set_cc = instruction land (1 lsl 20) <> 0 in
    let tmpreg = Register.make (Register.fresh_name ()) 64 in
    let accu_stmt = if accumulate then
        Set (V (treg rd), BinOp(Add, Lval (V (P (tmpreg, 0, 31))),
                               Lval (V (treg rn))))
      else
        Set (V (treg rd), Lval (V (P (tmpreg, 0, 31)))) in
    let cc_stmts = if set_cc then
        [ Set(V (T zflag), TernOp (Cmp(EQ, Lval (V (treg rd)), const 0 32),
                                   const 1 1, const 0 1)) ;
          Set(V (T nflag), Lval (V (preg rd 31 31))) ;
          Directive (Forget (V (T cflag))) ]
      else
        [] in
    let stmt = Set (V (T tmpreg), BinOp(Mul, Lval (V (treg rm)), Lval (V (treg rs)))) in
    stmt :: accu_stmt :: Directive (Remove tmpreg) :: cc_stmts


  let block_data_transfer s instruction =
    if instruction land (1 lsl 22) <> 0 then error s.a "LDM/STM with S=1 not implemented"
    else
      let rn = (instruction lsr 16) land 0xf in
      let ascend = instruction land (1 lsl 23) <> 0 in
      let dir_op = if ascend then Add else Sub in
      let ofs = ref (if instruction land (1 lsl 24) = 0 then 0 else 4) in
      let store = instruction land (1 lsl 20) = 0 in
      let tmpreg = Register.make (Register.fresh_name ()) 32 in
      let tmpreg_v = V(T tmpreg) in
      (* set tmp reg to src register value, so that the src register can be
       * loaded *)
      let stmts = ref [Set(tmpreg_v, Lval (V (treg rn)))] in
      let update_pc = ref false in
      let reg_count = ref 0 in
      for i = 0 to 15 do
        let regtest = if ascend then i else 15-i in
        if (instruction land (1 lsl regtest)) <> 0 then
          begin
            if store then
              stmts := !stmts @
                [ Set( M (BinOp(dir_op, Lval (tmpreg_v), const !ofs 32), 32),
                            Lval (V (treg regtest))) ]
            else
              begin
                stmts := !stmts @
                  [ Set( V (treg regtest),
                         Lval (M (BinOp(dir_op, Lval (tmpreg_v), const !ofs 32), 32))) ];
                if i = 15 then update_pc := true
              end;
            ofs := !ofs+4;
            reg_count := !reg_count + 1
          end
        else ()
      done;
      if instruction land (1 lsl 21) <> 0 then
        stmts := !stmts @
          [ Set (V (treg rn), BinOp(dir_op, Lval (V (treg rn)), const (4*(!reg_count)) 32)) ];
      if !update_pc then
        stmts := !stmts @ [ Jmp (R (Lval (V (T pc)))) ];
      !stmts @ [Directive (Remove tmpreg)]

  let branch s instruction =
    let link = (instruction land (1 lsl 24)) <> 0 in
    let link_stmt,jmp_or_call_stmt =
      if link then
        ([ Set( V (T lr), Const (Word.of_int (Z.add (Address.to_int s.a) (Z.of_int 4)) 32)) ], [ Call (R (Lval (V (T pc)))) ])
      else
        ([ ], [ Jmp (R (Lval (V (T pc)))) ]) in
    let ofs = (instruction land 0xffffff) lsl 2 in
    let ofs32 = if ofs land 0x2000000 <> 0 then ofs lor 0xfc000000 else ofs in (* sign extend 26 bits to 32 bits *)
    link_stmt
    @ [ Set (V (T pc), BinOp(Add, Lval (V (T pc)), const ofs32 32)) ]
    @ jmp_or_call_stmt

  let branch_exchange s instruction =
    let zero = const 0 1 in
    let one = const 1 1 in
    let jreg = Lval(V(treg (instruction land 0xf))) in
    let bit1 = BinOp(And, jreg, one) in
    let target = BinOp(And, jreg, const 0xfffffffe 32) in
    let set_pc_and_t =
      [ Set (V (T tflag), TernOp(Cmp (EQ, bit1, zero), zero, one)) ;
        Set (V (T pc), target ) ] in
    if instruction land (1 lsl 5) = 0 then (* BX *)
      set_pc_and_t @ [ Jmp (R (Lval (V (T pc)))) ]
    else (* BLX *)
      Set( V (T lr), Const (Word.of_int (Z.add (Address.to_int s.a) (Z.of_int 4)) 32)) ::
        set_pc_and_t @ [ Call (R (Lval (V (T pc)))) ]

  let asr_stmt exp shift =
    let sign_mask = const ((-1) lsl (32-shift)) 32 in
    let shifted = BinOp(Shr, exp, const shift 32) in
    let msb = BinOp(Shr, exp, const 31 32) in
    let sign = TernOp( Cmp (EQ, msb, const 0 32), const 0 32, sign_mask) in
    BinOp(Or, shifted, sign)


  let asr_stmt_exp exp shift_exp =
    let sign_mask = BinOp(Shl, const (-1) 32, BinOp(Sub, const 32 32, shift_exp)) in
    let shifted = BinOp(Shr, exp, shift_exp) in
    let msb = BinOp(Shr, exp, const 31 32) in
    let sign = TernOp( Cmp (EQ, msb, const 0 32), const 0 32, sign_mask) in
    BinOp(Or, shifted, sign)

  let ror_stmt exp shift =
    let left = BinOp(Shr, exp, const shift 32) in
    let right = BinOp(Shl, exp, const (32-shift) 32) in
    BinOp(Or, left, right)

  let ror_stmt_exp exp shift_exp =
    let left = BinOp(Shr, exp, shift_exp) in
    let right = BinOp(Shl, exp, BinOp(Sub, const 32 32, shift_exp)) in
    BinOp(Or, left, right)

  let set_cflag_from_bit rm n =
    let nm1 = (n-1) mod 32 in
    Set (V (T cflag), Lval (V (preg rm nm1 nm1)))

  let set_cflag_from_bit_exp rm n_exp =
    let one33 = const 1 33 in
    let rm33 = UnOp(ZeroExt 33, Lval (V (treg rm))) in
    Set ( V (T cflag),
          TernOp (Cmp (EQ,
                       BinOp(And, one33,
                             BinOp(Shr, (* We shift left 1 and right n_exp, but on 33 bits *)
                                   BinOp(Shl, rm33, one33),
                                   UnOp(ZeroExt 33, n_exp))),
                       one33),
                  const 1 1, const 0 1))


  let single_data_transfer s instruction =
    let rd = (instruction lsr 12) land 0xf in
    let rn = (instruction lsr 16) land 0xf in
    let ofs = if instruction land (1 lsl 25) = 0 then (* immediate value *)
        const (instruction land 0xfff) 32
      else
        let rm = instruction land 0xf in
        let shift_op = (instruction lsr 4) land 0xff in
        if shift_op land 1 = 1 then error s.a "Shift register cannot be specified for single data transfer instructions"
        else
          let shift_type = (shift_op lsr 1) land 3 in
          let shift_amount = (shift_op lsr 3) land 0x1f in
          match  shift_type with
          | 0b00 -> (* logical shift left *)
             if shift_amount = 0 then
              Lval (V (treg rm))
            else
              BinOp(Shl, Lval (V (treg rm)), const shift_amount 32)
          | 0b01 -> (* logical shift right *)
             let actual_shift = if shift_amount = 0 then 32 else shift_amount in
             BinOp(Shl, Lval (V (treg rm)), const actual_shift 32)
          | 0b10 -> (* asr *)
             let actual_shift = if shift_amount = 0 then 32 else shift_amount in
             asr_stmt (Lval (V (treg rm))) actual_shift
          | 0b11 -> (* ror *)
             let actual_shift = if shift_amount = 0 then 32 else shift_amount in
             ror_stmt (Lval (V (treg rm))) actual_shift
          | _ -> error s.a "unexpected shift type insingle data xfer"
    in
    let updown = if (instruction land (1 lsl 23)) = 0 then Sub else Add in
    let preindex = (instruction land (1 lsl 24)) <> 0 in
    let writeback = (instruction land (1 lsl 21)) <> 0 in
    let length, dst_or_src = if (instruction land (1 lsl 22)) = 0 then
        32, (V (treg rd))
      else
        8, (V (preg rd 0 7)) in
    let src_or_dst = match preindex,writeback with
      | true, false -> M (BinOp(updown, Lval (V (treg rn)), ofs), length)
      | true, true
      | false, false -> M (Lval (V (treg rn)), length) (* if post-indexing, write back is implied and W=0 *)
      | false, true -> error s.a "Undefined combination (post indexing and W=1)" in
    let stmts,update_pc = if (instruction land (1 lsl 20)) = 0 then (* store *)
        [ Set (src_or_dst, Lval dst_or_src)], false
      else (* load *)
        if length = 32 then
          [ Set (V (treg rd), Lval src_or_dst) ], rd = 15
        else
          [ Set (V (treg rd), UnOp(ZeroExt 32, Lval src_or_dst)) ], rd = 15
    in
    let write_back_stmt = Set (V (treg rn), BinOp(updown, Lval (V (treg rn)), ofs)) in
    let stmts' =
      if preindex then
        if writeback then
          write_back_stmt :: stmts
        else
          stmts
      else
        stmts @ [ write_back_stmt ] in
    if update_pc then
      stmts' @ [ Jmp (R (Lval (V (T pc)))) ]
    else
      stmts'

  let halfword_data_transfer s instruction =
    let rd = (instruction lsr 12) land 0xf in
    let rn = (instruction lsr 16) land 0xf in
    let load = (instruction land (1 lsl 20)) <> 0 in
    let writeback = (instruction land (1 lsl 21)) <> 0 in
    let immediate = (instruction land (1 lsl 22)) <> 0 in
    let updown = if (instruction land (1 lsl 23)) = 0 then Sub else Add in
    let preindex = (instruction land (1 lsl 24)) <> 0 in
    let extend_op = if (instruction land (1 lsl 6)) = 0 then (ZeroExt 32) else (SignExt 32) in
    let length = if (instruction land (1 lsl 5)) <> 0 then 16 else 8 in
    let ofs = if immediate then
        const (((instruction lsr 4) land 0xf0) lor (instruction land 0xf)) 32
      else
        let rm = instruction land 0xf in
        Lval (V (treg rm)) in
    let index_expr = BinOp(updown, Lval (V (treg rn)), ofs) in
    let src_or_dst = match preindex,writeback with
      | true, false -> M (index_expr, length)
      | true, true
      | false, false -> M (Lval (V (treg rn)), length) (* if post-indexing, write back is implied and W=0 *)
      | false, true -> error s.a "Undefined combination (post indexing and W=1)" in
    let stmts, update_pc = if load then
        [ Set (V (treg rd), UnOp(extend_op, Lval src_or_dst)) ], rd = 15
      else
        [ Set (src_or_dst, Lval (V (preg rd 0 (length-1)))) ], false in
    let write_back_stmt = Set (V (treg rn), index_expr) in
    let stmts' =
      if preindex then
        if writeback then
          write_back_stmt :: stmts
        else
          stmts
      else
        stmts @ [ write_back_stmt ] in
    if update_pc then
      stmts' @ [ Jmp (R (Lval (V (T pc)))) ]
    else
      stmts'


  let data_proc_msr rm_stmt =
    let zero32 = const 0 32 in
    [ Set (V (T nflag), TernOp(Cmp (EQ, BinOp(And, rm_stmt, const (1 lsl 31) 32), zero32),
                               const 0 1, const 1 1)) ;
      Set (V (T zflag), TernOp(Cmp (EQ, BinOp(And, rm_stmt, const (1 lsl 30) 32), zero32),
                               const 0 1, const 1 1)) ;
      Set (V (T cflag), TernOp(Cmp (EQ, BinOp(And, rm_stmt, const (1 lsl 29) 32), zero32),
                               const 0 1, const 1 1)) ;
      Set (V (T vflag), TernOp(Cmp (EQ, BinOp(And, rm_stmt, const (1 lsl 28) 32), zero32),
                               const 0 1, const 1 1)) ]

  let data_proc_misc_instructions s instruction =
    let op = (instruction lsr 21) land 3 in
    let _op1 = (instruction lsr 16) land 3 in (* doc says op1 is 4 bits, but only first two are used to decide *)
    let op2 = (instruction lsr 4) land 7 in
    let op_B = (instruction lsr 9) land 1 in
    let rd = (instruction lsr 12) land 0xf in
    let rm = instruction land 0xf in
    let rm_stmt = Lval (V (treg rm)) in
    match op2,op_B,op with
    | 0b000,1,0b00 | 0b000,1,0b10 -> notimplemented_arm s instruction "MRS (Banked register)"
    | 0b000,1,0b01 | 0b000,1,0b11 -> notimplemented_arm s instruction "MSR (Banked register)"
    | 0b000,0,0b00 | 0b000,0,0b10 ->
       if instruction land (1 lsl 22) = 0
       then (* Source PSR: 0=CPSR 1=SPSR *)
         [ Set (V (treg rd),
                BinOp(Or,
                      BinOp(Or,
                            BinOp(Or, BinOp(Shl, UnOp(ZeroExt 32, Lval (V (T nflag))),
                                            const 31 32),
                                  BinOp(Shl, UnOp(ZeroExt 32, Lval (V (T zflag))),
                                        const 30 32)),
                            BinOp(Or, BinOp(Shl, UnOp(ZeroExt 32, Lval (V (T cflag))),
                                            const 29 32),
                                  BinOp(Shl, UnOp(ZeroExt 32, Lval (V (T vflag))),
                                        const 28 32))),
                      const 0b10000 32)) ]
       else error s.a "MRS from SPSR not supported"
    | 0b000,0,0b01 ->
       if instruction land (1 lsl 22) = 0 then (* Source PSR: 0=CPSR 1=SPSR *)
         data_proc_msr rm_stmt
       else error s.a "MSR to SPSR not supported"
    | 0b000,0,0b11 -> notimplemented_arm s instruction "MSR (system level)"
    | 0b001,_,0b01 -> branch_exchange s instruction
    | 0b001,_,0b11 -> notimplemented_arm s instruction "CLZ"
    | 0b010,_,0b01 -> notimplemented_arm s instruction "BXJ"
    | 0b011,_,0b01 -> branch_exchange s instruction
    | 0b101,_,_ -> notimplemented_arm s instruction "Saturating addition and subtraction"
    | 0b110,_,0b11 -> notimplemented_arm s instruction "ERET"
    | 0b111,_,0b01 -> notimplemented_arm s instruction "BKPT"
    | 0b111,_,0b10 -> notimplemented_arm s instruction "HVC"
    | 0b111,_,0b11 -> notimplemented_arm s instruction "SMC (SMI)"
    | _ -> error s.a (Printf.sprintf "unknown data processing miscellaneous instruction opcode (%08x)" instruction)

  let data_proc_second_operand _s instruction =
    let is_imm = instruction land (1 lsl 25) <> 0 in
    if is_imm then
      let shift = (instruction lsr 8) land 0xf in
      let imm = instruction land 0xff in
      const (ror32 imm (2*shift)) 32, [ Set( V (T cflag), const ((imm lsr (2*shift-1)) land 1) 1)]
    else
      let shift_op = (instruction lsr 4) land 0xff in
      let rm = instruction land 0xf in
      let op3, int_shift_count =
        if shift_op land 1 = 0 then
          const (shift_op lsr 3) 32, Some (shift_op lsr 3)
        else
          Lval (V (treg (shift_op lsr 4))), None in
      match (shift_op lsr 1) land 0x3 with
      | 0b00 -> (* lsl *)
         begin
           match  int_shift_count with
           | Some 0 -> Lval (V (treg rm))
           | _ -> BinOp(Shl, Lval (V (treg rm)), op3)
         end,
         begin
           match int_shift_count with
           | Some 0 -> [] (* lsl 0 => preserve carry *)
           | Some n -> [ Set( V (T cflag),  (* shift count is an immediate, we can directly test the bit *)
                              TernOp (Cmp (EQ, BinOp(And, Lval (V (treg rm)), const (1 lsl (32-n)) 32),const 0 32),
                                      const 0 1, const 1 1)) ]
           | None -> [ Set ( V (T cflag),   (* shift count comes from a register. We shift again on 33 bits *)
                            TernOp (Cmp (EQ, BinOp(And,
                                                    BinOp(Shl, UnOp(ZeroExt 33, Lval (V (treg rm))),
                                                          UnOp(ZeroExt 33, op3)),
                                                    const (1 lsl 32) 33), const 0 33),
                                     const 0 1, const 1 1)) ]
         end
      | 0b01 -> (* lsr *)
         begin
           match int_shift_count with
           | Some 0 -> const 0 32 (* 0 actually encodes lsr #32 *)
           | _ -> BinOp(Shr, Lval (V (treg rm)), op3)
         end,
         begin
           match int_shift_count with
           | Some 0 -> [ set_cflag_from_bit rm 32 ]
           | Some n -> [ set_cflag_from_bit rm n ]
           | None -> [ set_cflag_from_bit_exp rm op3 ]
         end
      | 0b10 -> (* asr *)
         begin
           match int_shift_count with
           | Some 0 -> asr_stmt (Lval (V (treg rm))) 32 (* 0 actually encodes lsr #32 *)
           | Some x -> asr_stmt (Lval (V (treg rm))) x
           | None -> asr_stmt_exp (Lval (V (treg rm))) op3
         end,
         begin
           match int_shift_count with
           | Some 0 -> [ set_cflag_from_bit rm 32 ]
           | Some n -> [ set_cflag_from_bit rm n ]
           | None -> [ set_cflag_from_bit_exp rm op3 ]
         end
      | 0b11 -> (* ror *)
         begin
           match int_shift_count with
           | Some 0 -> (* RRX operation *)
              let shifted = BinOp(Shr, Lval (V (treg rm)), const 1 32) in
              let carry_in = TernOp( Cmp (EQ, Lval (V (T cflag)), const 0 1), const 0 32, const 0x80000000 32) in
              BinOp(Or, shifted, carry_in)
           | Some x -> ror_stmt (Lval (V (treg rm))) x
           | None -> ror_stmt_exp (Lval (V (treg rm))) op3
         end,
         begin
           match int_shift_count with
           | Some 0 -> (* RRX operation *)
              let carry_out = TernOp( Cmp (EQ, BinOp(And, Lval (V (treg rm)), const 1 32), const 0 32), const 0 1, const 1 1) in
              [ Set ( V (T cflag), carry_out) ]
           | Some n -> [ set_cflag_from_bit rm n ]
           | None -> [ set_cflag_from_bit_exp rm op3 ]
         end
      | st -> L.abort (fun p -> p "unexpected shift type %x" st)

  let data_proc_msr_immediate_and_hints s instruction =
    let op = (instruction lsr 22) land 0x1 in
    let op1 = (instruction lsr 16) land 0xf in
    let op2 = instruction land 0xff in
    match op,op1,op2 with
    | 0,0b0000,0b00000000 -> L.analysis (fun p -> p "NOP: No Operation hint") ; []
    | 0,0b0000,0b00000001 -> L.analysis (fun p -> p "YIELD: Yield hint") ; []
    | 0,0b0000,0b00000010 -> L.analysis (fun p -> p "WFE: Wait For Event hint") ; []
    | 0,0b0000,0b00000011 -> L.analysis (fun p -> p "WFI: Wait For Interrupt hint") ; []
    | 0,0b0000,0b00000100 -> L.analysis (fun p -> p "SEV: Send Event hint") ; []
    | 0,0b0000,_ when op2 land 0xf0 == 0xf0  -> L.analysis (fun p -> p "DBG %02x:Debug hint" (op2 land 0xf)) ; []
    | _ when (op == 1) || (op1=0b0100) || (op1 land 0b1011 == 0b1000) || (op1 land 3 == 1) || (op1 land 2 == 2) ->
       let rm_stmt,_ = data_proc_second_operand s instruction in
       data_proc_msr rm_stmt
    | _ -> error s.a (Printf.sprintf "unknown MSR immediate or hint instruction opcode (%08x)" instruction)


  let data_proc_synchronization_primitives s instruction =
    let op = (instruction lsr 20) land 0xf in
    match op with
    | 0b0000 | 0b0100 -> single_data_swap s instruction
    | 0b1000 -> notimplemented_arm s instruction "STREX"
    | 0b1001 -> notimplemented_arm s instruction "LDREX"
    | 0b1010 -> notimplemented_arm s instruction "STREXD"
    | 0b1011 -> notimplemented_arm s instruction "LDREXD"
    | 0b1100 -> notimplemented_arm s instruction "STREXB"
    | 0b1101 -> notimplemented_arm s instruction "LDREXB"
    | 0b1110 -> notimplemented_arm s instruction "STREXH"
    | 0b1111 -> notimplemented_arm s instruction "LDREXH"
    | _ -> error s.a (Printf.sprintf "unknown synchronization primitive instruction opcode (%08x)" instruction)


  let data_proc s instruction =
    let op_i = (instruction lsr 25) land 1 in
    let op1 = (instruction lsr 20) land 0x1f in
    let op2 = (instruction lsr 4) land 0xf in
    let rd = (instruction lsr 12) land 0xf in
    match op_i,op1,op2 with
    | 0,_,0b1001 when op1 lsr 4 == 0 -> mul_mla s instruction
    | 0,_,0b1001 when op1 lsr 4 <> 0 -> data_proc_synchronization_primitives s instruction
    | 0,_,0b1011 | 0,_,0b1101 | 0,_,0b1111  -> halfword_data_transfer s instruction
    | 0,_,_ when (op1 land 0b11001 == 0b10000) && (op2 land 0b1000 == 0b0000) -> data_proc_misc_instructions s instruction
    | 0,_,_ when (op1 land 0b11001 == 0b10000) && (op2 land 0b1001 == 0b1000) -> notimplemented_arm s instruction "Halfword multiply and multiply accumulate"
    | 1,0b10000,_ -> if rd == 15
                     then L.abort (fun p -> p "at %s: MOVW to PC: UNPREDICTABLE"
                                              (Address.to_string s.a))
                     else [ Set (V (treg rd),
                                 Const (Word.of_int (Z.of_int (
                                                         ((instruction lsr 4) land 0xf000)
                                                         lor (instruction land 0xfff)
                                          )) 32))]
    | 1,0b10100,_ -> [ Set (V (preg rd 16 31),
                            Const (Word.of_int (Z.of_int (
                                          ((instruction lsr 4) land 0xf000)
                                          lor (instruction land 0xfff)
                         )) 16))]
    | 1,0b10010,_ | 1,0b10110,_ -> data_proc_msr_immediate_and_hints s instruction
    | _ ->
       let rn = (instruction lsr 16) land 0xf in
       let set_cond_codes = instruction land (1 lsl 20) <> 0 in
       let op2_stmt, op2_carry_stmt = data_proc_second_operand s instruction in
       let stmts, flags_stmts, update_pc =
         match op1 with
         | 0b00000 | 0b00001 -> (* AND - Rd:= Op1 AND Op2 *)
            let opstmts,flagstmts = op_and (reg rd) rn op2_stmt in
            opstmts, flagstmts @ op2_carry_stmt, rd = 15
         | 0b00010 | 0b00011 -> (* EOR - Rd:= Op1 EOR Op2 *)
            let opstmts,flagstmts = op_eor (reg rd) rn op2_stmt in
            opstmts, flagstmts @ op2_carry_stmt, rd = 15
         | 0b00100 | 0b00101 -> (* SUB - Rd:= Op1 + not Op2 + 1 *)
            let opstmts,flagstmts = op_sub (reg rd) rn op2_stmt in
            opstmts, flagstmts, rd = 15
         | 0b00110 | 0b00111 -> (* RSB - Rd:= Op2 - Op1 *)
            let opstmts,flagstmts = op_rsb (reg rd) rn op2_stmt in
            opstmts, flagstmts, rd = 15
         | 0b01000 | 0b01001 -> (* ADD - Rd:= Op1 + Op2 *)
            let opstmts,flagstmts = op_add (reg rd) rn op2_stmt in
            opstmts, flagstmts, rd = 15
         | 0b01010 | 0b01011 -> (* ADC - Rd:= Op1 + Op2 + C *)
            [ Set (V (treg rd), BinOp(Add, UnOp(ZeroExt 32, Lval (V (T cflag))),
                                      BinOp(Add, Lval (V (treg rn)), op2_stmt) )) ],
            [ zflag_update_exp (Lval (V (treg rd))) ;
              nflag_update_exp (reg rd) ;
              vflag_update_exp (Lval (V (treg rn))) op2_stmt (Lval (V (treg rd))) ; ]
            @ cflag_update_stmts_with_carry Add (Lval (V (treg rn))) op2_stmt,
            rd = 15
         | 0b01100 | 0b01101 -> (* SBC - Rd:= Op1 - Op2 + C - 1 *)
            [ Set (V (treg rd), BinOp(Sub,
                                      BinOp(Add, BinOp(Sub, Lval (V (treg rn)), op2_stmt),
                                            UnOp(ZeroExt 32, Lval (V (T cflag))) ),
                                      const 1 32)) ],
            [ zflag_update_exp (Lval (V (treg rd))) ;
              nflag_update_exp (reg rd) ; ]
            @ set_cflag_vflag_after_add_with_carry (Lval (V (treg rn))) (UnOp(Not, op2_stmt)) (Lval (V (T cflag))),
            rd = 15
         | 0b01110 | 0b01111 -> (* RSC - Rd:= Op2 - Op1 + C - 1 *)
            [ Set (V (treg rd), BinOp(Sub,
                                      BinOp(Add, BinOp(Sub, op2_stmt, Lval (V (treg rn))),
                                            UnOp(ZeroExt 32, Lval (V (T cflag))) ),
                                      const 1 32)) ],
            [ zflag_update_exp (Lval (V (treg rd))) ;
              nflag_update_exp (reg rd) ; ]
            @ set_cflag_vflag_after_add_with_carry op2_stmt (UnOp(Not, (Lval (V (treg rn))))) (Lval (V (T cflag))),
            rd = 15
         | 0b11000 | 0b11001 -> (* ORR - Rd:= Op1 OR Op2 *)
            let opstmts,flagstmts = op_orr (reg rd) rn op2_stmt in
            opstmts, flagstmts @ op2_carry_stmt, rd = 15
         | 0b11010 | 0b11011 -> (* MOV - Rd:= Op2 *)
            [ Set (V (treg rd), op2_stmt) ],
            [ zflag_update_exp (Lval (V (treg rd))) ;
              nflag_update_exp (reg rd) ]
            @ op2_carry_stmt,
            rd = 15
         | 0b11100 | 0b11101 -> (* BIC - Rd:= Op1 AND NOT Op2 *)
            let opstmts,flagstmts = op_bic (reg rd) rn op2_stmt in
            opstmts, flagstmts @ op2_carry_stmt, rd = 15
         | 0b11110 | 0b11111 -> (* MVN - Rd:= NOT Op2 *)
            let opstmts,flagstmts = op_mvn (reg rd) op2_stmt in
            opstmts, flagstmts @ op2_carry_stmt, rd = 15
         | 0b10001 -> (* TST - set condition codes on Op1 AND Op2 *)
            let tmpreg = Register.make (Register.fresh_name ()) 32 in
            let opstmts,flagstmts = op_and tmpreg rn op2_stmt in
            [], opstmts @ flagstmts @ [ Directive (Remove tmpreg) ] @ op2_carry_stmt, false
         | 0b10011 -> (* TEQ - set condition codes on Op1 EOR Op2 *)
            let tmpreg = Register.make (Register.fresh_name ()) 32 in
            [],
            [ Set(V (T tmpreg), BinOp(Xor, Lval (V (treg rn)), op2_stmt)) ;
              zflag_update_exp (Lval (V (T tmpreg))) ;
              nflag_update_exp tmpreg ;
              Directive (Remove tmpreg) ]
            @ op2_carry_stmt,
            false
         | 0b10101 -> (* CMP - set condition codes on Op1 - Op2 *)
            let tmpreg = Register.make (Register.fresh_name ()) 33 in
            [],
            [
              Set( V (T tmpreg), BinOp(Add, to33bits (Lval (V (treg rn))),
                                       to33bits(BinOp(Add, UnOp(Not, op2_stmt),
                                                      const 1 32)))) ;
              zflag_update_exp (Lval (V (P (tmpreg, 0, 31)))) ;
              nflag_update_exp tmpreg ;
              vflag_update_exp  (Lval (V (treg rn))) (UnOp(Not, op2_stmt)) (Lval (V (P (tmpreg, 0, 31)))) ;
              Set (V (T cflag), Lval (V (P (tmpreg, 32, 32)))) ;
              Directive (Remove tmpreg) ],
            false
         | 0b10111 -> (* CMN - set condition codes on Op1 + Op2 *)
            let tmpreg = Register.make (Register.fresh_name ()) 33 in
            [],
            [ Set( V (T tmpreg), BinOp(Add, to33bits (Lval (V (treg rn))),
                                       to33bits op2_stmt) ) ;
              Set (V (T cflag), Lval (V (P (tmpreg, 32, 32)))) ;
              zflag_update_exp (Lval (V (P (tmpreg, 0, 31)))) ;
              nflag_update_exp tmpreg ;
              vflag_update_exp (Lval (V (treg rn))) op2_stmt (Lval (V (P (tmpreg, 0, 31)))) ;
              Directive (Remove tmpreg) ],
            false
         | _ -> L.abort (fun p -> p "unexpected opcode %x" op1) in
       let stmt_cc =
         if set_cond_codes
         then
           stmts @ flags_stmts
         else
           stmts in
       if update_pc then
         stmt_cc @ [ Jmp (R (Lval (V (T pc)))) ]
       else
         stmt_cc

  let decode_packing_unpacking_saturation_reversal s instruction =
    let add_if_needed rn expr =
      if rn == 0xf
      then expr
      else BinOp (Add, Lval (V (treg rn)), expr) in
    let op1 = (instruction lsr 20) land 0x7 in
    let op2 = (instruction lsr 5) land 0x7 in
    let rn = (instruction lsr 16) land 0xf in
    let rd = (instruction lsr 12) land 0xf in
    let rm = instruction land 0xf in
    match op1,op2 with
    | 0b000,0b000 | 0b000,0b010 | 0b000,0b100 | 0b000,0b110 -> (* PKH *)
       let tb = (instruction lsr 6) land 1 in
       let imm5 = (instruction lsr 7) land 0x1f in
       let op2 =
         if tb == 0 then
           begin
             if imm5 <= 16
             then Lval (V (preg rm (16-imm5) (31-imm5)))
             else BinOp (Shl, Lval (V (preg rm 0 15)), const (imm5-16) 16)
           end
         else
           begin
             if imm5 <= 16
             then Lval (V (preg rm (imm5) (imm5+15)))
             else
               let sign_mask = const ((-1) lsl (32-imm5)) 16 in
               let shifted = BinOp (Shr, Lval (V (preg rm 16 31)), const (imm5-16) 16) in
               let msb = Lval (V (preg rm 31 31)) in
               let sign = TernOp( Cmp (EQ, msb, const 0 1), const 0 16, sign_mask) in
               BinOp(Or, shifted, sign)
           end in
       if tb == 0
       then (* PKHBT *)
         [ Set (V (preg rd 0 15), Lval (V (preg rn 0 15))) ;
           Set (V (preg rd 16 31), op2)  ]
       else (* PKHTB *)
         [ Set (V (preg rd 0 15), op2)  ;
           Set (V (preg rd 16 31), Lval (V (preg rn 16 31))) ]
    | 0b000,0b011 -> (* SXTAB16 / SXTB16 *)
       let rotate = (instruction lsr 7) land 0x18 in
       let add_if_needed_16 rn a b expr =
         if rn == 0xf
         then expr
         else BinOp (Add, Lval (V (preg rn a b)), expr) in
       [ Set (V (treg rd),
              (BinOp (Or,
                      UnOp(ZeroExt 32,
                           add_if_needed_16 rn 0 15
                             (UnOp (SignExt 16, Lval (V (preg rm rotate (rotate+7)))))),
                      BinOp(Shl,
                            UnOp(ZeroExt 32,
                                 add_if_needed_16 rn 16 31
                                   (UnOp (SignExt 16, Lval (V (preg rm ((rotate+16) mod 32) ((rotate+23) mod 32)))))),
                            const 16 32))))]
    | 0b000,0b101 -> notimplemented_arm s instruction "SEL"
    | 0b010,0b000 | 0b010,0b010 | 0b010,0b100 | 0b010,0b110
      | 0b011,0b000 | 0b011,0b010 | 0b011,0b100 | 0b011,0b110 -> notimplemented_arm s instruction "SSAT"
    | 0b010,0b001 -> notimplemented_arm s instruction "SSAT16"
    | 0b010,0b011 -> (* SXTB / SXTAB *)
       let rotate = (instruction lsr 7) land 0x18 in
       [ Set (V (treg rd),
              add_if_needed rn (UnOp (SignExt 32,
                                      Lval (V (preg rm rotate (rotate+7)))))) ]
    | 0b011,0b001 -> notimplemented_arm s instruction "REV"
    | 0b011,0b011 -> (* SXTAH / SXTH *)
       let rotate = (instruction lsr 7) land 0x18 in
       let rotated =
         if rotate < 24 then
           Lval (V (preg rm rotate (rotate+15)))
         else
           BinOp (Or,
                  UnOp (ZeroExt 16, Lval (V (preg rm rotate (rotate+7)))),
                  BinOp (Shl, UnOp (ZeroExt 16, Lval (V (preg rm 0 7))) , const 8 16))
       in [ Set (V (treg rd),
                 add_if_needed rn (UnOp (SignExt 32, rotated ))) ]
    | 0b011,0b101 -> notimplemented_arm s instruction "REV16"
    | 0b100,0b011 -> (* UXTAB16 / UXTB16 *)
       let rotate = (instruction lsr 7) land 0x18 in
       [ Set (V (treg rd),
              add_if_needed rn
                (BinOp (Or,
                        UnOp (ZeroExt 32, Lval (V (preg rm rotate (rotate+7)))),
                        BinOp(Shl,
                              UnOp (ZeroExt 32, Lval (V (preg rm ((rotate+16) mod 32) ((rotate+23) mod 32)))),
                              const 16 32))))]
    | 0b110,0b000 | 0b110,0b010 | 0b110,0b100 | 0b110,0b110
      | 0b111,0b000 | 0b111,0b010 | 0b111,0b100 | 0b111,0b110 -> notimplemented_arm s instruction "USAT"
    | 0b110,0b001 -> notimplemented_arm s instruction "USAT16"
    | 0b110,0b011 -> (* UXTB / UXTAB *)
       let rotate = (instruction lsr 7) land 0x18 in
       [ Set (V (treg rd),
              add_if_needed rn (UnOp (ZeroExt 32,
                                      Lval (V (preg rm rotate (rotate+7)))))) ]
    | 0b111,0b001 -> notimplemented_arm s instruction "RBIT"
    | 0b111,0b011 -> (* UXTAH / UXTH *)
       let rotate = (instruction lsr 7) land 0x18 in
       let rotated =
         if rotate < 24 then
           Lval (V (preg rm rotate (rotate+15)))
         else
           BinOp (Or,
                  UnOp (ZeroExt 16, Lval (V (preg rm rotate (rotate+7)))),
                  BinOp (Shl, UnOp (ZeroExt 16, Lval (V (preg rm 0 7))) , const 8 16))
       in [ Set (V (treg rd),
                 add_if_needed rn (UnOp (ZeroExt 32, rotated ))) ]
    | 0b111,0b101 -> notimplemented_arm s instruction "REVSH"
    | _ -> error s.a (Printf.sprintf "unknown packing/unpacking/saturation/reversal instruction opcode (%08x)" instruction)


  let decode_media_instructions s instruction =
    let op1 = (instruction lsr 20) land 0x1f in
    let op2 = (instruction lsr 5) land 7 in
    match op1,op2 with
    | 0b00000,_ | 0b00001,_ | 0b00010,_ | 0b00011,_ -> notimplemented_arm s instruction "Parallel addition and subtraction, signed"
    | 0b00100,_ | 0b00101,_ | 0b00110,_ | 0b00111,_ -> notimplemented_arm s instruction "Parallel addition and subtraction, unsigned"
    | 0b01000,_ | 0b01001,_ | 0b01010,_ | 0b01011,_ | 0b01100,_ | 0b01101,_ | 0b01110,_ | 0b01111,_ ->
       decode_packing_unpacking_saturation_reversal s instruction
    | 0b10000,_ | 0b10001,_ | 0b10010,_ | 0b10011,_ | 0b10100,_ | 0b10101,_ | 0b10110,_ | 0b10111,_  -> notimplemented_arm s instruction "Signed multiply, signed and unsigned divide"
    | 0b11000,0b000 -> notimplemented_arm s instruction "USAD8 / ISADA8"
    | 0b11010,0b010 | 0b11011,0b010| 0b11010,0b110| 0b11011,0b110 -> notimplemented_arm s instruction "SBFX"
    | 0b11100,0b000 | 0b11101,0b000| 0b11100,0b100| 0b11101,0b100 -> notimplemented_arm s instruction "BFC / BFI"
    | 0b11110,0b010 | 0b11111,0b010| 0b11110,0b110| 0b11111,0b110 ->
       let rd = (instruction lsr 12) land 0xf in
       let rn = instruction land 0xf in
       let lsb = (instruction lsr 7) land 0x1f in
       let widthm1 = (instruction lsr 16) land 0x1f in
       [ Set ( V (treg rd), UnOp(ZeroExt 32, Lval (V (preg rn lsb (lsb+widthm1))))) ]
    | 0b11111,0b111 when instruction lsr 28 == 0xe -> error s.a "UDF: Permanently UNDEFINED opcode. Stopping analysis."
    | _ -> error s.a (Printf.sprintf "unknown media instruction opcode (%08x)" instruction)

  let wrap_cc cc stmts =
    match cc with
    | 0xf -> []    (* never *)
    | 0xe -> stmts (* always *)
    | cc -> [ If (asm_cond cc, stmts, []) ]


  let decode_arm (s: state): Cfa.State.t * Data.Address.t =
    let str = String.sub s.buf 0 4 in
    let instruction = build_instruction s str in
    let stmts = match (instruction lsr 25) land 0x7 with
    | 0b000 | 0b001 -> data_proc s instruction
    | 0b010 -> single_data_transfer s instruction
    | 0b011 ->
           if instruction land (1 lsl 4) = 0
           then single_data_transfer s instruction
           else decode_media_instructions s instruction
    | 0b100 -> block_data_transfer s instruction (* block data transfer *)
    | 0b101 -> branch s instruction
    | 0b110 -> error s.a (Printf.sprintf "Comprocessor data transfer not implemented (isn=%08x)" instruction)
    | 0b111 when instruction land (1 lsl 24) = 0 -> error s.a (Printf.sprintf "coprocessor operation or register transfer (isn=%08x)" instruction)
    | 0b111 when instruction land (1 lsl 24) <> 0 -> error s.a (Printf.sprintf "software interrupt not implemented (swi=%08x)" instruction)
    | _ -> error s.a (Printf.sprintf "Unknown opcode 0x%x" instruction) in
    let cc = (instruction lsr 28) land 0xf in
    let stmts_cc = wrap_cc cc stmts in
    let current_pc = Const (Word.of_int (Z.add (Address.to_int s.a) (Z.of_int 8)) 32) in (* pc is 8 bytes ahead because of pre-fetching. *)
    (* XXX: 12 bytes if a register is used to specify a shift amount *)
    return s instruction (Set( V (T pc), current_pc) :: stmts_cc)


(*  _____ _              _     *)
(* |_   _| |_ _  _ _ __ | |__  *)
(*   | | | ' \ || | '  \| '_ \ *)
(*   |_| |_||_\_,_|_|_|_|_.__/ *)
(*                             *)

  let thumb_push _s isn =
    let reglist = ((isn lsl 6) land 0x4000) lor (isn land 0xff) in (* reglist = 0:bit8:000000:bit7-0 bit8=r14=lr*)
    let stmts = ref [] in
    let bitcount = ref 0 in
    for i = 14 downto 0 do
      if (reglist lsr i) land 1 = 1 then
        begin
          bitcount := !bitcount+4;
          let stmt = Set (M (BinOp(Sub, Lval (V (T sp)), const !bitcount 32), 32),
                          Lval (V (treg i))) in
          stmts := stmt :: (!stmts)
        end
    done;
    (!stmts) @ [ Set (V (T sp), BinOp(Sub, Lval (V (T sp)), const !bitcount 32)) ] |> mark_as_isn

  let thumb_pop _s isn =
    let reglist = ((isn lsl 7) land 0x8000) lor (isn land 0xff) in (* reglist = bit8:0000000:bit7-0 bit8=r15=pc *)
    let stmts = ref [] in
    let bitcount = ref 0 in
    for i = 0 to 15 do
      if (reglist lsr i) land 1 = 1 then
        begin
          let stmt = Set (V (treg i),
                          Lval (M (BinOp(Add, Lval (V (T sp)), const !bitcount 32), 32))) in
          bitcount := !bitcount+4;
          stmts := stmt :: (!stmts)
        end
    done;
    let jmppc =
      if reglist lsr 15 = 1 then
        [ Set (V (T tflag), TernOp (Cmp (EQ, BinOp(And, Lval (V (T pc)), const 3 32), const 0 32),
                                    const 0 1,    (* back to ARM mode *)
                                    const 1 1)) ; (* stay in thumb mode *)
          If (Cmp (EQ, Lval (V (T tflag)), const 1 1),
              [ Set (V (P (pc, 0, 0)), const 0 1) ],
              [ Set (V (P (pc, 0, 1)), const 0 2) ]) ;
          Jmp (R (Lval (V (T pc)))) ; ]
      else [] in

    (!stmts) @ [ Set (V (T sp), BinOp(Add, Lval (V (T sp)), const !bitcount 32)) ] @ jmppc|> mark_as_isn

  let thumb_it _s isn =
    let new_itstate = isn land 0xff in
    [ Set( V (T itstate), const new_itstate 8) ] |> mark_as_isn

  let decode_thumb_it_hints s isn =
    if isn land 0xf != 0 then (* If-Then*)
      thumb_it s isn
    else
      match (isn lsr 4) land 0x7 with
      | 0b000 -> L.analysis (fun p -> p "NOP: No Operation hint"); []
      | 0b001 -> L.analysis (fun p -> p "YIELD: Yield hint") ; []
      | 0b010 -> L.analysis (fun p -> p "WFE: Wait For Event hint") ; []
      | 0b011 -> L.analysis (fun p -> p "WFI: Wait For Interrupt hint") ; []
      | 0b100 -> L.analysis (fun p -> p "SEV: Send Event hint") ; []
      | _ -> L.abort (fun p -> p "Unkown hint instruction encoding %04x" isn)

  let decode_thumb_uxtb isn =
    let rm = (isn lsr 3) land 0x07 in
    let rd = isn land 0x07 in
    [Set (V (treg rm), UnOp(ZeroExt 32, Lval (V (preg rd 0 7)))) ], []
    
  let decode_thumb_misc s isn =
    match (isn lsr 6) land 0x3f with
    | 0b011001 ->
       if (isn lsr 5) land 1 = 0 then (* Set Endianness SETEND *)
         notimplemented_thumb s isn "SETEND"
       else (* Change Processor State CPS *)
         notimplemented_thumb s isn "CPS"
      
    | 0b000000 | 0b000001 -> (* Add Immediate to SP ADD (SP plus immediate) *)
       let imm7 = isn land 0x7f in
       op_add sp 13 (const (imm7 lsl 2) 32) |> mark_couple
       
    | 0b000010 | 0b000011 -> (* Subtract Immediate from SP SUB (SP minus immediate) *)
       let imm7 = isn land 0x7f in
       op_sub sp 13 (const (imm7 lsl 2) 32) |> mark_couple
       
    | 0b000100 | 0b000101 | 0b000110 | 0b000111 -> (* Compare and Branch on Zero CBNZ, CBZ *)
       notimplemented_thumb s isn "CBZ/CBNZ (0)"

    | 0b001000 -> (* Signed Extend Halfword SXTH *)
       notimplemented_thumb s isn "SXTH"

    | 0b001001 -> (* Signed Extend Byte SXTB *)
       notimplemented_thumb s isn "SXTB"

    | 0b001010 -> (* Unsigned Extend Halfword UXTH *)
       notimplemented_thumb s isn "UXTH"

    | 0b001011 -> (* Unsigned Extend Byte UXTB *)
       decode_thumb_uxtb isn |> mark_couple
      
    | 0b001100 | 0b001101 | 0b001110 | 0b001111 -> (* Compare and Branch on Zero CBNZ, CBZ *)
       notimplemented_thumb s isn "CBNZ/CBZ (1)"
    | 0b010000 | 0b010001 | 0b010010 | 0b010011 | 0b010100 | 0b010101 | 0b010110 | 0b010111 -> (* Push Multiple Registers PUSH *)
       thumb_push s isn
    | 0b100100 | 0b100101 | 0b100110 | 0b100111 -> (* Compare and Branch on Nonzero CBNZ, CBZ *)
       notimplemented_thumb s isn "CBNZ/CBZ (2)"
    | 0b101000 -> (* Byte-Reverse Word REV *)
       notimplemented_thumb s isn "REV"
    | 0b101001 -> (* Byte-Reverse Packed Halfword REV16 *)
       notimplemented_thumb s isn "REV16"
    | 0b101011 -> (* Byte-Reverse Signed Halfword REVSH *)
       notimplemented_thumb s isn "REVSH"
    | 0b101100 | 0b101101 | 0b101110 | 0b101111 -> (* Compare and Branch on Nonzero CBNZ, CBZ *)
       notimplemented_thumb s isn "CBNZ/CBZ (3)"
    | 0b110000 | 0b110001 | 0b110010 | 0b110011 | 0b110100 | 0b110101 | 0b110110 | 0b110111 -> (* Pop Multiple Registers POP *)
       thumb_pop s isn
    | 0b111000 | 0b111001 | 0b111010 | 0b111011 -> (* Breakpoint BKPT *)
       notimplemented_thumb s isn "BKPT"
    | 0b111100 | 0b111101 | 0b111110 | 0b111111 -> (* If-Then and hints *)
       decode_thumb_it_hints s isn
    | _ ->  L.abort (fun p -> p "Unknown thumb misc encoding %04x" isn)


  let thumb_mov_imm _s isn =
    let regnum = (isn lsr 8) land 7 in
    let imm = isn land 0xff in
    [ MARK_ISN (Set (V (treg regnum), const imm 32)) ;
      MARK_FLAG (Set (V (T zflag), const (if imm = 0 then 1 else 0) 1)) ;
      MARK_FLAG (Set (V (T nflag), const (imm lsr 31) 1)) ; ]

  let thumb_cmp_imm _s isn =
    let rn = (isn lsr 8) land 7 in
    let imm = isn land 0xff in
    let tmpreg = Register.make (Register.fresh_name ()) 32 in
    let opstmts,flagstmts = op_sub tmpreg rn (const imm 32) in
    mark_as_isn (opstmts @ flagstmts @ [ Directive (Remove tmpreg) ])


  let decode_thumb_shift_add_sub_mov_cmp s isn =
    match (isn lsr 11) land 7 with
    | 0b011 ->
       let rm_or_imm3 = (isn lsr 6) land 7 in
       let rn = (isn lsr 3) land 7 in
       let rd = isn land 7 in
       begin
         match (isn lsr 9) land 3 with
         | 0b00 -> (* Add register ADD (register) *)
            op_add (reg rd) rn (Lval (V (treg rm_or_imm3)))
         | 0b01 -> (* Subtract register SUB (register) *)
            
            op_sub (reg rd) rn (Lval (V (treg rm_or_imm3)))
         | 0b10 -> (* Add 3-bit immediate ADD (immediate, Thumb) *)
            op_add (reg rd) rn (const rm_or_imm3 32)
           
         | 0b11 -> (* Subtract 3-bit immediate SUB (immediate, Thumb) *)
            op_sub (reg rd) rn (const rm_or_imm3 32)

         | _ -> L.abort (fun p -> p "Unknown encoding %04x" isn)
       end |> mark_couple
       
    | 0b000 -> (* Logical Shift Left LSL (immediate) *)
       let shift = (isn lsr 6) land 0x1f in
       let rm = (isn lsr 3) land 7 in
       let rd = isn land 7 in
       let flags_stmts = mark_as_flag [
           nflag_update_exp (reg rd) ;
           zflag_update_exp (Lval ( V (treg rd))) ; ] in
       if shift > 0 then
         MARK_FLAG (Set (V (T cflag), Lval (V (preg rm (32-shift) (32-shift))))) ::
           MARK_ISN  (Set (V (treg rd), BinOp (Shl, Lval (V (treg rm)), const shift 32))) ::
             flags_stmts
       else
         MARK_ISN (Set (V (treg rd), Lval (V (treg rm)))) :: flags_stmts
       
    | 0b001 -> (* Logical Shift Right LSR (immediate) *)
       let imm5 = (isn lsr 6) land 0x1f in
       let shift = if imm5 = 0 then 32 else imm5 in
       let rm = (isn lsr 3) land 7 in
       let rd = isn land 7 in
       [ MARK_FLAG (Set (V (T cflag), Lval (V (preg rm (shift-1) (shift-1))))) ;
         MARK_ISN  (Set (V (treg rd), BinOp (Shr, Lval (V (treg rm)), const shift 32))) ;
         MARK_FLAG (nflag_update_exp (reg rd)) ;
         MARK_FLAG (zflag_update_exp (Lval ( V (treg rd)))) ; ]

    | 0b010 -> (* Arithmetic Shift Right ASR (immediate) *)
       notimplemented_thumb s isn "ASR (imm)"

    | 0b100 -> (* Move MOV (immediate) *)
       thumb_mov_imm s isn

    | 0b101 -> (* Compare CMP (immediate) *)
       thumb_cmp_imm s isn

    | 0b110 -> (* Add 8-bit immediate ADD (immediate, Thumb) *)
       let rdn = (isn lsr 8) land 7 in
       let imm8 = isn land 0xff in
       op_add (reg rdn) rdn (const imm8 32) |> mark_couple
       
    | 0b111 -> (* Subtract 8-bit immediate SUB (immediate, Thumb) *)
       let rdn = (isn lsr 8) land 7 in
       let imm8 = isn land 0xff in
       op_sub (reg rdn) rdn (const imm8 32) |> mark_couple
    | _ -> L.abort (fun p -> p "Unknown encoding %04x" isn)


  let thumb_cond_branching _s isn =
    let cc = (isn lsr 8) land 0xf in
    let imm8 = isn land 0xff in
    let ofs = sconst (imm8 lsl 1) 9 32 in
    let branching = [
        Set (V (T pc), BinOp( Add, Lval (V (T pc)), ofs)) ;
        Jmp (R (Lval (V (T pc)))) ;
      ] in
    [ If (asm_cond cc, branching, [] ) ] |> mark_as_isn

  let thumb_branching _s isn =
    let ofs = (isn land 0x7ff) lsl 1 in
    [ Set (V (T pc),
           BinOp(Add, Lval (V (T pc)), sconst ofs 12 32)) ;
      Jmp (R (Lval (V (T pc)))) ] |> mark_as_isn

  let decode_thumb_branching_svcall s isn =
    match isn lsr 8 land 0xf with
    | 0b1110 -> (* Permanently UNDEFINED *)
       L.abort (fun p -> p "Thumb16 instruction %04x permanently undefined" isn)
    | 0b1111 -> (* Supervisor Call *)
       notimplemented_thumb s isn "SVC"
    | _ -> (* Conditional branch *)
       thumb_cond_branching s isn

  let thumb_mov_high_reg _s isn =
    let rm = (isn lsr 3) land 0xf in
    let rd = ((isn lsr 4) land 8) lor (isn land 7) in
    let jump_pc = if rd = 15 then [ Jmp (R (Lval (V (T pc)))) ] else [] in
    [ Set (V (treg rd), Lval (V (treg rm))) ] @ jump_pc |> mark_as_isn

  let thumb_bx _s isn =
    let rm = (isn lsr 3) land 0xf in
    [ Set (V (T tflag), Lval (V (preg rm 0 0))) ;
      Set (V (T pc), BinOp (And, Lval (V (treg rm)), const 0xfffffffe 32)) ;
      Jmp (R (Lval (V (T pc)))) ] |> mark_as_isn

  let decode_thumb32_mov s isn =
    let str2 = String.sub s.buf 2 2 in
    let isn2 = build_thumb16_instruction s str2 in
    L.debug (fun p->p "decode_thumb_mov_low 0x%x 0x%x" isn isn2);
    let rm = isn2 land 0xF in
    let rd = (isn2 lsr 8) land 0xF in
    let jump_pc = if rd = 15 then [ Jmp (R (Lval (V (T pc)))) ] else [] in
    [ Set (V (treg rd), Lval (V (treg rm))) ] @ jump_pc |> mark_as_isn

  let decode_thumb_special_data_branch_exch s isn =
    match (isn lsr 6) land 0xf with
    | 0b000 | 0b0001 | 0b0010 | 0b0011 -> (* Add High Registers ADD (register) *)
       let rd = ((isn lsr 4) land 0x8) lor (isn land 0x7) in
       let rm = (isn lsr 3) land 0xf in
       op_add (reg rd) rm (Lval (V (treg rd))) |> mark_couple
       
    | 0b0101 | 0b0110 | 0b0111 -> (* Compare High Registers CMP (register) *)
       notimplemented_thumb s isn "CMP (high reg)"
      
    | 0b1000 | 0b1001 | 0b1010 | 0b1011 -> (* Move High Registers MOV (register) *)
       thumb_mov_high_reg s isn
      
    | 0b1100 | 0b1101 -> (* Branch and Exchange BX *)
       thumb_bx s isn
      
    | 0b1110 | 0b1111 -> (* Branch with Link and Exchange BLX *)
       notimplemented_thumb s isn "BLX"

    | _ -> L.abort (fun p -> p "Unknown or unpredictable instruction %04x" isn)

  let thumb_mul _s isn =
    let rn = (isn lsr 3) land 7 in
    let rdm = isn land 7 in
    let dest = V (treg rdm) in
    let tmp = Register.make (Register.fresh_name ()) 64 in
    [ MARK_ISN (Set (V (T tmp),
                    BinOp(Mul,
                          Lval dest,
                          Lval (V (treg (rn)))))) ;
      MARK_ISN (Set (dest, Lval (V (P (tmp, 0, 31))))) ;
      MARK_ISN (Directive (Remove tmp)) ;
      MARK_FLAG (zflag_update_exp (Lval dest)) ;
      MARK_FLAG (nflag_update_exp (reg rdm)) ]

  let decode_thumb_data_processing s isn =
    let op1 = (isn lsr 3) land 7 in
    let op0 = isn land 7 in
    match (isn lsr 6) land 0xf with
    | 0b0000 -> (* Bitwise AND *)
       op_and (reg op0) op0 (Lval (V (treg op1))) |> mark_couple
      
    | 0b0001 -> (* Bitwise Exclusive OR *)
       op_eor (reg op0) op0 (Lval (V (treg op1))) |> mark_couple

    | 0b0010 -> (* LSL Logical Shift Left (register) *)
       let rm = (isn lsr 3) land 7 in
       let rd = isn land 7 in
       ([Set (V (treg rd), BinOp (Shl, Lval (V (treg rm)), UnOp (ZeroExt 32, Lval (V (preg rm 0 7)))))],
       [nflag_update_exp (reg rd) ; zflag_update_exp (Lval ( V (treg rd)))]) |> mark_couple


    | 0b0011 -> (* LSR Logical Shift Right *)
       notimplemented_thumb s isn "LSR (register)"
      
    | 0b0100 -> (* ASR Arithmetic Shift Right *)
       notimplemented_thumb s isn "ASR (register)"

    | 0b0101 -> (* ADC Add with Carry *)
       notimplemented_thumb s isn "ADC (register)"

    | 0b0110 -> (* SBC Subtract with Carry *)
       notimplemented_thumb s isn "SBC (register)"

    | 0b0111 -> (* ROR Rotate Right *)
       notimplemented_thumb s isn "ROR (register)"

    | 0b1000 -> (* TST Test *)
       let tmpreg = Register.make (Register.fresh_name ()) 32 in
       let opstmts,flagstmts = op_and tmpreg op0 (Lval (V (treg op1))) in
       mark_as_isn (opstmts @ flagstmts @ [ Directive (Remove tmpreg) ])

    | 0b1001 -> (* RSB Reverse Subtract from 0 *)
       op_rsb (reg op0) op1 (const 0 32) |> mark_couple
      
    | 0b1010 -> (* CMP Compare Registers *)
       let tmpreg = Register.make (Register.fresh_name ()) 32 in
       let opstmts,flagstmts = op_sub tmpreg op0 (Lval (V (treg op1))) in
       mark_as_isn (opstmts @ flagstmts @ [ Directive (Remove tmpreg) ])

    | 0b1011 -> (* CMN Compare Negative *)
       let tmpreg = Register.make (Register.fresh_name ()) 32 in
       let opstmts,flagstmts = op_add tmpreg op0 (Lval (V (treg op1))) in
       mark_as_isn (opstmts @ flagstmts @ [ Directive (Remove tmpreg) ])

    | 0b1100 -> (* ORR Bitwise OR *)
       op_orr (reg op0) op0 (Lval (V (treg op1))) |> mark_couple

    | 0b1101 -> (* MUL Multiply Two Registers *)
       thumb_mul s isn

    | 0b1110 -> (* BIC Bitwise Bit Clear *)
       op_bic (reg op0) op0 (Lval (V (treg op1))) |> mark_couple

    | 0b1111 -> (* MVN Bitwise NOT *)
       op_mvn (reg op0) (Lval (V (treg op1))) |> mark_couple

    | _ -> L.abort (fun p -> p "internal error")

  let thumb_ldr _s isn =
    let rt = (isn lsr 8) land 7 in
    let imm = isn land 0xff in
    [ Set (V (treg rt),
           Lval (M (BinOp (Add,
                           BinOp(And, Lval (V (T pc)),
                                 const 0xfffffffc 32),
                           const (imm lsl 2) 32),
                    32))) ] |> mark_as_isn

  let decode_thumb_load_store_single_data_item _s isn =
    let stmts =
      match (isn lsr 12) land 0xf with
      | 0b0101 ->
         let rn = (isn lsr 3) land 7 in
         let rt = isn land 7 in
         let rm = (isn lsr 6) land 7 in
         let ofs = BinOp (Add, Lval (V (treg rm)), Lval (V (treg rn))) in
         begin
           match (isn lsr 9) land 0x7 with
           | 0b000 -> (* STR (register) Store Register *)
              [ Set (M (ofs, 32), Lval (V (treg rt))) ]
           | 0b001 -> (* STRH (register) Store Register Halfword *)
              [ Set (M (ofs, 16), Lval (V (preg rt 0 15))) ]
           | 0b010 -> (* STRB (register) Store Register Byte *)
              [ Set (M (ofs, 8), Lval (V (preg rt 0 7))) ]
           | 0b011 -> (* LDRSB (register) Load Register Signed Byte *)
              [ Set (V (treg rt), UnOp (SignExt 32, Lval (M (ofs, 8)))) ]
           | 0b100 -> (* LDR (register) Load Register *)
              [ Set (V (treg rt), Lval (M (ofs, 32))) ]
           | 0b101 -> (* LDRH (register) Load Register Halfword *)
              [ Set (V (treg rt), UnOp( ZeroExt 32, Lval (M (ofs, 16)))) ]
           | 0b110 -> (* LDRB (register) Load Register Byte *)
              [ Set (V (treg rt), UnOp( ZeroExt 32, Lval (M (ofs, 8)))) ]
           | 0b111 -> (* LDRSH (register) Load Register Signed Halfword *)
              [ Set (V (treg rt), UnOp( SignExt 32, Lval (M (ofs, 16)))) ]
           | _ -> L.abort (fun p -> p "Internal error")
         end
      | 0b1001 ->
         let imm8 = isn land 0xff in
         let rt = isn lsr 8 land 7 in
         let ofs = BinOp (Add, Lval (V (T sp)), const (imm8 lsl 2) 32) in
         if isn land 0x800 = 0 then  (* STR (immediate) Store Register SP relative *)
           [ Set (M (ofs, 32), Lval (V (treg rt))) ]
         else (* LDR (immediate) Load Register SP relative *)
           [ Set (V (treg rt), Lval (M (ofs, 32))) ]
      | _ ->
         let rn = (isn lsr 3) land 7 in
         let rt = isn land 7 in
         let imm5 = (isn lsr 6) land 0x1f in
         let ofs sz = BinOp (Add, Lval (V (treg rn)), const (imm5 lsl sz) 32) in
         (* imm5 is shifted by 0 for byte access, 1 for halfword access, 2 for word access *)
         begin
           match isn lsr 11 land 0x1f with
           | 0b01100 -> (* STR (immediate) Store Register *)
              [ Set (M (ofs 2, 32), Lval (V (treg rt))) ]
           | 0b01101 -> (* LDR (immediate) Load Register *)
              [ Set (V (treg rt), Lval (M (ofs 2, 32))) ]
           | 0b01110 -> (* STRB (immediate) Store Register Byte *)
              [ Set (M (ofs 0, 8), Lval (V (preg rt 0 7))) ]
           | 0b01111 -> (* LDRB (immediate) *)
              [ Set (V (treg rt), UnOp(ZeroExt 32, Lval (M (ofs 0, 8)))) ]
           | 0b10000 -> (* STRH (immediate) Store Register Halfword *)
              [ Set (M (ofs 1, 16), Lval (V (preg rt 0 15))) ]
           | 0b10001 -> (* LDRH (immediate) Load Register Halfword *)
              [ Set (V (treg rt), UnOp(ZeroExt 32, Lval (M (ofs 1, 16)))) ]
           | _ -> L.abort (fun p -> p "Internal error")
         end in
    mark_as_isn stmts


  let decode_thumb32_data_proc_shift_reg s isn isn2 =
    let op = (isn lsr 5) land 0xf in
    let rn = isn land 0xf in
    let tst = (isn lsr 4) land 1 in
    match op with
    | 0b0000 ->
       if tst = 0 then (* Bitwise AND AND (register) *)
         notimplemented_thumb s isn "AND (register)"
       else (* TST (register) *)
         notimplemented_thumb s isn "TST (register)"
    | 0b0001 -> (* Bitwise Bit Clear BIC (register) *)
       notimplemented_thumb s isn "BIC (register)"
    | 0b0010 ->
       if rn = 0xf then (* Move MOV (register) *)
         notimplemented_thumb s isn "ORR (register)"
       else (* Bitwise OR ORR (register) *)
         notimplemented_thumb s isn "ORR (register)"
    | 0b0011 ->
       if rn = 0xf then (* Bitwise NOT MVN (register) *)
         notimplemented_thumb s isn "MVN (register)"
       else (* Bitwise OR NOT ORN (register) *)
         notimplemented_thumb s isn "ORN (register)"
    | 0b0100 ->
       if tst = 0 then (* Bitwise Exclusive OR EOR (register) *)
         notimplemented_thumb s isn "EOR (register)"
       else (* Test Equivalence TEQ (register) *)
         notimplemented_thumb s isn "TEQ (register)"
    | 0b0110 -> (* Pack Halfword PKH *)
       notimplemented_thumb s isn "PKH"
    | 0b1000 ->
       if tst = 0 then (* Add ADD (register) *)
         notimplemented_thumb s isn "ADD (register)"
       else (* Compare Negative CMN (register) *)
         notimplemented_thumb s isn "CMN (register)"
    | 0b1010 -> (* Add with Carry ADC (register) *)
       notimplemented_thumb s isn "ADC (register)"
    | 0b1011 -> (* Subtract with Carry SBC (register) *)
       notimplemented_thumb s isn "SBC (register)"
    | 0b1101 ->
       if tst = 0 then (* Subtract SUB (register) *)
         notimplemented_thumb s isn "SUB (register)"
       else (* Compare CMP (register) *)
         notimplemented_thumb s isn "CMP (register)"
    | 0b1110 -> (* Reverse Subtract RSB (register) *)
       notimplemented_thumb s isn "RSB (register)"
    | _ -> L.abort (fun p -> p "Unexpected thumb32 encoding %04x %04x" isn isn2)



  let thumb32_bl_blx_immediate _s isn isn2 =
    let immh = isn land 0x3ff in
    let imml = isn2 land 0x7ff in
    let toARM = isn2 land 0x1000 = 0 in (* true -> BLX | false -> BL *)
    let bit_s = (isn lsr 10) land 1 in
    let j1 = (isn2 lsr 13) land 1 in
    let j2 = (isn2 lsr 11) land 1 in
    let i1 = 1 lxor (j1 lxor bit_s) in
    let i2 = 1 lxor (j2 lxor bit_s) in
    let imm32 = sconst ((imml lsl 1) lor
                        (immh lsl 12) lor
                        (i2 lsl 22) lor
                        (i1 lsl 23) lor
                        (bit_s lsl 24)) 25 32 in
    let alignpc =
      if toARM then BinOp(And, Lval (V (T pc)), const 0xfffffffc 32)
      else Lval (V (T pc)) in
    let exch =
      if toARM then [ Set (V (T tflag), const 0 1) ] else [] in
    [ Set( V (T lr), BinOp (Or, Lval (V (T pc)), const 1 32)) ;
      Set (V (T pc), BinOp(Add, alignpc, imm32)) ;
    ] @ exch @ [ Call (R (Lval (V (T pc)))) ] |> mark_as_isn


  let decode_thumb32_branches_misc s isn isn2 =
    let op = (isn lsr 4) land 0x7f in
    let op1 = (isn2 lsr 12) land 7 in
    let _op2 = (isn2 lsr 8) land 0xf in
    match op1 with
    | 0b000 | 0b010 ->
       begin
         if op land 0x38 = 0x38 then
           match op with
           | 0b0111000 | 0b0111001 -> notimplemented_thumb s isn "MSR"
           | 0b0111010 -> notimplemented_thumb s isn "change proc state and hints"
           | 0b0111011 -> notimplemented_thumb s isn "misc control"
           | 0b0111100 -> notimplemented_thumb s isn "BXJ"
           | 0b0111101 -> notimplemented_thumb s isn "exception return SUBS PC,LR"
           | 0b0111110 | 0b0111111 -> notimplemented_thumb s isn "MRS"
           | 0b1111111 ->
              if op1 = 0 then
                notimplemented_thumb s isn "SMC"
              else
                L.abort (fun p -> p "permanently undefined thumb32 instruction %04x %04x" isn isn2)
           | _ -> L.abort (fun p -> p "unexpected thumb32 encoding %04x %04x" isn isn2)
         else (* Conditional branch *)
           notimplemented_thumb s isn "conditional branch"
       end
    | 0b001 | 0b011 -> notimplemented_thumb s isn "B"
    | 0b100 | 0b110 | 0b101 | 0b111 -> (* BL, BLX *)
       thumb32_bl_blx_immediate s isn isn2
    | _ -> L.abort (fun p -> p "unexpected thumb32 encoding %04x %04x" isn isn2)

  let ror_c_imm32 imm n _c =
    let m = n mod 32 in
    let result = (imm lsr m) lor (imm lsl (32-m)) in
    (result land 0xFFFFFFFF, (result lsr 31) land 1)


  let thumb_expand_imm_c imm12 c =
    L.debug (fun p->p "thumb_expand_imm_c 0x%x" imm12);
    let imm8 = imm12 land 0xFF in
    if (imm12 lsr 10) land 3 = 0 then
        let op = ((imm12 lsr 8) land 3) in
        if op != 0 && imm8 = 0 then
            L.abort (fun p->p "thumb_expand_imm_c: unpredictable")
        else
            let imm32 =
                match op with
                | 0b00 -> const imm8 32
                | 0b01 -> const ((imm8 lsl 16) lor imm8) 32
                | 0b10 -> const ((imm8 lsl 24) lor (imm8 lsl 8)) 32
                | 0b11 -> const ((imm8 lsl 24) lor (imm8 lsl 16)
                                 lor (imm8 lsl 8) lor imm8) 32
                | _ -> L.abort (fun p -> p "Impossible state")
            in
            L.debug (fun p->p "thumb_expand_imm_c ret %s" (Asm.string_of_exp imm32 true));
            (imm32, c)
    else
        let unrot = 0b10000000 lor (imm12 land 0x7F) in
        let rot, c = ror_c_imm32 unrot (imm12 lsr 7) c in
        (const rot 32, c)


  let thumb32_mov rd rn _bit_s imm12 =
    let imm32, _ = thumb_expand_imm_c imm12 0 (* TODO: carry *) in
    if rn = 0xF then
        [ MARK_ISN (Set (V (treg rd), imm32)) ]
    else
        [ MARK_ISN (Set (V (treg rd), BinOp(Or, Lval(V (treg rn)), imm32))) ]

  let thumb32_add_cmn rd rn _bit_s imm12 =
    let imm32, _ = thumb_expand_imm_c imm12 0 (* TODO: carry *) in
    if rn = 0xF then
        [ MARK_ISN (Set (V (treg rd), BinOp(Sub, Lval(V (treg rn)), imm32))) ]
    else
        [ MARK_ISN (Set (V (treg rd), BinOp(Add, Lval(V (treg rn)), imm32))) ]

  let thumb32_sub_cmp rd rn _bit_s imm12 =
    let imm32, _ = thumb_expand_imm_c imm12 0 (* TODO: carry *) in
    if rn = 0xF then
        [ MARK_ISN (Set (V (treg rd), imm32)) ]
    else
        [ MARK_ISN (Set (V (treg rd), BinOp(Sub, Lval(V (treg rn)), imm32))) ]


  let decode_thumb32_data_mod_imm s isn isn2 =
    let op = (isn lsr 5) land 0xf in
    let bit_s = (isn lsr 1) land 1 in
    let rn = isn land 0xf in
    let rd = (isn2 lsr 8) land 0xf in
    let imml = isn2 land 0xff in
    let immh = (isn2 lsr 12) land 0b111 in
    let imm12 = (immh lsl 8) lor imml lor ((isn land 0x400) lsl 1) in
    L.debug (fun p->p "decode_thumb32_data_mod_imm 0x%x 0x%x 0x%x" isn isn2 imm12);
    match op with
    | 0b0000 -> notimplemented_thumb s isn "thumb32 AND/TST"
    | 0b0001 -> notimplemented_thumb s isn "thumb32 BIC"
    | 0b0010 -> thumb32_mov rd rn bit_s imm12
    | 0b0011 -> notimplemented_thumb s isn "thumb32 OR/NOR"
    | 0b0100 -> notimplemented_thumb s isn "thumb32 XOR/TST"
    | 0b1000 -> thumb32_add_cmn rd rn bit_s imm12
    | 0b1010 -> notimplemented_thumb s isn "thumb32 addc"
    | 0b1011 -> notimplemented_thumb s isn "thumb32 subc"
    | 0b1101 -> thumb32_sub_cmp rd rn bit_s imm12
    | 0b1110 -> notimplemented_thumb s isn "thumb32 revsub"
    | _ -> L.abort (fun p -> p "Unexpected thumb32 encoding")

  let decode_thumb32_store_single s isn isn2 =
    let op1 = (isn lsr 5) land 7 in
    let op2msb = (isn2 lsr 11) land 1 in
    let rn = (isn land 0xF) in
    let rt = ((isn2 lsr 12) land 0xF) in
    match (op1, op2msb) with
    | (0b100, _) -> notimplemented_thumb s isn "STRB imm"
    | (0, 1) -> let index  = ((isn2 lsr 10) land 1) = 1 in
                let op = if ((isn2 lsr 9) land 1) = 1 then Add else Sub in
                let wback  = ((isn2 lsr 8) land 1) = 1 in
                let imm32 = const (isn2 land 0xFF) 32 in
                let offset_addr = BinOp(op, Lval(V (treg rn)), imm32) in
                let address = if index then offset_addr else Lval(V( treg rn)) in
                let wback_stmts = if wback then [MARK_ISN(Set(V(treg rn), offset_addr))] else [] in
                let store = MARK_ISN(Set(M(address, 8), Lval(V (preg rt 0 7)))) in
                [store] @ wback_stmts
    | (0, 0) -> notimplemented_thumb s isn "STRB reg"
    | (0b101, _) | (0b001, 1) -> notimplemented_thumb s isn "STRH imm"
    | (0b001, 0) -> notimplemented_thumb s isn "STRH reg"
    | (0b110, _) | (0b010, 1) -> notimplemented_thumb s isn "STR imm"
    | (0b010, 0) -> notimplemented_thumb s isn "STR reg"
    | _ -> L.abort (fun p -> p "Unexpected thumb32 encoding")


  let decode_thumb32 s isn isn2 =
    let op1 = (isn lsr 11) land 3 in
    let op2 = (isn lsr 4) land 0x7f in
    let op = isn2 lsr 15 in
    match op1 with
    | 0b01 ->
       if op2 land 0x64 = 0 then (* Load/store multiple *)
         notimplemented_thumb s isn "thumb32 load/store multible"
       else if op2 land 0x64 = 4 then (* Load/store dual, load/store exclusive, table branch *)
         notimplemented_thumb s isn  "load/store dual/excl, table branch"
       else if op2 land 0x60 = 0x20 then (* Data-processing (shifted register) *)
         decode_thumb32_data_proc_shift_reg s isn isn2
       else if op2 land 0x40 = 40 then (* Coprocessor instructions *)
         notimplemented_thumb s isn "Coprocessor instructions"
       else L.abort (fun p -> p "Unexpected thumb32 encoding %04x %04x" isn isn2)
    | 0b10 ->
       if op = 1 then (* Branches and miscellaneous control *)
         decode_thumb32_branches_misc s isn isn2
       else
         if op2 land 0x20 = 0 then (* Data-processing (modified immediate) *)
           decode_thumb32_data_mod_imm s isn isn2
         else (* Data-processing (immediate) *)
           notimplemented_thumb s isn "Data-processing (plain binary immediate)"
    | 0b11 ->
       if op2 land 0x71 = 0 then (* Store single data item *)
         decode_thumb32_store_single s isn isn2
       else if op2 land 0x71 = 0x10 then (* Advanced SIMD element or structure load/store *)
         notimplemented_thumb s isn "Advanced SIMD element or structure load/store"
       else if op2 land 0x67 = 1 then (* Load byte, memory hints *)
         notimplemented_thumb s isn "Load byte, memory hints"
       else if op2 land 0x67 = 3 then (* Load halfword, memory hints *)
         notimplemented_thumb s isn "Load halfword, memory hints"
       else if op2 land 0x67 = 5 then (* Load word *)
         notimplemented_thumb s isn "Load word"
       else if op2 land 0x67 = 7 then
         L.abort (fun p -> p "undefined Thumb32 instruction")
       else if op2 land 0x70 = 0x20 then (* Data-processing (register) *)
         notimplemented_thumb s isn "Data-processing (register)"
       else if op2 land 0x78 = 0x30 then (* Multiply, multiply accumulate, and absolute difference *)
         notimplemented_thumb s isn "Multiply, multiply accumulate, and absolute difference"
       else if op2 land 0x78 = 0x38 then (* Long multiply, long multiply accumulate, and divide *)
         notimplemented_thumb s isn "Long multiply, long multiply accumulate, and divide"
       else if op2 land 0x40 = 0x40 then (* Coprocessor instructions *)
         notimplemented_thumb s isn "Coprocessor instructions"
       else L.abort (fun p -> p "Unexpected thumb32 encoding %04x %04x" isn isn2)
    | _ -> L.abort (fun p -> p "Unexpected thumb32 encoding")

  let thumb_generate_pc_relative _s isn =
    let rd = (isn lsr 8) land 7 in
    let imm8 = isn land 0xff in
    let value = const (imm8 lsl 2) 32 in
    mark_as_isn [ Set (V (treg rd),
                       BinOp (Add,
                              BinOp(And, Lval (V (T pc)),
                                    const 0xfffffffc 32),
                              value)) ]

  let thumb_generate_sp_relative _s isn =
    let rd = (isn lsr 8) land 7 in
    let imm8 = isn land 0xff in
    let value = const (imm8 lsl 2) 32 in
    op_add (reg rd) 13 value |> mark_couple (* 13 = sp *)

  let decode_thumb (s: state): Cfa.State.t * Data.Address.t =
    let str = String.sub s.buf 0 2 in
    let instruction = build_thumb16_instruction s str in
    let marked_stmts =
      if (instruction lsr 13) land 7 = 0b111 && (instruction lsr 11) land 3 != 0 then
        let str2 = String.sub s.buf 2 2 in
        let isn2 = build_thumb16_instruction s str2 in
        decode_thumb32 s instruction isn2
      else
        match (instruction lsr 10) land 0x3f with
        | 0b010000 -> (* Data-processing *)
           decode_thumb_data_processing s instruction
        | 0b010001 -> (* Special data instructions and branch and exchange *)
           decode_thumb_special_data_branch_exch s instruction
        | 0b010010 | 0b010011 -> (* Load from Literal Pool *)
           thumb_ldr s instruction
        | 0b101000 | 0b101001 -> (* Generate PC-relative address *)
           thumb_generate_pc_relative s instruction
        | 0b101010 | 0b101011 -> (* Generate SP-relative address *)
           thumb_generate_sp_relative s instruction
        | 0b101100 | 0b101101 | 0b101110 | 0b101111 -> (* Miscellaneous 16-bit instructions *)
           decode_thumb_misc s instruction
        | 0b110000 | 0b110001 -> (* Store multiple registers *)
           notimplemented_thumb s instruction "multiple reg storage"
        | 0b110010 | 0b110011 -> (* Load multiple registers *)
           notimplemented_thumb s instruction "multiple reg loading"
        | 0b110100 | 0b110101 | 0b110110 | 0b110111 -> (* Conditional branch, and Supervisor Call *)
           decode_thumb_branching_svcall s instruction
        | 0b111000 | 0b111001 -> (* Unconditional Branch *)
           thumb_branching s instruction
        | _ ->
           begin
             match (instruction lsr 13) land 7 with
             | 0b000 | 0b001 -> (* Shift (immediate), add, subtract, move, and compare *)
                decode_thumb_shift_add_sub_mov_cmp s instruction
             | 0b010 | 0b011 | 0b100 -> (* Load/store single data item *)
                (* 0b0100 does not belong here but is taken care of before*)
                decode_thumb_load_store_single_data_item s instruction
             | _ -> L.abort (fun p -> p "Unknown thumb encoding %04x" instruction)
           end in
    (* pc is 4 bytes ahead in thumb mode because of pre-fetching. *)
    let current_pc = Const (Word.of_int (Z.add (Address.to_int s.a) (Z.of_int 4)) 32) in
    let filtered_stmts =
      match s.itstate with
      | None -> L.abort (fun p -> p "Could not obtain a concrete ITSTATE value. Decoding not supported yet in this case")
      | Some v ->
         if (v land 0xf) = 0
         then remove_marks marked_stmts
         else let next_itstate = if v land 7 = 0 then 0 else (v land 0xf0) lor ((v lsl 1) land 0xf) in
              (wrap_cc (v lsr 4) (remove_marks_keep_isn marked_stmts)) @ [ Set (V (T itstate), const next_itstate 8)] in
    return s instruction (Set( V (T pc), current_pc) :: filtered_stmts)

  let parse text cfg _ctx state addr oracle =
    let tflag_val =
      try oracle#value_of_register tflag
      with Exceptions.Too_many_concrete_elements _ ->
        raise (Exceptions.Too_many_concrete_elements "Value of T flag cannot be determined. Cannot disassemble next instruction") in
    let itstate_val =
      try Some (Z.to_int (oracle#value_of_register itstate))
      with Exceptions.Too_many_concrete_elements _ -> None in
    let s =  {
      g = cfg;
      b = state;
      a = addr;
      buf = text;
      endianness = !Config.endianness;
      thumbmode = tflag_val = Z.one;
      itstate = itstate_val;
    }
    in
    try
      let decode = if  s.thumbmode then decode_thumb else decode_arm in
      let v', ip' = decode s in
      Some (v', ip', ())
    with
      | Exceptions.Error _ as e -> raise e
      | _  -> (*end of buffer *) None

  let init_registers () = []
                        
let init () = Imports.init ()

  let overflow_expression () = Lval (V (T vflag))
end
