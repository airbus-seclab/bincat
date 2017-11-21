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

  let reg_from_num n =
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

  let reg n =
    T (reg_from_num n)

  let preg n a b =
    P ((reg_from_num n), a, b)

  let n_is_set = Cmp(EQ, Lval (V (T nflag)), const 1 1)
  let z_is_set = Cmp(EQ, Lval (V (T zflag)), const 1 1)
  let c_is_set = Cmp(EQ, Lval (V (T cflag)), const 1 1)
  let v_is_set = Cmp(EQ, Lval (V (T vflag)), const 1 1)
  let n_is_clear = Cmp(EQ, Lval (V (T nflag)), const 0 1)
  let z_is_clear = Cmp(EQ, Lval (V (T zflag)), const 0 1)
  let c_is_clear = Cmp(EQ, Lval (V (T cflag)), const 0 1)
  let v_is_clear = Cmp(EQ, Lval (V (T vflag)), const 0 1)

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
    | 0b1010 -> BBinOp(LogOr, BBinOp(LogAnd, n_is_set, v_is_set), BBinOp(LogAnd, n_is_clear, v_is_clear))
    (* GE - N set and V set, or N clear and V clear (greater or equal) *)
    | 0b1011 -> BBinOp(LogOr, BBinOp(LogAnd, n_is_set, v_is_clear), BBinOp(LogAnd, n_is_clear, v_is_set))
    (* LT - N set and V clear, or N clear and V set (less than) *)
    | 0b1100 -> BBinOp(LogOr, BBinOp(LogAnd, z_is_clear, BBinOp(LogOr, n_is_set, v_is_set)),
                       BBinOp(LogAnd, n_is_clear, v_is_clear))
    (* GT - Z clear, and either N set and V set, or N clear and V clear (greater than) *)
    | 0b1101 -> BBinOp(LogOr, z_is_set,
                       BBinOp(LogOr, BBinOp(LogAnd, z_is_set, v_is_clear),
                              BBinOp(LogAnd, n_is_clear, v_is_set)))
    (* LE - Z set, or N set and V clear, or N clear and V set (less than or equal) *)
    | _ -> L.abort (fun p -> p "Unexpected condiction code %x" cc)


  let to33bits x = UnOp(ZeroExt 33, x)
  let to33bits_s x = UnOp(SignExt 33, x)

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

  (* fatal error reporting *)
  let error a msg =
    L.abort (fun p -> p "at %s: %s" (Address.to_string a) msg)

  let notimplemented isn = L.abort (fun p -> p "%s thumb16 instruction not implemented yet" isn)

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
        8, (V (preg rm 0 7)), (M (Lval (V (reg rn)), 8)), (V (preg rd 0 7))
      else
        32, (V (reg rm)), M (Lval (V (reg rn)), 32), (V (reg rd)) in
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
        Set (V (reg rd), BinOp(Add, Lval (V (P (tmpreg, 0, 31))),
                               Lval (V (reg rn))))
      else
        Set (V (reg rd), Lval (V (P (tmpreg, 0, 31)))) in
    let cc_stmts = if set_cc then
        [ Set(V (T zflag), TernOp (Cmp(EQ, Lval (V (reg rd)), const 0 32),
                                   const 1 1, const 0 1)) ;
          Set(V (T nflag), Lval (V (preg rd 31 31))) ;
          Directive (Forget (V (T cflag))) ]
      else
        [] in
    let stmt = Set (V (T tmpreg), BinOp(Mul, Lval (V (reg rm)), Lval (V (reg rs)))) in
    stmt :: accu_stmt :: Directive (Remove tmpreg) :: cc_stmts


  let block_data_transfer s instruction =
    if instruction land (1 lsl 22) <> 0 then error s.a "LDM/STM with S=1 not implemented"
    else
      let rn = (instruction lsr 16) land 0xf in
      let ascend = instruction land (1 lsl 23) <> 0 in
      let dir_op = if ascend then Add else Sub in
      let ofs = ref (if instruction land (1 lsl 24) = 0 then 0 else 4) in
      let store = instruction land (1 lsl 20) = 0 in
      let stmts = ref [] in
      let update_pc = ref false in
      let reg_count = ref 0 in
      for i = 0 to 15 do
        let regtest = if ascend then i else 15-i in
        if (instruction land (1 lsl regtest)) <> 0 then
          begin
            if store then
              stmts := !stmts @
                [ Set( M (BinOp(dir_op, Lval (V (reg rn)), const !ofs 32), 32),
                            Lval (V (reg regtest))) ]
            else
              begin
                stmts := !stmts @
                  [ Set( V (reg regtest),
                         Lval (M (BinOp(dir_op, Lval (V (reg rn)), const !ofs 32), 32))) ];
                if i = 15 then update_pc := true
              end;
            ofs := !ofs+4;
            reg_count := !reg_count + 1
          end
        else ()
      done;
      if instruction land (1 lsl 21) <> 0 then
        stmts := !stmts @
          [ Set (V (reg rn), BinOp(dir_op, Lval (V (reg rn)), const (4*(!reg_count)) 32)) ];
      if !update_pc then
        stmts := !stmts @ [ Jmp (R (Lval (V (T pc)))) ];
      !stmts

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
    let zero = const 0 32 in
    let one = const 1 32 in
    let jreg = Lval(V(reg (instruction land 0xf))) in
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
    let rm33 = UnOp(ZeroExt 33, Lval (V (reg rm))) in
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
              Lval (V (reg rm))
            else
              BinOp(Shl, Lval (V (reg rm)), const shift_amount 32)
          | 0b01 -> (* logical shift right *)
             let actual_shift = if shift_amount = 0 then 32 else shift_amount in
             BinOp(Shl, Lval (V (reg rm)), const actual_shift 32)
          | 0b10 -> (* asr *)
             let actual_shift = if shift_amount = 0 then 32 else shift_amount in
             asr_stmt (Lval (V (reg rm))) actual_shift
          | 0b11 -> (* ror *)
             let actual_shift = if shift_amount = 0 then 32 else shift_amount in
             ror_stmt (Lval (V (reg rm))) actual_shift
          | _ -> error s.a "unexpected shift type insingle data xfer" in
    let updown = if (instruction land (1 lsl 23)) = 0 then Sub else Add in
    let preindex = (instruction land (1 lsl 24)) <> 0 in
    let writeback = (instruction land (1 lsl 21)) <> 0 in
    let length, dst_or_src = if (instruction land (1 lsl 22)) = 0 then
        32, (V (reg rd))
      else
        8, (V (preg rd 0 7)) in
    let src_or_dst = match preindex,writeback with
      | true, false -> M (BinOp(updown, Lval (V (reg rn)), ofs), length)
      | true, true
      | false, false -> M (Lval (V (reg rn)), length) (* if post-indexing, write back is implied and W=0 *)
      | false, true -> error s.a "Undefined combination (post indexing and W=1)" in
    let stmts,update_pc = if (instruction land (1 lsl 20)) = 0 then (* store *)
        [ Set (src_or_dst, Lval dst_or_src)], false
      else (* load *)
        if length = 32 then
          [ Set (V (reg rd), Lval src_or_dst) ], rd = 15
        else
          [ Set (V (reg rd), UnOp(ZeroExt 32, Lval src_or_dst)) ], rd = 15 in
    let write_back_stmt = Set (V (reg rn), BinOp(updown, Lval (V (reg rn)), ofs)) in
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
        Lval (V (reg rm)) in
    let index_expr = BinOp(updown, Lval (V (reg rn)), ofs) in
    let src_or_dst = match preindex,writeback with
      | true, false -> M (index_expr, length)
      | true, true
      | false, false -> M (Lval (V (reg rn)), length) (* if post-indexing, write back is implied and W=0 *)
      | false, true -> error s.a "Undefined combination (post indexing and W=1)" in
    let stmts, update_pc = if load then
        [ Set (V (reg rd), UnOp(extend_op, Lval src_or_dst)) ], rd = 15
      else
        [ Set (src_or_dst, Lval (V (preg rd 0 (length-1)))) ], false in
    let write_back_stmt = Set (V (reg rn), index_expr) in
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

  let data_proc s instruction =
    let rd = (instruction lsr 12) land 0xf in
    let rn = (instruction lsr 16) land 0xf in
    let is_imm = instruction land (1 lsl 25) <> 0 in
    let set_cond_codes = instruction land (1 lsl 20) <> 0 in
    let op2_stmt, op2_carry_stmt =
      if is_imm then
        let shift = (instruction lsr 8) land 0xf in
        let imm = instruction land 0xff in
        const (ror32 imm (2*shift)) 32, [ Set( V (T cflag), const ((imm lsr (2*shift-1)) land 1) 0)]
      else
        let shift_op = (instruction lsr 4) land 0xff in
        let rm = instruction land 0xf in
        let op3, int_shift_count =
          if shift_op land 1 = 0 then
            const (shift_op lsr 3) 32, Some (shift_op lsr 3)
          else
            Lval (V (reg (shift_op lsr 4))), None in
        match (shift_op lsr 1) land 0x3 with
        | 0b00 -> (* lsl *)
           begin
             match  int_shift_count with
             | Some 0 -> Lval (V (reg rm))
             | _ -> BinOp(Shl, Lval (V (reg rm)), op3)
           end,
             begin
               match int_shift_count with
               | Some 0 -> [] (* lsl 0 => preserve carry *)
               | Some n -> [ Set( V (T cflag),  (* shift count is an immediate, we can directly test the bit *)
                                  TernOp (Cmp (EQ, BinOp(And, Lval (V (reg rm)), const (1 lsl (32-n)) 32),const 0 32),
                                          const 0 1, const 1 1)) ]
               | None -> [ Set ( V (T cflag),   (* shift count comes from a register. We shift again on 33 bits *)
                                 TernOp (Cmp (EQ, BinOp(And,
                                                        BinOp(Shl, UnOp(ZeroExt 33, Lval (V (reg rm))),
                                                              UnOp(ZeroExt 33, op3)),
                                                        const (1 lsl 32) 33), const 0 33),
                                         const 0 1, const 1 1)) ]
             end
        | 0b01 -> (* lsr *)
           begin
             match int_shift_count with
             | Some 0 -> const 0 32 (* 0 actually encodes lsr #32 *)
             | _ -> BinOp(Shr, Lval (V (reg rm)), op3)
           end,
             begin
               match int_shift_count with
               | Some n -> [ set_cflag_from_bit rm n ]
               | None -> [ set_cflag_from_bit_exp rm op3 ]
             end
        | 0b10 -> (* asr *)
           begin
             match int_shift_count with
             | Some 0 -> asr_stmt (Lval (V (reg rm))) 32 (* 0 actually encodes lsr #32 *)
             | Some x -> asr_stmt (Lval (V (reg rm))) x
             | None -> asr_stmt_exp (Lval (V (reg rm))) op3
           end,
             begin
               match int_shift_count with
               | Some n -> [ set_cflag_from_bit rm n ]
               | None -> [ set_cflag_from_bit_exp rm op3 ]
             end
        | 0b11 -> (* ror *)
           begin
             match int_shift_count with
             | Some 0 -> (* RRX operation *)
                let shifted = BinOp(Shr, Lval (V (reg rm)), const 1 32) in
                let carry_in = TernOp( Cmp (EQ, Lval (V (T cflag)), const 0 1), const 0 32, const 0x80000000 32) in
                BinOp(Or, shifted, carry_in)
             | Some x -> ror_stmt (Lval (V (reg rm))) x
             | None -> ror_stmt_exp (Lval (V (reg rm))) op3
           end,
             begin
               match int_shift_count with
               | Some 0 -> (* RRX operation *)
                  let carry_out = TernOp( Cmp (EQ, BinOp(And, Lval (V (reg rm)), const 1 32), const 0 32), const 0 1, const 1 1) in
                  [ Set ( V (T cflag), carry_out) ]
               | Some n -> [ set_cflag_from_bit rm n ]
               | None -> [ set_cflag_from_bit_exp rm op3 ]
             end
        | st -> L.abort (fun p -> p "unexpected shift type %x" st)
    in
    let _nflag_update_exp res_exp = Set(V (T nflag), TernOp (Cmp(EQ, BinOp(And, res_exp, const 0x80000000 32),
                                                                const 0 32),
                                                            const 0 1, const 1 1)) in
    let nflag_update_from_reg_exp res_reg = Set(V (T nflag), Lval (V (P (res_reg, 31, 31)))) in
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
        Directive(Remove tmpregs) ] in
    let cflag_update_stmts op a b =
      let tmpreg = Register.make (Register.fresh_name ()) 33 in
      [ Set (V (T tmpreg), BinOp(op, to33bits a, to33bits b)) ;
        Set (V (T cflag), Lval (V (P (tmpreg, 32, 32)))) ;
        Directive (Remove tmpreg) ] in
    let cflag_update_stmts_with_carry op a b =
      let tmpreg = Register.make (Register.fresh_name ()) 33 in
      [ Set (V (T tmpreg), BinOp(op, UnOp(ZeroExt 33, Lval (V (T cflag))),
                                 BinOp(op, to33bits a, to33bits b))) ;
        Set (V (T cflag), Lval (V (P (tmpreg, 32, 32)))) ;
        Directive (Remove tmpreg) ] in
    let stmts, flags_stmts, update_pc =
      let opcode = (instruction lsr 21) land 0xf in
      match opcode with
      | 0b0000 -> (* AND - Rd:= Op1 AND Op2 *)
        [ Set (V (reg rd), BinOp(And, Lval (V (reg rn)), op2_stmt) ) ],
        [ zflag_update_exp (Lval (V (reg rd))) ;
          nflag_update_from_reg_exp (reg_from_num rd) ]
        @ op2_carry_stmt,
        rd = 15
      | 0b0001 -> (* EOR - Rd:= Op1 EOR Op2 *)
        [ Set (V (reg rd), BinOp(Xor, Lval (V (reg rn)), op2_stmt) ) ],
        [ zflag_update_exp (Lval (V (reg rd))) ;
          nflag_update_from_reg_exp (reg_from_num rd) ]
        @ op2_carry_stmt,
        rd = 15
      | 0b0010 -> (* SUB - Rd:= Op1 + not Op2 + 1 *)
         let tmpreg = Register.make (Register.fresh_name ()) 33 in
         [ Set (V (reg rd), BinOp(Sub, Lval (V (reg rn)), op2_stmt) ) ],
         [ zflag_update_exp (Lval (V (reg rd))) ;
           nflag_update_from_reg_exp (reg_from_num rd) ;
           vflag_update_exp (Lval (V (reg rn))) (UnOp(Not, op2_stmt)) (Lval (V (reg rd))) ;
           (* sub is computed witn sub a,b = a+(not b)+1, hence the carry *)
           Set (V (T tmpreg), BinOp(Add, BinOp(Add,
                                               to33bits (Lval (V (reg rn))),
                                               to33bits (UnOp(Not, op2_stmt))),
                                    const 1 33)) ;
           Set (V (T cflag), Lval (V (P (tmpreg, 32, 32)))) ;
           Directive (Remove tmpreg) ],
         rd = 15
      | 0b0011 -> (* RSB - Rd:= Op2 - Op1 *)
         let tmpreg = Register.make (Register.fresh_name ()) 33 in
         [ Set (V (reg rd), BinOp(Sub, op2_stmt, Lval (V (reg rn)))) ],
         [ zflag_update_exp (Lval (V (reg rd))) ;
           nflag_update_from_reg_exp (reg_from_num rd) ;
           vflag_update_exp op2_stmt (UnOp(Not, (Lval (V (reg rn))))) (Lval (V (reg rd))) ;
           Set (V (T tmpreg), BinOp(Add, BinOp(Add,
                                               to33bits op2_stmt,
                                               to33bits (UnOp(Not, Lval (V (reg rn))))),
                                    const 1 33)) ;
           Set (V (T cflag), Lval (V (P (tmpreg, 32, 32)))) ;
           Directive (Remove tmpreg) ],
         rd = 15
    | 0b0100 -> (* ADD - Rd:= Op1 + Op2 *)
      [ Set (V (reg rd), BinOp(Add, Lval (V (reg rn)), op2_stmt) ) ],
      [ zflag_update_exp (Lval (V (reg rd))) ;
        nflag_update_from_reg_exp (reg_from_num rd) ;
        vflag_update_exp (Lval (V (reg rn))) op2_stmt (Lval (V (reg rd))) ; ]
      @ cflag_update_stmts Add (Lval (V (reg rn))) op2_stmt,
      rd = 15
    | 0b0101 -> (* ADC - Rd:= Op1 + Op2 + C *)
      [ Set (V (reg rd), BinOp(Add, UnOp(ZeroExt 32, Lval (V (T cflag))),
                                BinOp(Add, Lval (V (reg rn)), op2_stmt) )) ],
      [ zflag_update_exp (Lval (V (reg rd))) ;
        nflag_update_from_reg_exp (reg_from_num rd) ;
        vflag_update_exp (Lval (V (reg rn))) op2_stmt (Lval (V (reg rd))) ; ]
      @ cflag_update_stmts_with_carry Add (Lval (V (reg rn))) op2_stmt,
      rd = 15
    | 0b0110 -> (* SBC - Rd:= Op1 - Op2 + C - 1 *)
       [ Set (V (reg rd), BinOp(Sub,
                                BinOp(Add, BinOp(Sub, Lval (V (reg rn)), op2_stmt),
                                      UnOp(ZeroExt 32, Lval (V (T cflag))) ),
                                const 1 32)) ],
       [ zflag_update_exp (Lval (V (reg rd))) ;
         nflag_update_from_reg_exp (reg_from_num rd) ; ]
       @ set_cflag_vflag_after_add_with_carry (Lval (V (reg rn))) (UnOp(Not, op2_stmt)) (Lval (V (T cflag))),
      rd = 15
    | 0b0111 -> (* RSC - Rd:= Op2 - Op1 + C - 1 *)
       [ Set (V (reg rd), BinOp(Sub,
                                BinOp(Add, BinOp(Sub, op2_stmt, Lval (V (reg rn))),
                                      UnOp(ZeroExt 32, Lval (V (T cflag))) ),
                                const 1 32)) ],
       [ zflag_update_exp (Lval (V (reg rd))) ;
         nflag_update_from_reg_exp (reg_from_num rd) ; ]
       @ set_cflag_vflag_after_add_with_carry op2_stmt (UnOp(Not, (Lval (V (reg rn))))) (Lval (V (T cflag))),
      rd = 15
    | 0b1100 -> (* ORR - Rd:= Op1 OR Op2 *)
      [ Set (V (reg rd), BinOp(Or, Lval (V (reg rn)), op2_stmt) ) ],
      [ zflag_update_exp (Lval (V (reg rd))) ;
        nflag_update_from_reg_exp (reg_from_num rd) ]
      @ op2_carry_stmt,
      rd = 15
    | 0b1101 -> (* MOV - Rd:= Op2 *)
      [ Set (V (reg rd), op2_stmt) ],
      [ zflag_update_exp (Lval (V (reg rd))) ;
        nflag_update_from_reg_exp (reg_from_num rd) ]
      @ op2_carry_stmt,
      rd = 15
    | 0b1110 -> (* BIC - Rd:= Op1 AND NOT Op2 *)
      [ Set (V (reg rd), BinOp(And, Lval (V (reg rn)), UnOp(Not, op2_stmt)) ) ],
      [ zflag_update_exp (Lval (V (reg rd))) ;
        nflag_update_from_reg_exp (reg_from_num rd) ]
      @ op2_carry_stmt,
      rd = 15
    | 0b1111 -> (* MVN - Rd:= NOT Op2 *)
      [ Set (V (reg rd), UnOp(Not, op2_stmt)) ],
      [ zflag_update_exp (Lval (V (reg rd))) ;
        nflag_update_from_reg_exp (reg_from_num rd) ]
      @ op2_carry_stmt,
      rd = 15
    | _ -> (* TST/TEQ/CMP/CMN or MRS/MSR *)
       if (instruction land (1 lsl 20)) <> 0 then (* S=1 => TST/TEQ/CMP/CMN *)
         begin
           match opcode with
           | 0b1000 -> (* TST - set condition codes on Op1 AND Op2 *)
              let tmpreg = Register.make (Register.fresh_name ()) 32 in
              [],
              [ Set(V (T tmpreg), BinOp(And, Lval (V (reg rn)), op2_stmt)) ;
                zflag_update_exp (Lval (V (T tmpreg))) ;
                nflag_update_from_reg_exp tmpreg ;
                Directive (Remove tmpreg) ]
              @ op2_carry_stmt,
              false
           | 0b1001 -> (* TEQ - set condition codes on Op1 EOR Op2 *)
              let tmpreg = Register.make (Register.fresh_name ()) 32 in
              [],
              [ Set(V (T tmpreg), BinOp(Xor, Lval (V (reg rn)), op2_stmt)) ;
                zflag_update_exp (Lval (V (T tmpreg))) ;
                nflag_update_from_reg_exp tmpreg ;
                Directive (Remove tmpreg) ]
              @ op2_carry_stmt,
              false
           | 0b1010 -> (* CMP - set condition codes on Op1 - Op2 *)
              let tmpreg = Register.make (Register.fresh_name ()) 33 in
              [],
              [
                Set( V (T tmpreg), BinOp(Add, to33bits (Lval (V (reg rn))),
                                         to33bits(BinOp(Add, UnOp(Not, op2_stmt),
                                                        const 1 32)))) ;
                zflag_update_exp (Lval (V (P (tmpreg, 0, 31)))) ;
                nflag_update_from_reg_exp tmpreg ;
                vflag_update_exp  (Lval (V (reg rn))) (UnOp(Not, op2_stmt)) (Lval (V (P (tmpreg, 0, 31)))) ;
                Set (V (T cflag), Lval (V (P (tmpreg, 32, 32)))) ;
                Directive (Remove tmpreg) ],
              false
           | 0b1011 -> (* CMN - set condition codes on Op1 + Op2 *)
              let tmpreg = Register.make (Register.fresh_name ()) 33 in
              [],
              [ Set( V (T tmpreg), BinOp(Add, to33bits (Lval (V (reg rn))),
                                         to33bits op2_stmt) ) ;
                Set (V (T cflag), Lval (V (P (tmpreg, 32, 32)))) ;
                zflag_update_exp (Lval (V (P (tmpreg, 0, 31)))) ;
                nflag_update_from_reg_exp tmpreg ;
                vflag_update_exp (Lval (V (reg rn))) op2_stmt (Lval (V (P (tmpreg, 0, 31)))) ;
                Directive (Remove tmpreg) ],
              false
           | _ -> L.abort (fun p -> p "unexpected opcode %x" opcode)
         end
       else  (* MRS/MSR *)
         begin
           match (instruction lsr 18) land 0xf with
           | 0b0011 -> (* MRS *)
              if instruction land (1 lsl 22) = 0 then (* Source PSR: 0=CPSR 1=SPSR *)
                [ Set (V (reg rd),
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
                             const 0b10000 32)) ], [], false (* 0b10000 means user mode *)
              else error s.a "MRS from SPSR not supported"
           | 0b1010 -> (* MSR *)
              if instruction land (1 lsl 22) = 0 then (* Source PSR: 0=CPSR 1=SPSR *)
                let zero32 = const 0 32 in
                [ Set (V (T nflag), TernOp(Cmp (EQ, BinOp(And, op2_stmt, const (1 lsl 31) 32), zero32),
                                           const 0 1, const 1 1)) ;
                  Set (V (T zflag), TernOp(Cmp (EQ, BinOp(And, op2_stmt, const (1 lsl 30) 32), zero32),
                                           const 0 1, const 1 1)) ;
                  Set (V (T cflag), TernOp(Cmp (EQ, BinOp(And, op2_stmt, const (1 lsl 29) 32), zero32),
                                           const 0 1, const 1 1)) ;
                  Set (V (T vflag), TernOp(Cmp (EQ, BinOp(And, op2_stmt, const (1 lsl 28) 32), zero32),
                                           const 0 1, const 1 1)) ], [], false
              else error s.a "MSR to SPSR not supported"
           | _ -> error s.a "unknown MSR/MRS opcode"
         end in
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

  let wrap_cc cc stmts =
    [ If (asm_cond cc, stmts, []) ]


  let decode_arm (s: state): Cfa.State.t * Data.Address.t =
    let str = String.sub s.buf 0 4 in
    let instruction = build_instruction s str in
    let stmts = match (instruction lsr 25) land 0x7 with
    | 0b000 ->
       if instruction land 0x0fffffd0 = 0x012fff10 then branch_exchange s instruction
       else if instruction land 0x0fb00ff0 = 0x01000090 then single_data_swap s instruction
       else if instruction land 0x0fc000f0 = 0x00000090 then mul_mla s instruction
       else if instruction land 0x0f8000f0 = 0x08000090 then (* multiply long *) error s.a "mul long"
       else if instruction land 0x0e400f90 = 0x00000090 then (* halfword data transfer, reg *) halfword_data_transfer s instruction
       else if instruction land 0x0e400090 = 0x00400090 then (* halfword data transfer, imm *) halfword_data_transfer s instruction
       else data_proc s instruction
    | 0b001 -> data_proc s instruction
    | 0b010 -> single_data_transfer s instruction
    | 0b011 when instruction land (1 lsl 4) = 0 -> single_data_transfer s instruction
    | 0b100 -> block_data_transfer s instruction (* block data transfer *)
    | 0b101 -> branch s instruction
    | 0b110 -> error s.a (Printf.sprintf "Comprocessor data transfer not implemented (isn=%08x)" instruction)
    | 0b111 when instruction land (1 lsl 24) = 0 -> error s.a (Printf.sprintf "coprocessor operation or register transfer (isn=%08x)" instruction)
    | 0b111 when instruction land (1 lsl 24) <> 0 -> error s.a (Printf.sprintf "software interrupt not implemented (swi=%08x)" instruction)
    | _ -> error s.a (Printf.sprintf "Unknown opcode 0x%x" instruction) in
    let stmts_cc = match (instruction lsr 28) land 0xf with
    | 0xf -> []    (* never *)
    | 0xe -> stmts (* always *)
    | cc -> wrap_cc cc stmts in
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
                          Lval (V (reg i))) in
          stmts := stmt :: (!stmts)
        end
    done;
    (!stmts) @ [ Set (V (T sp), BinOp(Sub, Lval (V (T sp)), const !bitcount 32)) ], []

  let thumb_pop _s isn =
    let reglist = ((isn lsl 7) land 0x8000) lor (isn land 0xff) in (* reglist = bit8:0000000:bit7-0 bit8=r15=pc *)
    let stmts = ref [] in
    let bitcount = ref 0 in
    for i = 0 to 15 do
      if (reglist lsr i) land 1 = 1 then
        begin
          let stmt = Set (V (reg i),
                          Lval (M (BinOp(Add, Lval (V (T sp)), const !bitcount 32), 32))) in
          bitcount := !bitcount+4;
          stmts := stmt :: (!stmts)
        end
    done;
    (!stmts) @ [ Set (V (T sp), BinOp(Add, Lval (V (T sp)), const !bitcount 32)) ], []

  let decode_thumb_it_hints _s isn =
    if isn land 0xf != 0 then (* If-Then*)
      notimplemented "IT"
    else
      match (isn lsr 4) land 0x7 with
      | 0b000 -> (* No Operation hint NOP *)
         notimplemented "hint NOP"
      | 0b001 -> (* Yield hint YIELD *)
         notimplemented "hint YIELD"
      | 0b010 -> (* Wait For Event hint WFE *)
         notimplemented "hint WFE"
      | 0b011 -> (* Wait For Interrupt hint WFI *)
         notimplemented "hint WFI"
      | 0b100 -> (* Send Event hint SEV *)
         notimplemented "hint SEV"
      | _ -> L.abort (fun p -> p "Unkown hint instruction encoding %04x" isn)

  let decode_thumb_misc s isn =
    match (isn lsr 6) land 0x3f with
    | 0b011001 ->
       if (isn lsr 5) land 1 = 0 then (* Set Endianness SETEND *)
         notimplemented "SETEND"
       else (* Change Processor State CPS *)
         notimplemented "CPS"
    | 0b000000 | 0b000001 -> (* Add Immediate to SP ADD (SP plus immediate) *)
       notimplemented "ADD on SP"
    | 0b000010 | 0b000011 -> (* Subtract Immediate from SP SUB (SP minus immediate) *)
       notimplemented "SUB on SP"
    | 0b000100 | 0b000101 | 0b000110 | 0b000111 -> (* Compare and Branch on Zero CBNZ, CBZ *)
       notimplemented "CBZ/CBNZ (0)"
    | 0b001000 -> (* Signed Extend Halfword SXTH *)
       notimplemented "SXTH"
    | 0b001001 -> (* Signed Extend Byte SXTB *)
       notimplemented "SXTB"
    | 0b001010 -> (* Unsigned Extend Halfword UXTH *)
       notimplemented "UXTH"
    | 0b001011 -> (* Unsigned Extend Byte UXTB *)
       notimplemented "UXTB"
    | 0b001100 | 0b001101 | 0b001110 | 0b001111 -> (* Compare and Branch on Zero CBNZ, CBZ *)
       notimplemented "CBNZ/CBZ (1)"
    | 0b010000 | 0b010001 | 0b010010 | 0b010011 | 0b010100 | 0b010101 | 0b010110 | 0b010111 -> (* Push Multiple Registers PUSH *)
       thumb_push s isn
    | 0b100100 | 0b100101 | 0b100110 | 0b100111 -> (* Compare and Branch on Nonzero CBNZ, CBZ *)
       notimplemented "CBNZ/CBZ (2)"
    | 0b101000 -> (* Byte-Reverse Word REV *)
       notimplemented "REV"
    | 0b101001 -> (* Byte-Reverse Packed Halfword REV16 *)
       notimplemented "REV16"
    | 0b101011 -> (* Byte-Reverse Signed Halfword REVSH *)
       notimplemented "REVSH"
    | 0b101100 | 0b101101 | 0b101110 | 0b101111 -> (* Compare and Branch on Nonzero CBNZ, CBZ *)
       notimplemented "CBNZ/CBZ (3)"
    | 0b110000 | 0b110001 | 0b110010 | 0b110011 | 0b110100 | 0b110101 | 0b110110 | 0b110111 -> (* Pop Multiple Registers POP *)
       thumb_pop s isn
    | 0b111000 | 0b111001 | 0b111010 | 0b111011 -> (* Breakpoint BKPT *)
       notimplemented "BKPT"
    | 0b111100 | 0b111101 | 0b111110 | 0b111111 -> (* If-Then and hints *)
       decode_thumb_it_hints s isn
    | _ ->  L.abort (fun p -> p "Unknown thumb misc encoding %04x" isn)


  let thumb_mov_imm _s isn =
    let regnum = (isn lsr 8) land 7 in
    let imm = isn land 0xff in
    [ Set (V (reg regnum), const imm 32) ],
    [ Set (V (T zflag), const (if imm = 0 then 1 else 0) 1) ;
      Set (V (T nflag), const (imm lsr 31) 1) ; ]

  let thumb_cmp_imm _s isn =
    let rn = reg ((isn lsr 8) land 7) in
    let not_imm =  lnot (isn land 0xff) in
    let not_imm32 = const not_imm 32 in
    let not_imm33 = const not_imm 33 in
    let tmpreg = Register.make (Register.fresh_name ()) 33 in
    [ Set (V (T tmpreg),
           BinOp(Add,
                 BinOp(Add, to33bits (Lval (V rn)), not_imm33),
                 to33bits (Lval (V (T cflag))))) ;
      Set (V (T nflag), Lval (V (P (tmpreg, 31, 31)))) ;
      zflag_update_exp (Lval (V (P (tmpreg, 0, 31)))) ;
      Set (V (T cflag), Lval (V (P (tmpreg, 32, 32)))) ;
      vflag_update_exp  (Lval (V rn)) not_imm32 (Lval (V (P (tmpreg, 0, 31)))) ;
    ], []


  let decode_thumb_shift_add_sub_mov_cmp s isn =
    match (isn lsr 11) land 7 with
    | 0b011 ->
       begin
         match (isn lsr 9) land 3 with
         | 0b00 -> (* Add register ADD (register) *)
            notimplemented "ADD (reg)"
         | 0b01 -> (* Subtract register SUB (register) *)
            notimplemented "SUB (reg)"
         | 0b10 -> (* Add 3-bit immediate ADD (immediate, Thumb) *)
            notimplemented "ADD 3 (imm)"
         | 0b11 -> (* Subtract 3-bit immediate SUB (immediate, Thumb) *)
            notimplemented "SUB 3 (imm)"
         | _ -> L.abort (fun p -> p "Unknown encoding %04x" isn)
       end
    | 0b000 -> (* Logical Shift Left LSL (immediate) *)
       notimplemented "LSL (imm)"
    | 0b001 -> (* Logical Shift Right LSR (immediate) *)
       notimplemented "LSR (imm)"
    | 0b010 -> (* Arithmetic Shift Right ASR (immediate) *)
       notimplemented "ASR (imm)"
    | 0b100 -> (* Move MOV (immediate) *)
       thumb_mov_imm s isn
    | 0b101 -> (* Compare CMP (immediate) *)
       thumb_cmp_imm s isn
    | 0b110 -> (* Add 8-bit immediate ADD (immediate, Thumb) *)
       notimplemented "ADD 8 (imm)"
    | 0b111 -> (* Subtract 8-bit immediate SUB (immediate, Thumb) *)
       notimplemented "SUB 8 (imm)"
    | _ -> L.abort (fun p -> p "Unknown encoding %04x" isn)


  let thumb_cond_branching _s isn =
    let cc = (isn lsr 8) land 0xf in
    let imm8 = isn land 0xff in
    let imm32 = (imm8 lsl 24) lsr 23 in (* SignExtend (imm8:'0',32) *)
    let branching = [
        Set (V (T pc), BinOp( Add, Lval (V (T pc)), const imm32 32)) ;
        Jmp (R (Lval (V (T pc)))) ;
      ] in
    [ If (asm_cond cc, branching, [] ) ], []

  let decode_thumb_branching_svcall s isn =
    match isn lsr 8 land 0xf with
    | 0b1110 -> (* Permanently UNDEFINED *)
       L.abort (fun p -> p "Thumb16 instruction %04x permanently undefined" isn)
    | 0b1111 -> (* Supervisor Call *)
       notimplemented "SVC"
    | _ -> (* Conditional branch *)
       thumb_cond_branching s isn


  let decode_thumb (s: state): Cfa.State.t * Data.Address.t =
    let str = String.sub s.buf 0 2 in
    let instruction = build_thumb16_instruction s str in
    let stmts, itdependant_stmts =
      if (instruction lsr 13) land 7 = 0b111 && (instruction lsr 11) land 3 != 0 then
        L.abort (fun p -> p "Thumb 32bit instruction decoding not implemented yet")
      else
        match (instruction lsr 10) land 0x3f with
        | 0b010000 -> (* Data-processing *)
           notimplemented "data processing"
        | 0b010001 -> (* Special data instructions and branch and exchange *)
           notimplemented "special data/branch/exch"
        | 0b010010 | 0b010011 -> (* Load from Literal Pool *)
           notimplemented "load from literal pool"
        | 0b010100 | 0b010101 | 0b010110 | 0b010111 -> (* Load/store single data item *)
           notimplemented "single data item loading/storage"
        | 0b101000 | 0b101001 -> (* Generate PC-relative address *)
           notimplemented "pc-relative address generation"
        | 0b101010 | 0b101011 -> (* Generate SP-relative address *)
           notimplemented "sp-relative address generation"
        | 0b101100 | 0b101101 | 0b101110 | 0b101111 -> (* Miscellaneous 16-bit instructions *)
           decode_thumb_misc s instruction
        | 0b110000 | 0b110001 -> (* Store multiple registers *)
           notimplemented "multiple reg storage"
        | 0b110010 | 0b110011 -> (* Load multiple registers *)
           notimplemented "multiple reg loading"
        | 0b110100 | 0b110101 | 0b110110 | 0b110111 -> (* Conditional branch, and Supervisor Call *)
           decode_thumb_branching_svcall s instruction
        | 0b111000 | 0b111001 -> (* Unconditional Branch *)
           notimplemented "unconditional branching"
        | _ ->
           if (instruction lsr 14) land 3 = 0 then
             (* Shift (immediate), add, subtract, move, and compare *)
             decode_thumb_shift_add_sub_mov_cmp s instruction
           else
             L.abort (fun p -> p "Unknown thumb encoding %04x" instruction) in
    (* pc is 4 bytes ahead in thumb mode because of pre-fetching. *)
    let current_pc = Const (Word.of_int (Z.add (Address.to_int s.a) (Z.of_int 4)) 32) in
    let stmts1,stmts2 =
      match s.itstate with
      | None -> L.abort (fun p -> p "Could not obtain a concrete ITSTATE value. Decoding not supported yet in this case")
      | Some v ->
         if (v land 0xf) = 0
         then stmts, itdependant_stmts
         else L.abort (fun p -> p "ITSTATE management not supported yet") in
    return s instruction (Set( V (T pc), current_pc) :: stmts1 @ stmts2)

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


  let init () =
    Imports.init ()

end
