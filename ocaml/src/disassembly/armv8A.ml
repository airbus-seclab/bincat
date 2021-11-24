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
   Decoder for ARMv8-A 64-bits
   Implements the specification https://static.docs.arm.com/ddi0487/b/DDI0487B_a_armv8_arm.pdf
*)
module L = Log.Make(struct let name = "armv8A" end)

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
  let x0 = Register.make ~name:"x0" ~size:64;;
  let x1 = Register.make ~name:"x1" ~size:64;;
  let x2 = Register.make ~name:"x2" ~size:64;;
  let x3 = Register.make ~name:"x3" ~size:64;;
  let x4 = Register.make ~name:"x4" ~size:64;;
  let x5 = Register.make ~name:"x5" ~size:64;;
  let x6 = Register.make ~name:"x6" ~size:64;;
  let x7 = Register.make ~name:"x7" ~size:64;;
  let x8 = Register.make ~name:"x8" ~size:64;;
  let x9 = Register.make ~name:"x9" ~size:64;;
  let x10 = Register.make ~name:"x10" ~size:64;;
  let x11 = Register.make ~name:"x11" ~size:64;;
  let x12 = Register.make ~name:"x12" ~size:64;;
  let x13 = Register.make ~name:"x13" ~size:64;;
  let x14 = Register.make ~name:"x15" ~size:64;;
  let x15 = Register.make ~name:"x14" ~size:64;;
  let x16 = Register.make ~name:"x16" ~size:64;;
  let x17 = Register.make ~name:"x17" ~size:64;;
  let x18 = Register.make ~name:"x18" ~size:64;;
  let x19 = Register.make ~name:"x19" ~size:64;;
  let x20 = Register.make ~name:"x20" ~size:64;;
  let x21 = Register.make ~name:"x21" ~size:64;;
  let x22 = Register.make ~name:"x22" ~size:64;;
  let x23 = Register.make ~name:"x23" ~size:64;;
  let x24 = Register.make ~name:"x24" ~size:64;;
  let x25 = Register.make ~name:"x25" ~size:64;;
  let x26 = Register.make ~name:"x26" ~size:64;;
  let x27 = Register.make ~name:"x27" ~size:64;;
  let x28 = Register.make ~name:"x28" ~size:64;;
  let x29 = Register.make ~name:"x29" ~size:64;;
  let x30 = Register.make ~name:"x30" ~size:64;;
  let xzr = Register.make ~name:"xzr" ~size:64;; (* Zero register *)
  let pc = Register.make ~name:"pc" ~size:64;; (* instruction pointer *)
  let sp = Register.make ~name:"sp" ~size:64;; (* stack pointer *)

  (* condition flags are modeled as registers of size 1 *)
  let nflag = Register.make ~name:"n" ~size:1;;
  let zflag = Register.make ~name:"z" ~size:1;;
  let cflag = Register.make ~name:"c" ~size:1;;
  let vflag = Register.make ~name:"v" ~size:1;;

  (* SIMD/FP registers *)
  (* SIMD register Qx      [................] 128 bits *)
  (* Double precision Dx   [xxxxxxxx........]  64 bits *)
  (* Single precision Sx   [xxxxxxxxxxxx....]  32 bits *)
  (* Half precision Hx     [xxxxxxxxxxxxxx..]  16 bits *)
  (* byte Bx               [xxxxxxxxxxxxxxx.]   8 bits *)
  let q0 = Register.make ~name:"q0" ~size:128;;
  let q1 = Register.make ~name:"q1" ~size:128;;
  let q2 = Register.make ~name:"q2" ~size:128;;
  let q3 = Register.make ~name:"q3" ~size:128;;
  let q4 = Register.make ~name:"q4" ~size:128;;
  let q5 = Register.make ~name:"q5" ~size:128;;
  let q6 = Register.make ~name:"q6" ~size:128;;
  let q7 = Register.make ~name:"q7" ~size:128;;
  let q8 = Register.make ~name:"q8" ~size:128;;
  let q9 = Register.make ~name:"q9" ~size:128;;
  let q10 = Register.make ~name:"q10" ~size:128;;
  let q11 = Register.make ~name:"q11" ~size:128;;
  let q12 = Register.make ~name:"q12" ~size:128;;
  let q13 = Register.make ~name:"q13" ~size:128;;
  let q14 = Register.make ~name:"q15" ~size:128;;
  let q15 = Register.make ~name:"q14" ~size:128;;
  let q16 = Register.make ~name:"q16" ~size:128;;
  let q17 = Register.make ~name:"q17" ~size:128;;
  let q18 = Register.make ~name:"q18" ~size:128;;
  let q19 = Register.make ~name:"q19" ~size:128;;
  let q20 = Register.make ~name:"q20" ~size:128;;
  let q21 = Register.make ~name:"q21" ~size:128;;
  let q22 = Register.make ~name:"q22" ~size:128;;
  let q23 = Register.make ~name:"q23" ~size:128;;
  let q24 = Register.make ~name:"q24" ~size:128;;
  let q25 = Register.make ~name:"q25" ~size:128;;
  let q26 = Register.make ~name:"q26" ~size:128;;
  let q27 = Register.make ~name:"q27" ~size:128;;
  let q28 = Register.make ~name:"q28" ~size:128;;
  let q29 = Register.make ~name:"q29" ~size:128;;
  let q30 = Register.make ~name:"q30" ~size:128;;
  let q31 = Register.make ~name:"q31" ~size:128;;

  let nf_v = V( T(nflag) )
  let zf_v = V( T(zflag) )
  let cf_v = V( T(cflag) )
  let vf_v = V( T(vflag) )

  let nf_lv = Lval ( V( T(nflag) ) )
  let zf_lv = Lval ( V( T(zflag) ) )
  let cf_lv = Lval ( V( T(cflag) ) )
  let vf_lv = Lval ( V( T(vflag) ) )

  let reg_from_num n =
    match n with
    | 0 -> x0   | 1 -> x1   | 2 -> x2   | 3 -> x3   | 4 -> x4   | 5 -> x5   | 6 -> x6   | 7 -> x7
    | 8 -> x8   | 9 -> x9   | 10 -> x10 | 11 -> x11 | 12 -> x12 | 13 -> x13 | 14 -> x14 | 15 -> x15
    | 16 -> x16 | 17 -> x17 | 18 -> x18 | 19 -> x19 | 20 -> x20 | 21 -> x21 | 22 -> x22 | 23 -> x23
    | 24 -> x24 | 25 -> x25 | 26 -> x26 | 27 -> x27 | 28 -> x28 | 29 -> x29 | 30 -> x30 | 31 -> sp
    | _ -> L.abort (fun p -> p "Unknown register number %i" n)

  let qreg_from_num n =
    match n with
    | 0 -> q0   | 1 -> q1   | 2 -> q2   | 3 -> q3   | 4 -> q4   | 5 -> q5   | 6 -> q6   | 7 -> q7
    | 8 -> q8   | 9 -> q9   | 10 -> q10 | 11 -> q11 | 12 -> q12 | 13 -> q13 | 14 -> q14 | 15 -> q15
    | 16 -> q16 | 17 -> q17 | 18 -> q18 | 19 -> q19 | 20 -> q20 | 21 -> q21 | 22 -> q22 | 23 -> q23
    | 24 -> q24 | 25 -> q25 | 26 -> q26 | 27 -> q27 | 28 -> q28 | 29 -> q29 | 30 -> q30 | 31 -> sp
    | _ -> L.abort (fun p -> p "Unknown register number %i" n)

  let reg n =
    T (reg_from_num n)

  let wreg n =
    P ((reg_from_num n), 0, 31)

  let qreg n =
    T (qreg_from_num n)

  let sreg n =
    P ((qreg_from_num n), 0, 31)

  (* helper to get register with the right size according to sf value *)
  (* 1 is 64 bits *)
  let reg_sf n sf =
    if sf = 1 then
      T (reg_from_num n)
    else
      P (reg_from_num n, 0, 31)

  module Cfa = Cfa.Make(Domain)
               
  module Imports = Armv8aImports.Make(Domain)(Stubs)

  type state = {
    mutable g       : Cfa.t;       (** current cfa *)
    mutable b       : Cfa.State.t; (** state predecessor *)
    a               : Address.t;   (** current address to decode *)
    buf             : string;      (** buffer to decode *)
  }

  (* fatal error reporting *)
  let error a msg =
    L.abort (fun p -> p "at %s: %s" (Address.to_string a) msg)

  

  let build_instruction (str: string): int =
    (Char.code (String.get str 0))
    lor ((Char.code (String.get str 1)) lsl 8)
    lor ((Char.code (String.get str 2)) lsl 16)
    lor ((Char.code (String.get str 3)) lsl 24)

  let return (s: state) (str: string) (stmts: Asm.stmt list): Cfa.State.t * Data.Address.t =
    s.b.Cfa.State.stmts <- stmts;
    s.b.Cfa.State.bytes <- string_to_char_list str;
    s.b, Data.Address.add_offset s.a (Z.of_int 4)

  (******************************)
  (* Instruction fields helpers *)
  (******************************)
  let sf2sz sf = if sf = 1 then 64 else 32

  (* sf : 32 bit or 64 bits ops *)
  let get_sf insn =
    let sf = (insn lsr 31) land 1 in
    (sf, sf2sz sf)

  (* Note about use_sp: register number 31 can mean 2 differents things:
        - the "zero" register, which always reads "0" and discards writes
        - SP (stack pointer)
     pass ~use_sp:true to use the stack pointer
  *)
  let get_reg_lv ?(use_sp = false) num sf =
    if num = 31 && not use_sp then (* zero register *)
      (* XXX see how we can discard the result *)
      V (T(xzr))
    else
      V (reg_sf num sf)

  let get_reg_exp ?(use_sp = false) num sf =
    if num = 31 && not use_sp then (* zero register *)
      const0 (sf2sz sf)
    else
      Lval (V (reg_sf num sf))

  (* helper for destination register, if we have XZR as dest, we generate
   * a temporary register and return a pair *)
  let get_Rd_lv ?(use_sp = false) insn sf =
    let num = (insn land 0x1F) in
    if num = 31 && not use_sp then begin
      L.debug (fun p->p "write to XZR");
      let tmp = Register.make (Register.fresh_name ()) (sf2sz sf) in
      V(T(tmp)), [Directive(Remove(tmp))]
    end else
      V(reg_sf num sf), []

  (* shift *)
  let get_shifted_imm s shift imm sz =
    match shift with
    | 0b10 | 0b11 -> error s.a (Printf.sprintf "Reserved shift value 0x%x" shift)
    | 0b00 -> const imm sz
    | 0b01 -> const (imm lsl 12) sz
    | _ -> error s.a "Impossible error !"

  (******************************)
  (* Common IL generation       *)
  (******************************)

  let ror sz reg count =
    let sz_exp = const sz sz in
    let count_ext = UnOp(ZeroExt sz, count) in
    let count_mod = BinOp(Mod, count_ext, sz_exp) in
    let inv_count_mod = BinOp (Sub, sz_exp, count_mod) in
    let low = BinOp (Shr, reg, count_mod)  in
    let high = BinOp (Shl, reg, inv_count_mod) in
    let res = BinOp (Or, high, low) in
    res

  let get_shifted_reg sz insn reg amount =
    if amount = 0 then
      reg
    else
      let shift = (insn lsr 22) land 3 in
      match shift with
      | 0b00 (* LSL *) -> BinOp(Shl, reg, const amount sz)
      | 0b01 (* LSR *) -> BinOp(Shr, reg, const amount sz)
      | 0b10 (* ASR XXX *) -> L.abort (fun p->p "shifted reg with ASR not implemented yet");
      | 0b11 (* ROR *) -> ror sz reg (const amount sz)
      | _ -> L.abort (fun p->p "Invalid value for shift")

  (* 32 bits ops zero the top 32 bits, this helper does it if needed *)
  let sf_zero_rd rd_v sf s_b =
    (* don't zero if the target is discarded (set flags or XZR) *)
    if sf = 0 && (not s_b || rd_v != 31) then begin
      let rd_top = P(reg_from_num rd_v, 32, 63) in
      [Set ( V(rd_top), const 0 32)]
    end else []

  (* compute n z and set c v flags for value in reg *)
  let flags_stmts sz reg cf vf =
    (* NF: negative flag, check MSB of reg,
       ZF: zero flag, is reg zero ?,
       CF: carry flag,
       VF: Overflow flag
    *)
    [ Set ( nf_v, TernOp(Cmp(EQ, (msb_expr reg sz), const1 sz), const1 1, const0 1));
      Set ( zf_v, TernOp(Cmp(EQ, reg, const0 sz), const1 1, const0 1));
      (* XXX do CF and VF *)
      Set ( cf_v, cf);
      Set ( vf_v, vf)]


  let ror_int value size amount =
    let mask = Z.sub (Z.shift_left Z.one (size-amount)) Z.one in
    let v_sr = Z.logand (Z.shift_right value amount) mask in
    let v_sl = Z.shift_left (Z.logand value (Z.sub (Z.shift_left Z.one amount) Z.one)) (size-amount) in
    Z.logor v_sr v_sl

  let replicate_z (value:Z.t) size final_size =
    if final_size mod size != 0 then
      L.abort (fun p->p "Invalid replicate params %s %x %x" (Z.to_string value) size final_size);
    let res = ref Z.zero in
    for i = 0 to (final_size/size-1) do
      res :=  Z.logor !res (Z.shift_left value (size * i));
    done;
    !res

  let rec log2 n =
    if n <= 1 then 0 else 1 + log2(n asr 1)

  let decode_bitmasks sz n imms immr =
    L.debug (fun p->p "decode_bitmask(%d,%d,%x,%x)" sz n imms immr);
    (*// Compute log2 of element size
      // 2^len must be in range [2, M]
      len = HighestSetBit(immN:NOT(imms));*)
    let len = log2 (((n lsl 6) lor ((lnot imms) land 0x3F)) land 0x7F) in
    L.debug (fun p->p "decode_bitmask: len= %d" len);
    let levels = (1 lsl len)-1 in
    let s = imms land levels in
    let r = immr land levels in
    L.debug (fun p->p "decode_bitmask: S=%x R=%x" s r);
    let diff = (s-r) land 0x3F in
    (*
       // From a software perspective, the remaining code is equivalant to:
        //   esize = 1 << len;
        //   d = UInt(diff<len-1:0>);
        //   welem = ZeroExtend(Ones(S + 1), esize);
        //   telem = ZeroExtend(Ones(d + 1), esize);
        //   wmask = Replicate(ROR(welem, R));
        //   tmask = Replicate(telem);
        //   return (wmask, tmask);
     *)
    let esize = 1 lsl len in
    let welem = z_mask_ff (s+1) in
    let telem = z_mask_ff (diff+1) in
    let wmask_t = ror_int welem esize r in
    let wmask = replicate_z wmask_t esize sz in
    let tmask = replicate_z telem esize sz in
    L.debug (fun p->p "decode_bitmask: esize=%d diff=%d welem=%s telem=%s wmask_t=%s wmask=%s tmask=%s" esize diff (Z.format "%x" welem) (Z.format "%x" telem) (Z.format "%x" wmask_t) (Z.format "%x" wmask) (Z.format "%x" tmask));
    wmask, tmask

  let extend_reg sz reg ext_type shift =
    let len = match ext_type with
      | 0 -> 8
      | 1 -> 16
      | 2 -> 32
      | 3 -> 64
      | 4 -> 8
      | 5 -> 16
      | 6 -> 32
      | 7 -> 64
      | _ -> L.abort(fun p->p "invalid shift")
    in
    let len' = min len (sz-shift) in
    let ext_op = match ext_type with
      | 0 | 1 | 2 | 3 -> ZeroExt sz
      | 4 | 5 | 6 | 7 -> SignExt sz
      | _ -> L.abort(fun p->p "invalid shift")
    in
    BinOp(Shl, UnOp(ext_op, Lval( V( P(reg_from_num reg, 0, len'-1)))), const shift len)
  (*if shift < 0 || shift > 4 then
      L.abort (fun p->p "Invalid shift value for extend_reg")
    else*)

  (******************************)
  (* Actual instruction decoder *)
  (******************************)

  (* Helper for ADD/SUB *)
  let add_sub_core sz dst op1 op op2 set_flags =
    let op_s = if op = 0 then Add else Sub in
    let core_stmts =
      [ Set (dst, BinOp(op_s, op1, op2)) ]
    in
    (* flags ? *)
    if set_flags then begin
      (* ARMv8 implements "sub" with
       * operand2 = NOT(imm);
       * (result, -) = AddWithCarry(operand1, operand2, '1');*
       * so we emulate this behaviour
      *)
      let op2' = if op = 1 (*sub*) then BinOp(Add, UnOp(Not, op2), const1 sz) else op2 in
      let cf = carry_stmts sz op1 Add op2' in
      let vf = overflow_stmts sz (Lval dst) op1 op_s op2 in
      core_stmts @ (flags_stmts sz (Lval dst) cf vf)
    end else
      core_stmts

  (* ADD/ ADDS / SUB / SUBS (32/64) with immediate *)
  let add_sub_imm s insn sf =
    let%decode insn' = insn "31:31:sf:F:0,30:30:op:F:0,29:29:S:F:0,28:24:_:F:10001,23:22:shift:F:xx,21:10:imm12:F:xxxxxxxxxxxx,9:5:Rn:F:xxxxx,4:0:Rd:F:xxxxx" in
    let s_b = s_v = 1 in (* set flags ? *)
    let sz = sf2sz sf_v in
    let shift = get_shifted_imm s shift_v imm12_v sz in
    let rd, post = get_Rd_lv ~use_sp:(not s_b) rd_v sf_v in
    let rn = get_reg_exp ~use_sp:true rn_v sf in
    (add_sub_core sz rd rn op_v shift s_b @ sf_zero_rd rd_v sf s_b) @ post

  (* ADD/ ADDS / SUB / SUBS (32/64) with extended register *)
  let add_sub_reg_ext insn =
    let%decode insn' = insn "31:31:sf:F:0,30:30:op:F:1,29:29:S:F:1,28:24:_:F:01011,23:22:_opt:F:00,21:21:_:F:1,20:16:Rm:F:xxxxx,15:13:option:F:xxx,12:10:imm3:F:xxx,9:5:Rn:F:xxxxx,4:0:Rd:F:xxxxx" in
    let sz = sf2sz sf_v in
    let s_b = s_v = 1 in (* set flags ? *)
    let rd, post = get_Rd_lv rd_v sf_v in
    let rn = get_reg_exp rn_v sf_v in
    let extended_reg =  extend_reg sz rm_v option_v imm3_v in
    (add_sub_core sz rd rn op_v extended_reg s_b @ sf_zero_rd rd_v sf_v s_b) @ post

  (* ADD/ ADDS / SUB / SUBS (32/64) with shifted register *)
  let add_sub_reg_shift s insn =
    let%decode insn' = insn "31:31:sf:F:0,30:30:op:F:0,29:29:S:F:0,28:24:_:F:01011,23:22:shift:F:xx,21:21:_:F:0,20:16:Rm:F:xxxxx,15:10:imm6:F:xxxxxx,9:5:Rn:F:xxxxx,4:0:Rd:F:xxxxx" in
    if (sf_v = 0 && (imm6_v lsr 5) = 1) || (shift_v = 3) then
      (error s.a (Printf.sprintf "Invalid opcode 0x%x" insn));
    let sz = sf2sz sf_v in
    let s_b = s_v = 1 in (* set flags ? *)
    let rd, post = get_Rd_lv rd_v sf_v in
    let rn = get_reg_exp rn_v sf_v in
    let rm = get_reg_exp rm_v sf_v in
    let shifted_rm =  get_shifted_reg sz insn rm imm6_v in
    (add_sub_core sz rd rn op_v shifted_rm s_b @ sf_zero_rd rd_v sf_v s_b) @ post

  (* AND / ORR / EOR / ANDS (32/64) core *)
  let logic_core sz dst op1 opc op2 set_flags =
    let op = match opc with
      | 0b00 | 0b11 -> And
      | 0b01 -> Or
      | 0b10 -> Xor
      | _ -> L.abort (fun p->p "Impossible error in logic_core!") in
    let core_stmts =
      [ Set (dst, BinOp(op, op1, op2)) ]
    in
    if set_flags then begin
      let cf = carry_stmts sz op1 op op2 in
      let vf = overflow_stmts sz (Lval dst) op1 op op2 in
      core_stmts @ (flags_stmts sz (Lval dst) cf vf)
    end else
      core_stmts

  (* AND / ORR / EOR / ANDS (32/64) with immediate *)
  let logic_imm s insn =
    let%decode insn' = insn "31:31:sf:F:0,30:29:opc:F:00,28:23:_:F:100100,22:22:N:F:0,21:16:immr:F:xxxxxx,15:10:imms:F:xxxxxx,9:5:Rn:F:xxxxx,4:0:Rd:F:xxxxx" in
    if sf_v = 0 && n_v = 1 then (error s.a (Printf.sprintf "Invalid opcode 0x%x" insn));
    let sz = sf2sz sf_v in
    let flags = opc_v = 3 in
    let rd, post = get_Rd_lv ~use_sp:(not flags) rd_v sf_v in
    let rn = get_reg_exp rn_v sf_v in
    let imm_res, _ = decode_bitmasks sz n_v imms_v immr_v in
    logic_core sz rd rn opc_v (Const(Word.of_int imm_res sz)) flags @ sf_zero_rd rd_v sf_v (not flags) @ post

  (* AND / ORR / EOR / ANDS (32/64) with shifted register *)
  let logic_reg s insn =
    let%decode insn' = insn "31:31:sf:F:0,30:29:opc:F:00,28:24:_:F:01010,23:22:_shift:F:xx,21:21:N:F:0,20:16:Rm:F:xxxxx,15:10:imm6:F:xxxxxx,9:5:Rn:F:xxxxx,4:0:Rd:F:xxxxx " in
    let sz = sf2sz sf_v in
    if sf_v = 0 && (imm6_v lsr 5) = 1 then
      (error s.a (Printf.sprintf "Invalid opcode 0x%x" insn));
    let flags = opc_v = 3 in
    let rd, post = get_Rd_lv ~use_sp:(not flags) rd_v sf_v in
    let rn = get_reg_exp rn_v sf_v in
    let rm = get_reg_exp rm_v sf_v in
    let shifted_rm = get_shifted_reg sz insn rm imm6_v in
    let shifted_rm' = if n_v = 1 then UnOp(Not, shifted_rm) else shifted_rm in
    logic_core sz rd rn opc_v shifted_rm' flags @ sf_zero_rd rd_v sf_v (not flags) @ post

  (* MOVZ move immediate with optional shift *)
  let mov_wide s insn =
    let%decode insn' = insn "31:31:sf:F:0,30:29:opc:F:11,28:23:_:F:100101,22:21:hw:F:xx,20:5:imm16:F:xxxxxxxxxxxxxxxx,4:0:Rd:F:xxxxx" in
    let sz = sf2sz sf_v in
    if (sf_v = 0 && hw_v > 1) || (opc_v = 0b01) then error s.a (Printf.sprintf "Invalid opcode 0x%x" insn);
    let rd = get_reg_lv rd_v sf_v in
    let shift = hw_v lsl 4 in
    let imm_c = if shift > 0 then Const (Word.of_int (Z.shift_left (Z.of_int imm16_v) shift) sz) else const imm16_v sz in
    L.debug (fun p->p "mov_wide: opc:%x sz:%d shift:%d imm16:%x " opc_v sz shift imm16_v );
    L.debug (fun p->p "mov_wide: imm_c=%s" (Asm.string_of_exp imm_c true));
    let imm_f = match opc_v with
      | 0b00 -> (* MOVN *) UnOp(Not, imm_c)
      | 0b10 -> (* MOVZ *) UnOp(ZeroExt sz, imm_c)
      | 0b11 -> (* MOVK *)
        (* compute 0x...FFFF0000 mask *)
        let mask = Z.logxor (Z.sub (Z.shift_left Z.one sz) Z.one) (Z.of_int (0xFFFF lsl shift)) in
        (* only replace the bits corresponsding to imm in the destination *)
        BinOp(Or, BinOp(And, Lval(rd), Const (Word.of_int mask sz)), imm_c)
      | _ -> error s.a "Impossible error"; in

    [ Set (rd, imm_f) ] @ sf_zero_rd rd_v sf_v false

  (* ADR/ADRP *)
  let pc_rel_addr s insn _sf =
    let op = (insn lsr 31) land 1 in
    let immlo = (insn lsr 29) land 3 in
    let immhi = (insn lsr 5) land 0x7ffff in
    let imm = (immhi lsl 2) lor immlo in
    (* destination is always 64 bits *)
    let rd, post = get_Rd_lv  insn 1 in
    (* pc is 8 bytes ahead because of pre-fetching. *)
    let current_pc = Z.add (Address.to_int s.a) (Z.of_int 8) in
    let base, imm_ext =
      if op = 0 then (* ADR *)
        Word.of_int current_pc 64, UnOp(SignExt 64, const imm 21)
      else (* ADRP: base is PC aligned to 4k boundaries *)
        Word.of_int (Z.logand current_pc (Z.shift_left (Z.of_int 0xFFFFFFFFFFFFF) 12)) 64,
        UnOp(SignExt 64, const (imm lsl 12) (21+12))
    in
    [ Set(rd, BinOp(Add, Const base, imm_ext))] @ post
(*
BFM <31:31:sf:F:0,30:29:opc:F:01,28:23:_:F:100110,22:22:N:F:0,21:16:immr:F:xxxxxx,15:10:imms:F:xxxxxx,9:5:Rn:F:xxxxx,4:0:Rd:F:xxxxx> Bitfield Move
SBFM <31:31:sf:F:0,30:29:opc:F:00,28:23:_:F:100110,22:22:N:F:0,21:16:immr:F:xxxxxx,15:10:imms:F:xxxxxx,9:5:Rn:F:xxxxx,4:0:Rd:F:xxxxx> Signed Bitfield Move
UBFM <31:31:sf:F:0,30:29:opc:F:10,28:23:_:F:100110,22:22:N:F:0,21:16:immr:F:xxxxxx,15:10:imms:F:xxxxxx,9:5:Rn:F:xxxxx,4:0:Rd:F:xxxxx> Unsigned Bitfield Move
*)
  let bitfield insn =
    let%decode insn' = insn "31:31:sf:F:0,30:29:opc:F:10,28:23:_:F:100110,22:22:N:F:0,21:16:immr:F:xxxxxx,15:10:imms:F:xxxxxx,9:5:Rn:F:xxxxx,4:0:Rd:F:xxxxx" in
    let sz = sf2sz sf_v in
    let wmask, tmask = decode_bitmasks sz n_v imms_v immr_v in
    let rn = get_reg_lv rn_v sf_v in
    let rd = get_reg_lv rd_v sf_v in
    let rored = if immr_v = 0 then (Lval rn) else ror sz (Lval rn) (const immr_v 6) in
    let res = match opc_v with
      | 2 -> begin (* UBFM *)
          (* bits(datasize) bot = ROR(src, R) AND wmask;
             X[d] = bot AND tmask; *)
          [Set(rd, BinOp(And, BinOp(And, rored,  Const(Word.of_int wmask sz)), Const(Word.of_int tmask sz)))]
        end
      | 1 -> begin (* BFM *)
          (*  (dst AND NOT(wmask)) OR (ROR(src, R) AND wmask); *)
          let bot = BinOp(Or, BinOp(And, Lval rn, UnOp(Not, Const(Word.of_int wmask sz))), BinOp(And, rored, Const(Word.of_int wmask sz))) in
          [ Set(rd, BinOp(Or, BinOp(And, Lval rn, UnOp(Not, Const(Word.of_int tmask sz))), BinOp(And, bot, Const(Word.of_int tmask sz))))]
        end
      | 0 -> begin (* SBFM *)
          let src_s = BinOp(And, const1 sz, BinOp(Shr, Lval rn, const imms_v sz)) in
          let top = TernOp(Cmp(EQ, src_s, const1 sz), const_of_Z (z_mask_ff sz) sz, const0 sz) in
          (* (top AND NOT(tmask)) OR (bot AND tmask); *)
          [Set(rd, BinOp(Or, BinOp(And, top, UnOp(Not, Const(Word.of_int tmask sz))), BinOp(And, rored, Const(Word.of_int tmask sz))))]
        end
      | _ -> L.abort (fun p->p "BFM/SBFM not handled yet")
    in
    res @ sf_zero_rd rd_v sf_v false

  (* EXTR *)
  let extr insn =
    let%decode insn' = insn "31:31:sf:F:0,30:29:_op21:F:00,28:23:_:F:100111,22:22:_N:F:0,21:21:o0:F:0,20:16:Rm:F:xxxxx,15:10:imms:F:0xxxxx,9:5:Rn:F:xxxxx,4:0:Rd:F:xxxxx" in
    let sz = sf2sz sf_v in
    let rn = get_reg_lv rn_v sf_v in
    let rm = get_reg_lv rm_v sf_v in
    let rd = get_reg_lv rd_v sf_v in
    let tmp = Register.make (Register.fresh_name ()) (2*sz) in
    let tmp_v = V(T(tmp)) in
    [ Set(tmp_v, UnOp(ZeroExt (sz*2),Lval rn)); Set(tmp_v, BinOp(Or, BinOp(Shl, Lval tmp_v, const sz (sz*2)), UnOp(ZeroExt (sz*2), Lval rm)));
      Set(rd, Lval(V(P(tmp, imms_v, imms_v+sz-1)))); Directive(Remove tmp)]


  (* data processing with immediates *)
  let data_processing_imm (s: state) (insn: int): (Asm.stmt list) =
    let op0 = (insn lsr 23) land 7 in
    let sf, _ = get_sf insn in
    let stmts = match op0 with
      | 0b000 | 0b001 -> pc_rel_addr s insn sf
      | 0b010 | 0b011 -> add_sub_imm s insn sf
      | 0b100         -> logic_imm s insn
      | 0b101 -> mov_wide s insn
      | 0b110 -> bitfield insn
      | 0b111 -> extr insn
      | _ -> error s.a (Printf.sprintf "Unknown opcode 0x%x" insn)
    in stmts

  let data_proc_2src s insn =
    (* XXX *)
    error s.a (Printf.sprintf "Data processing (2 sources) not decoded yet (0x%x)" insn)

  let data_proc_1src s insn =
    (* XXX *)
    error s.a (Printf.sprintf "Data processing (1 source) not decoded yet (0x%x)" insn)

  (*
MADD   <31:31:sf:0  30:29:op54:00  28:24:_:11011  23:21:op31:000         20:16:Rm:  15:15:o0:0  14:10:Ra:  9:5:Rn:  4:0:Rd:> Multiply-Add
MSUB   <31:31:sf:0  30:29:op54:00  28:24:_:11011  23:21:op31:000         20:16:Rm:  15:15:o0:1  14:10:Ra:  9:5:Rn:  4:0:Rd:> Multiply-Subtract
SMADDL <31:31:sf:1  30:29:op54:00  28:24:_:11011  23:23:U:0  22:21:_:01  20:16:Rm:  15:15:o0:0  14:10:Ra:  9:5:Rn:  4:0:Rd:> Signed Multiply-Add Long
SMSUBL <31:31:sf:1  30:29:op54:00  28:24:_:11011  23:23:U:0  22:21:_:01  20:16:Rm:  15:15:o0:1  14:10:Ra:  9:5:Rn:  4:0:Rd:> Signed Multiply-Subtract Long
UMADDL <31:31:sf:1  30:29:op54:00  28:24:_:11011  23:23:U:1  22:21:_:01  20:16:Rm:  15:15:o0:0  14:10:Ra:  9:5:Rn:  4:0:Rd:> Unsigned Multiply-Add Long
UMSUBL <31:31:sf:1  30:29:op54:00  28:24:_:11011  23:23:U:1  22:21:_:01  20:16:Rm:  15:15:o0:1  14:10:Ra:  9:5:Rn:  4:0:Rd:> Unsigned Multiply-Subtract Long
SMULH  <31:31:sf:1  30:29:op54:00  28:24:_:11011  23:23:U:0  22:21:_:10  20:16:Rm:  15:15:o0:0  14:10:Ra:  9:5:Rn:  4:0:Rd:> Signed Multiply High
UMULH  <31:31:sf:1  30:29:op54:00  28:24:_:11011  23:23:U:1  22:21:_:10  20:16:Rm:  15:15:o0:0  14:10:Ra:  9:5:Rn:  4:0:Rd:> Unsigned Multiply High
*)
  let data_proc_3src s insn =
    let%decode insn' = insn "31:31:sf:F:0,30:29:_op54:F:00,28:24:_:F:11011,23:21:op31:F:000,20:16:Rm:F:xxxxx,15:15:o0:F:1,14:10:Ra:F:xxxxx,9:5:Rn:F:xxxxx,4:0:Rd:F:xxxxx" in
    let op = if o0_v = 0 then Add else Sub in
    if sf_v = 0 && (op31_v != 0) then
      error s.a (Printf.sprintf "invalid instruction 0x%x" insn);
    let sz = sf2sz sf_v in
    let tmp = Register.make (Register.fresh_name ()) (sz*2) in
    let u_v = op31_v lsr 2 in
    match op31_v with
    | 0 ->
      (* MADD / MSUB *)
      let rd = get_reg_lv rd_v sf_v in
      let rn = get_reg_exp rn_v sf_v in
      let rm = get_reg_exp rm_v sf_v in
      let ra = get_reg_exp ra_v sf_v in
      [ Set(V(T(tmp)), BinOp(op, UnOp(ZeroExt (sz*2), ra), BinOp(Mul, rn, rm)));
        Set(rd, Lval(V(P(tmp, 0, sz-1))));
        Directive(Remove tmp) ]
    | 2 | 6 ->
      (* [US]MULH *)
      let rd = get_reg_lv rd_v 1 in
      let rn = get_reg_exp rn_v 1 in
      let rm = get_reg_exp rm_v 1 in
      [ Set(V(T(tmp)), if u_v = 1 then BinOp(Mul, rn, rm) else BinOp(IMul, rn, rm));
        Set(rd, Lval(V(P(tmp, sz, sz*2-1))));
        Directive(Remove tmp) ]
    | _ ->
      (* [US]M(ADD|SUB)L *)
      let rd = get_reg_lv rd_v 1 in
      let rn = get_reg_exp rn_v 0 in
      let rm = get_reg_exp rm_v 0 in
      let ra = get_reg_exp ra_v 1 in
      [ Set(V(T(tmp)), BinOp(op, ra, if u_v = 1 then BinOp(Mul, rn, rm) else BinOp(IMul, rn, rm)));
        Set(rd, Lval(V(P(tmp, sz, 64))));
        Directive(Remove tmp) ]

  (* data processing with registers *)
  let data_processing_reg (s: state) (insn: int): (Asm.stmt list) =
    let op0 = (insn lsr 30) land 1 in
    let op1 = (insn lsr 28) land 1 in
    let op2 = (insn lsr 21) land 0b1111 in
    L.debug (fun p -> p "data_processing_reg: op0=%d op1=%d op2=0x%x" op0 op1 op2);
    if op1 = 1 && op2 = 0b0110 then begin
      if op0 = 0 then
        data_proc_2src s insn
      else
        data_proc_1src s insn
    end
    else begin
      if op1 = 0 then
        (* op2 = 0xxx *)
        if (op2 lsr 3) = 0 then
          logic_reg s insn
        else begin (* op2 = 1xxx : shifted / extended register *)
          if (op2 land 1) = 0 then (* shifted *)
            add_sub_reg_shift s insn
          else (* extended *)
            add_sub_reg_ext insn
        end
      else
        match op2 with
        | 0 -> error s.a (Printf.sprintf "ADD/SUB with carry not decoded yet (0x%x)" insn)
        | 2 -> error s.a (Printf.sprintf "cond compare not decoded yet (0x%x)" insn)
        | 4 -> error s.a (Printf.sprintf "cond select not decoded yet (0x%x)" insn)
        | _ when op2 >= 8 && op2 <= 15 -> data_proc_3src s insn
        | _-> error s.a (Printf.sprintf "invalid opcode (0x%x)" insn)
    end

(*
LDRB  <31:30:size:00  29:27:_:111  26:26:V:0  25:24:_:00  23:22:opc:01  21:21:_:1  20:16:Rm:  15:13:option:011  12:12:S:  11:10:_:10  9:5:Rn:  4:0:Rt:> Load Register Byte (register)
LDRH  <31:30:size:01  29:27:_:111  26:26:V:0  25:24:_:00  23:22:opc:01  21:21:_:1  20:16:Rm:  15:13:option:  12:12:S:  11:10:_:10  9:5:Rn:  4:0:Rt:> Load Register Halfword (register)
LDR   <31:30:size:00  29:27:_:111  26:26:V:1  25:24:_:00  23:22:opc:01  21:21:_:1  20:16:Rm:  15:13:option:011  12:12:S:  11:10:_:10  9:5:Rn:  4:0:Rt:> Load SIMD&FP Register (register offset)
LDR   <31:30:size:10  29:27:_:111  26:26:V:0  25:24:_:00  23:22:opc:01  21:21:_:1  20:16:Rm:  15:13:option:  12:12:S:  11:10:_:10  9:5:Rn:  4:0:Rt:> Load Register (register)
LDRSB <31:30:size:00  29:27:_:111  26:26:V:0  25:24:_:00  23:22:opc:11  21:21:_:1  20:16:Rm:  15:13:option:011  12:12:S:  11:10:_:10  9:5:Rn:  4:0:Rt:> Load Register Signed Byte (register)
LDRSH <31:30:size:01  29:27:_:111  26:26:V:0  25:24:_:00  23:22:opc:11  21:21:_:1  20:16:Rm:  15:13:option:  12:12:S:  11:10:_:10  9:5:Rn:  4:0:Rt:> Load Register Signed Halfword (register)
LDRSW <31:30:size:10  29:27:_:111  26:26:V:0  25:24:_:00  23:22:opc:10  21:21:_:1  20:16:Rm:  15:13:option:  12:12:S:  11:10:_:10  9:5:Rn:  4:0:Rt:> Load Register Signed Word (register)
STRB  <31:30:size:00  29:27:_:111  26:26:V:0  25:24:_:00  23:22:opc:00  21:21:_:1  20:16:Rm:  15:13:option:011  12:12:S:  11:10:_:10  9:5:Rn:  4:0:Rt:> Store Register Byte (register)
STRH  <31:30:size:01  29:27:_:111  26:26:V:0  25:24:_:00  23:22:opc:00  21:21:_:1  20:16:Rm:  15:13:option:  12:12:S:  11:10:_:10  9:5:Rn:  4:0:Rt:> Store Register Halfword (register)
STR   <31:30:size:00  29:27:_:111  26:26:V:1  25:24:_:00  23:22:opc:00  21:21:_:1  20:16:Rm:  15:13:option:011  12:12:S:  11:10:_:10  9:5:Rn:  4:0:Rt:> Store SIMD&FP register (register offset)
STR   <31:30:size:10  29:27:_:111  26:26:V:0  25:24:_:00  23:22:opc:00  21:21:_:1  20:16:Rm:  15:13:option:  12:12:S:  11:10:_:10  9:5:Rn:  4:0:Rt:> Store Register (register)
*)
  (* LDR / STR (register offset) *)
  let load_store_reg_off insn =
    let%decode insn' = insn "31:30:size:F:10,29:27:_:F:111,26:26:_V:F:0,25:24:_:F:00,23:22:opc:F:00,21:21:_:F:1,20:16:Rm:F:xxxxx,15:13:option:F:xxx,12:12:S:F:x,11:10:_:F:10,9:5:Rn:F:xxxxx,4:0:Rt:F:xxxxx" in
    let mem_sz = match size_v with
      | 0 -> 8
      | 1 -> 16
      | 2 -> 32
      | 3 -> 64
      | _ -> L.abort (fun p->p "impossible size")
    in
    let sf = (size_v land 1) in
    let sz = sf2sz sf in
    let rn = get_reg_lv ~use_sp:true rn_v sf in
    let rt = get_reg_lv rt_v sf in
    let shl_amount = if s_v = 1 then size_v else 0 in
    let offset = extend_reg sz rm_v option_v shl_amount in
    let addr = BinOp(Add, Lval rn, offset) in
    if opc_v != 0 then begin
      (* load *)
      if mem_sz < sz then begin
        [Set(rt, (UnOp(ZeroExt sz,Lval(M(addr, mem_sz)))))] @ sf_zero_rd rt_v sf false
      end
      else
        [Set(rt, Lval(M(addr, mem_sz)))]
    end else
      (* store *)
      [Set(M(addr, mem_sz), Lval(rt))]

(*
Signed:
LDRB  <31:30:size:00  29:27:_:111  26:26:V:0  25:24:_:00  23:22:opc:01  21:21:_:0  20:12:imm9:  11:10:_:11  9:5:Rn:  4:0:Rt:> Load Register Byte (immediate)
LDRH  <31:30:size:01  29:27:_:111  26:26:V:0  25:24:_:00  23:22:opc:01  21:21:_:0  20:12:imm9:  11:10:_:01  9:5:Rn:  4:0:Rt:> Load Register Halfword (immediate)
LDRSB <31:30:size:00  29:27:_:111  26:26:V:0  25:24:_:00  23:22:opc:11  21:21:_:0  20:12:imm9:  11:10:_:01  9:5:Rn:  4:0:Rt:> Load Register Signed Byte (immediate)
LDRSB <31:30:size:00  29:27:_:111  26:26:V:0  25:24:_:00  23:22:opc:11  21:21:_:0  20:12:imm9:  11:10:_:11  9:5:Rn:  4:0:Rt:> Load Register Signed Byte (immediate)
LDRH  <31:30:size:01  29:27:_:111  26:26:V:0  25:24:_:00  23:22:opc:01  21:21:_:0  20:12:imm9:  11:10:_:11  9:5:Rn:  4:0:Rt:> Load Register Halfword (immediate)
LDRSH <31:30:size:01  29:27:_:111  26:26:V:0  25:24:_:00  23:22:opc:11  21:21:_:0  20:12:imm9:  11:10:_:01  9:5:Rn:  4:0:Rt:> Load Register Signed Halfword (immediate)
LDRSH <31:30:size:01  29:27:_:111  26:26:V:0  25:24:_:00  23:22:opc:11  21:21:_:0  20:12:imm9:  11:10:_:11  9:5:Rn:  4:0:Rt:> Load Register Signed Halfword (immediate)
LDRSW <31:30:size:10  29:27:_:111  26:26:V:0  25:24:_:00  23:22:opc:10  21:21:_:0  20:12:imm9:  11:10:_:01  9:5:Rn:  4:0:Rt:> Load Register Signed Word (immediate)
LDRSW <31:30:size:10  29:27:_:111  26:26:V:0  25:24:_:00  23:22:opc:10  21:21:_:0  20:12:imm9:  11:10:_:11  9:5:Rn:  4:0:Rt:> Load Register Signed Word (immediate)
STRB  <31:30:size:00  29:27:_:111  26:26:V:0  25:24:_:00  23:22:opc:00  21:21:_:0  20:12:imm9:  11:10:_:01  9:5:Rn:  4:0:Rt:> Store Register Byte (immediate)
STRB  <31:30:size:00  29:27:_:111  26:26:V:0  25:24:_:00  23:22:opc:00  21:21:_:0  20:12:imm9:  11:10:_:11  9:5:Rn:  4:0:Rt:> Store Register Byte (immediate)
STRH  <31:30:size:01  29:27:_:111  26:26:V:0  25:24:_:00  23:22:opc:00  21:21:_:0  20:12:imm9:  11:10:_:01  9:5:Rn:  4:0:Rt:> Store Register Halfword (immediate)
STRH  <31:30:size:01  29:27:_:111  26:26:V:0  25:24:_:00  23:22:opc:00  21:21:_:0  20:12:imm9:  11:10:_:11  9:5:Rn:  4:0:Rt:> Store Register Halfword (immediate)

*)
  let load_store_reg_imm insn =
    let%decode insn' = insn "31:30:size:F:10,29:27:_:F:111,26:26:_V:F:0,25:24:_:F:00,23:22:opc:F:10,21:21:_:F:0,20:12:imm9:F:xxxxxxxxx,11:10:op5:F:01,9:5:Rn:F:xxxxx,4:0:Rt:F:xxxxx" in
    let mem_sz = match size_v with
      | 0 -> 8
      | 1 -> 16
      | 2 -> 32
      | 3 -> 64
      | _ -> L.abort (fun p->p "impossible size")
    in
    let rn = get_reg_lv ~use_sp:true rn_v 1 in
    let rt = get_reg_lv rt_v 1 in
    let offset = UnOp(SignExt 64, const imm9_v 9) in
    let addr, post = match op5_v with
      (* no index *)
      | 0b00 | 0b10 -> BinOp(Add, Lval(rn), offset), []
      (* post index *)
      | 0b01 -> offset, [Set(rn, BinOp(Add, Lval(rn), offset))]
      (* pre index *)
      | 0b11 -> BinOp(Add, Lval(rn), offset), [Set(rn, BinOp(Add, Lval(rn), offset))]
      | _ -> L.abort (fun p->p "Impossible value in load_store_pair")
    in
    if opc_v = 1 then
      (* load *)
      if mem_sz < 32 then
        [Set(rt, (UnOp(ZeroExt 32,Lval(M(addr, mem_sz)))))] @ post
      else
        [Set(rt, Lval(M(addr, mem_sz)))] @ post
    else
      (* store *)
      [Set(M(addr, mem_sz), Lval(rt))]@post

(*
Unsigned
LDRB  <31:30:size:00  29:27:_:111  26:26:V:0  25:24:_:01  23:22:opc:01  21:10:imm12:  9:5:Rn:  4:0:Rt:> Load Register Byte (immediate)
LDRH  <31:30:size:01  29:27:_:111  26:26:V:0  25:24:_:01  23:22:opc:01  21:10:imm12:  9:5:Rn:  4:0:Rt:> Load Register Halfword (immediate)
LDRSB <31:30:size:00  29:27:_:111  26:26:V:0  25:24:_:01  23:22:opc:11  21:10:imm12:  9:5:Rn:  4:0:Rt:> Load Register Signed Byte (immediate)
LDRSH <31:30:size:01  29:27:_:111  26:26:V:0  25:24:_:01  23:22:opc:11  21:10:imm12:  9:5:Rn:  4:0:Rt:> Load Register Signed Halfword (immediate)
LDRSW <31:30:size:10  29:27:_:111  26:26:V:0  25:24:_:01  23:22:opc:10  21:10:imm12:  9:5:Rn:  4:0:Rt:> Load Register Signed Word (immediate)
STRB  <31:30:size:00  29:27:_:111  26:26:V:0  25:24:_:01  23:22:opc:00  21:10:imm12:  9:5:Rn:  4:0:Rt:> Store Register Byte (immediate)
STRH  <31:30:size:01  29:27:_:111  26:26:V:0  25:24:_:01  23:22:opc:00  21:10:imm12:  9:5:Rn:  4:0:Rt:> Store Register Halfword (immediate)
*)
  let load_store_reg_uimm insn =
    let%decode insn' = insn "31:30:size:F:01,29:27:_:F:111,26:26:_V:F:0,25:24:_:F:01,23:22:opc:F:00,21:10:imm12:F:xxxxxxxxxxxx,9:5:Rn:F:xxxxx,4:0:Rt:F:xxxxx" in
    let mem_sz = match size_v with
      | 0 -> 8
      | 1 -> 16
      | 2 -> 32
      | 3 -> 64
      | _ -> L.abort (fun p->p "impossible size")
    in
    let sf = (size_v land 1) in
    let sz = sf2sz sf in
    let rn = get_reg_lv ~use_sp:true rn_v 1 in
    let rt = get_reg_lv rt_v sf in
    let offset = sign_extension (Z.of_int (imm12_v lsl size_v)) 14 64 in
    let addr = BinOp(Add, Lval(rn), Const (Word.of_int offset 64)) in
    if opc_v = 1 then
      if mem_sz < sz then
        [Set(rt, (UnOp(ZeroExt sz,Lval(M(addr, mem_sz)))))]
      else
        [Set(rt, Lval(M(addr, mem_sz)))]
    else
      (* store *)
      [Set(M(addr, mem_sz), Lval(rt))]

  (* STP / STNP / LDP *)
  let load_store_pair insn op3 =
    let%decode insn' = insn "31:30:opc:F:00,29:27:_:F:101,26:26:_V:F:0,25:23:_:F:001,22:22:L:F:1,21:15:imm7:F:xxxxxxx,14:10:Rt2:F:xxxxx,9:5:Rn:F:xxxxx,4:0:Rt:F:xxxxx" in
    let sf = (opc_v lsr 1) land 1 in
    let sz = sf2sz sf in
    let offset = Const (Word.of_int (sign_extension (Z.of_int (imm7_v lsl (sf+2))) 9 64) 64) in
    let rt2 = get_reg_lv rt2_v sf in
    let rt = get_reg_lv rt_v sf in
    let rn = get_reg_lv rn_v ~use_sp:true sf in
    let addr, post = match op3 with
      (* no index *)
      | 0b00 | 0b10 -> BinOp(Add, Lval(rn), offset), []
      (* post index *)
      | 0b01 ->  Lval(rn), [Set(rn, BinOp(Add, Lval(rn), offset))]
      (* pre index *)
      | 0b11 -> BinOp(Add, Lval(rn), offset), [Set(rn, BinOp(Add, Lval(rn), offset))]
      | _ -> L.abort (fun p->p "Impossible value in load_store_pair")
    in
    if l_v = 1 then
      (* load *)
      [Set(rt, Lval(M(addr, sz)));
       Set(rt2, Lval(M(BinOp(Add, addr, const (sz/8) sz), sz)))] @ post
    else
      (* store *)
      [Set(M(addr, sz), Lval(rt));
       Set(M(BinOp(Add, addr, const (sz/8) sz), sz), Lval(rt2))] @ post

  let load_store (s: state) (insn: int): (Asm.stmt list) =
    let op0 = (insn lsr 31) land 1 in
    let op1 = (insn lsr 28) land 3 in
    let op2 = (insn lsr 26) land 1 in
    let op3 = (insn lsr 23) land 3 in
    let op4 = (insn lsr 16) land 0x3F in
    let op5 = (insn lsr 10) land 3 in
    L.debug (fun p->p "load_store: op0=%x op1=%x op2=%x op3=%x op4=%x op5=%x" op0 op1 op2 op3 op4 op5);
    (* unallocated opcodes *)
    if (op0 = 0 && op1 = 0 && op2 = 1 &&
        op3 land 1 = 0 && (op4 land 0x1F) != 0) ||
       (op0 = 1 && op1 = 0 && op2 = 1) ||
       (op1 = 0 && op2 = 0 && op3 > 1) ||
       (op1 = 1 && op3 > 1) then
      error s.a (Printf.sprintf "Unallocated opcode 0x%x" insn);
    (* SIMD *)
    if (op0 = 0 && op1 =0 && op2 = 1) then
      error s.a (Printf.sprintf "SIMD load/store not decoded yet. opcode 0x%x" insn);
    if (op1 = 0b10) then
      load_store_pair insn op3
    else begin
      if (op1 = 0b11) then
        begin
          if op3 > 1 then begin
            load_store_reg_uimm insn
          end else begin
            if op5 = 0b10 then begin
              load_store_reg_off insn
            end else begin
              load_store_reg_imm insn
            end
          end
        end
      else
        error s.a (Printf.sprintf "load/store type not decoded yet. opcode 0x%x" insn);
    end

  (* Return statement matching cond, see ConditionHolds in MRA *)
  let decode_cond cond =
    let base_cond = match (cond lsr 1) with
      | 0b000 -> Cmp(EQ, zf_lv, const1 1)
      | 0b001 -> Cmp(EQ, cf_lv, const1 1)
      | 0b010 -> Cmp(EQ, nf_lv, const1 1)
      | 0b011 -> Cmp(EQ, vf_lv, const1 1)
      | 0b100 -> BBinOp(LogAnd, Cmp(EQ, cf_lv, const1 1), Cmp(EQ, zf_lv, const0 1))
      | 0b101 -> Cmp(EQ, nf_lv, vf_lv)
      | 0b110 -> BBinOp(LogAnd, Cmp(EQ, nf_lv, vf_lv), Cmp(EQ, zf_lv, const0 1))
      | 0b111 -> BConst(true)
      | _ -> L.abort (fun p->p "Invalid condition")
    in
    if (cond land 1) = 1 && cond != 15 then
      BUnOp(LogNot, base_cond)
    else
      base_cond

  (* Conditionnal branch *)
  let b_cond s insn =
    let%decode insn' = insn "31:25:_:F:0101010,24:24:_o1:F:0,23:5:imm19:F:xxxxxxxxxxxxxxxxxxx,4:4:_o0:F:0,3:0:cond:F:xxxx" in
    let offset = imm19_v lsl 2 in
    let signed_offset = sign_extension (Z.of_int offset) 21 64 in
    let cond_il = decode_cond cond_v in
    [If(cond_il, [Jmp(A(Address.add_offset s.a signed_offset))], [Nop])]

  (*
BLR <31:25:_:1101011  24:23:opc:T:00  22:21:op:01  20:16:op2:11111  15:10:op3:000000  9:5:Rn:  4:0:op4:00000> Branch with Link to Register
BR  <31:25:_:1101011  24:23:opc:T:00  22:21:op:00  20:16:op2:11111  15:10:op3:000000  9:5:Rn:  4:0:op4:00000> Branch to Register
RET <31:25:_:1101011  24:23:opc:T:00  22:21:op:10  20:16:op2:11111  15:10:op3:000000  9:5:Rn:  4:0:op4:00000> Return from subroutine
*)

  let b_uncond_reg s insn =
    let%decode insn' = insn "31:25:_:F:1101011,24:21:opc:F:x,20:16:_op2:F:11111,15:10:_op3:F:000000,9:5:Rn:F:xxxxx,4:0:_op4:F:00000" in
    (* pc is 8 bytes ahead because of pre-fetching. *)
    let current_pc = Z.add (Address.to_int s.a) (Z.of_int 4) in
    if opc_v = 1 then (* BLR *)
      [  Set( V(T(x30)), Const (Word.of_int current_pc 64)) ; Call(R(Lval(get_reg_lv rn_v 1)))]
    else (* BR / RET : TODO: use Return ? *)
      [ Jmp(R(Lval(get_reg_lv rn_v 1))) ]

  (*
BL <31:31:op:F:1,30:26:_:F:00101,25:0:imm26:F:xxxxxxxxxxxxxxxxxxxxxxxxxx> Branch with Link
B  <31:31:op:F:0,30:26:_:F:00101,25:0:imm26:F:xxxxxxxxxxxxxxxxxxxxxxxxxx> Branch
*)

  let b_uncond_imm s insn =
    let%decode insn' = insn "31:31:op:F:0,30:26:_:F:00101,25:0:imm26:F:xxxxxxxxxxxxxxxxxxxxxxxxxx" in
    (* pc is 8 bytes ahead because of pre-fetching. *)
    let current_pc = Z.add (Address.to_int s.a) (Z.of_int 4) in
    let offset = imm26_v lsl 2 in
    let signed_offset = sign_extension (Z.of_int offset) 28 64 in
    if op_v = 1 then (* BL *)
      [  Set( V(T(x30)), Const (Word.of_int current_pc 64)) ;
         Call(A(Address.add_offset s.a signed_offset))
      ]
    else
      [
        Jmp(A(Address.add_offset s.a signed_offset))
      ]

  let tst_br s insn =
    let%decode insn'= insn "31:31:b5:F:x,30:25:_:F:011011,24:24:op:F:0,23:19:b40:F:xxxxx,18:5:imm14:F:xxxxxxxxxxxxxx,4:0:Rt:F:xxxxx" in
    let sz = sf2sz b5_v in
    let bitpos = (b5_v lsl 4) lor b40_v in
    let offset = sign_extension (Z.of_int (imm14_v lsl 2)) 16 64 in
    let r = get_reg_lv rt_v b5_v in
    [ If(Cmp(EQ, BinOp(And, BinOp(Shl, Lval r, const bitpos sz), const1 sz), const op_v sz),
         [Jmp(A(Address.add_offset s.a offset))],
         [Nop])]

  let cmp_br s insn =
    let%decode insn'= insn "31:31:sf:F:0,30:25:_:F:011010,24:24:op:F:0,23:5:imm19:F:xxxxxxxxxxxxxxxxxxx,4:0:Rt:F:xxxxx" in
    let sz = sf2sz sf_v in
    let offset = imm19_v lsl 2 in
    let signed_offset = sign_extension (Z.of_int offset) 21 64 in
    let cmp_op = if op_v = 0 then EQ else NEQ in (* CBZ/CBNZ *)
    let rt = get_reg_lv rt_v sf_v in
    [ If(Cmp(cmp_op, Lval rt, const0 sz),
         [Jmp(A(Address.add_offset s.a signed_offset))],
         [Nop])]

  (* Branches, Exception Generating and System instructions *)
  let branch (s: state) (insn: int): (Asm.stmt list) =
    let op0 = (insn lsr 29) land 7 in
    let op1 = (insn lsr 22) land 15 in
    if op0 = 0b010 && op1 <= 7 then
      b_cond s insn
    else if op0 = 0b110 && op1 > 7 then
      b_uncond_reg s insn
    else if (op0 land 3) = 0 then
      b_uncond_imm s insn
    else if (op0 land 3) = 1 && op1 > 7 then
      tst_br s insn
    else if (op0 land 3) = 1 && op1 <= 7 then
      cmp_br s insn
    else
      error s.a (Printf.sprintf "Unsupported branch opcode 0x%08x" insn)


  (* SIMD three same - C4.1.5, page C-302) *)
  let simd_three_same s insn =
    let q = (insn lsr 30) land 1 in
    let u = (insn lsr 29) land 1 in
    let size = (insn lsr 22) land 3 in
    let opcode = (insn lsr 11) land 0x1f in
    let rm = (insn lsr 16) land 0x1f in
    let rn = (insn lsr 5) land 0x1f in
    let rd = insn land 0x1f in
    match u,size,opcode with
    | 1, 0b00, 0b00011 -> (* EOR (vector) *)
      let res128 = BinOp(Xor, Lval (V (qreg rm)), Lval (V (qreg rn))) in
      let masked_res = if q = 0 then BinOp(And, res128, const_mask 64 128) else res128 in
      [ Set (V (qreg rd), masked_res) ]
    | 0, 0b10, 0b00011 -> (* ORR (vector, register) *)
      let res128 = BinOp(Or, Lval (V (qreg rm)), Lval (V (qreg rn))) in
      let masked_res = if q = 0 then BinOp(And, res128, const_mask 64 128) else res128 in
      [ Set (V (qreg rd), masked_res) ]
    | 0, 0b00, 0b00011 -> (* AND (vector) *)
      let res128 = BinOp(And, Lval (V (qreg rm)), Lval (V (qreg rn))) in
      let masked_res = if q = 0 then BinOp(And, res128, const_mask 64 128) else res128 in
      [ Set (V (qreg rd), masked_res) ]

    | _ -> error s.a "SIMD three same"


  (* Scalar Floating-Point and Advanced SIMD *)

  (* Conversion between floating-point and fixed-point *)
  let fp_fp_conv  (s: state) (insn: int): (Asm.stmt list) =
    error s.a (Printf.sprintf "Conversion between floating-point and fixed-point not implemented, opcode : 0x%08x" insn)


  (* Conversion between floating-point and integer *)
  let fp_int_conv  (s: state) (insn: int): (Asm.stmt list) =
    let sf = (insn lsr 31) land 1 in
    let s_ = (insn lsr 29) land 1 in
    let typ = (insn lsr 22) land 3 in
    let rmode = (insn lsr 19) land 3 in
    let opcode = (insn lsr 16) land 7 in
    let rn = (insn lsr 5) land 0x1f in
    let rd = insn land 0x1f in
    match sf, s_, typ, rmode, opcode with
    | 0, 0, 0b00, 0b00, 0b110 -> [ Set( V (wreg rd), Lval (V (sreg rn))) ]
    | 0, 0, 0b00, 0b00, 0b111 -> [ Set( V (qreg rd), UnOp(ZeroExt 128, Lval (V (wreg rn)))) ]
    | _ -> error s.a (Printf.sprintf "Unsupported floating-point and integer conversion instruction opcode: 0x%08x" insn)

  let scalar_fp_simd  (s: state) (insn: int): (Asm.stmt list) =
    let op0 = (insn lsr 28) land 0xf in
    let op1 = (insn lsr 23) land 3 in
    let op2 = (insn lsr 19) land 0xf in
    let op3 = (insn lsr 10) land 0x1ff in
    let f =
      if (op0 land 5) = 1 && (op1 land 2) = 0 then
        begin
          if (op2 land 4) = 0 then  fp_fp_conv  else fp_int_conv
        end
      else if (op0 land 9) = 0 && (op1 land 2) = 0 then
        begin
          if (op2 land 4) = 4 && (op3 land 1) = 1 then
            simd_three_same
          else
            error s.a (Printf.sprintf "Unsupported scalar floating point or SIMD opcode: 0x%08x" insn)
        end
      else
        begin
          L.debug (fun p -> p "FP/SIMD instruction decoded as: op0=%x op1=%x op2=%x op3=%x" op0 op1 op2 op3);
          error s.a (Printf.sprintf "Unsupported scalar floating point or SIMD opcode: 0x%08x" insn)
        end
    in f s insn


  let decode (s: state): Cfa.State.t * Data.Address.t =
    let str = String.sub s.buf 0 4 in
    let instruction = build_instruction str in
    let stmts = match (instruction lsr 25) land 0xF with
      (* C4.1 in ARMv8 manual *)
      (* 00xx : unallocated *)
      | 0b0000 | 0b0001 | 0b0010 | 0b0011 -> error s.a (Printf.sprintf "Unallocated opcode 0x%x" instruction)
      (* 100x : data processing (immediate) *)
      | 0b1000 | 0b1001 -> data_processing_imm s instruction
      (* 101x : branches, exceptions, system instructions *)
      | 0b1010 | 0b1011 -> branch s instruction
      (* x1x0 : loads and stores *)
      | 0b0100 | 0b0110 | 0b1100 | 0b1110 -> load_store s instruction
      (* x101 : data processing (register) *)
      | 0b0101 | 0b1101 -> data_processing_reg s instruction
      | 0b0111 | 0b1111 -> scalar_fp_simd s instruction
      | _ -> error s.a (Printf.sprintf "Unknown opcode 0x%x" instruction)
    in
    return s str stmts

  let parse text cfg _ctx state addr _oracle =
    let s =  {
      g = cfg;
      b = state;
      a = addr;
      buf = text;
    }
    in
    try
      let v', ip' = decode s in
      Some (v', ip', ())
    with
    | Exceptions.Error _ as e -> raise e
    | _             -> (*end of buffer *) None


  let init () =
    Imports.init ()

  let overflow_expression () = Lval (V (T vflag))
  let init_registers () = []
end
