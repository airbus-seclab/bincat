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
   Decoder for ARMv8-A 64-bits
   Implements the specification https://static.docs.arm.com/ddi0487/b/DDI0487B_a_armv8_arm.pdf
*)
module L = Log.Make(struct let name = "armv8A" end)

module Make(Domain: Domain.T) =
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
    | 0 -> x0
    | 1 -> x1
    | 2 -> x2
    | 3 -> x3
    | 4 -> x4
    | 5 -> x5
    | 6 -> x6
    | 7 -> x7
    | 8 -> x8
    | 9 -> x9
    | 10 -> x10
    | 11 -> x11
    | 12 -> x12
    | 13 -> x13
    | 14 -> x14
    | 15 -> x15
    | 16 -> x16
    | 17 -> x17
    | 18 -> x18
    | 19 -> x19
    | 20 -> x20
    | 21 -> x21
    | 22 -> x22
    | 23 -> x23
    | 24 -> x24
    | 25 -> x25
    | 26 -> x26
    | 27 -> x27
    | 28 -> x28
    | 29 -> x29
    | 30 -> x30
    | 31 -> sp
    | _ -> L.abort (fun p -> p "Unknown register number %i" n)

  let reg n =
    T (reg_from_num n)

  (* helper to get register with the right size according to sf value *)
  (* 1 is 64 bits *)
  let reg_sf n sf =
    if sf = 1 then
        T (reg_from_num n)
    else
        P (reg_from_num n, 0, 31)

  module Cfa = Cfa.Make(Domain)

  module Imports = Armv8aImports.Make(Domain)

  type state = {
    mutable g 	    : Cfa.t; 	   (** current cfa *)
    mutable b 	    : Cfa.State.t; (** state predecessor *)
    a 	     	    : Address.t;   (** current address to decode *)
    buf 	     	: string;      (** buffer to decode *)
  }

  (* fatal error reporting *)
  let error a msg =
    L.abort (fun p -> p "at %s: %s" (Address.to_string a) msg)

  let string_to_char_list str =
    let len = String.length str in
    let rec process i =
      if i < len then
        (String.get str i)::(process (i+1))
      else
        []
    in
    List.rev (process 0)

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
  let get_sf_bool insn = ((insn lsr 31) land 1) = 1

  (* S : set flags ? *)
  let get_s insn = (insn lsr 30) land 1
  let get_s_bool insn = ((insn lsr 30) land 1) = 1

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

  (* Note about use_sp: register number 31 can mean 2 differents things:
        - the "zero" register, which always reads "0" and discards writes
        - SP (stack pointer)
    pass ~use_sp:true to use the stack pointer
  *)
  (* Rm (20:16) / Rn (9:5) / Rd (4:0) : registers *)
  let get_Rm_exp ?(use_sp = false) insn sf =
        let num = ((insn lsr 16) land 0x1F) in get_reg_exp ~use_sp:use_sp num sf
  let get_Rn_exp ?(use_sp = false) insn sf =
        let num = ((insn lsr 5) land 0x1F) in get_reg_exp ~use_sp:use_sp num sf
  let get_Rd_lv ?(use_sp = false) insn sf =
        let num = (insn land 0x1F) in
        if num = 31 && not use_sp then begin
            L.info (fun p->p "write to XZR");
            let tmp = Register.make (Register.fresh_name ()) (sf2sz sf) in
            V(T(tmp)), [Directive(Remove(tmp))]
        end else
            V(reg_sf num sf), []

  let get_regs ?(use_sp = false) insn sf =
    let dst, post = get_Rd_lv ~use_sp:use_sp insn sf in
    (dst,
     get_Rn_exp ~use_sp:use_sp insn sf,
     get_Rm_exp ~use_sp:use_sp insn sf, post)

  let get_regs_ld_st ?(use_sp = false) insn sf =
    (get_reg_lv ~use_sp:use_sp ((insn lsr 16) land 0x1F) sf,
     get_reg_lv ~use_sp:true ((insn lsr 5) land 0x1F) sf,
     get_reg_lv ~use_sp:use_sp (insn land 0x1F) sf)

  (* gets Rt2 / Rn / Rt (LDP/STP operations) *)
  let get_regs_pair ?(use_sp = false) insn sf =
    (get_reg_lv ~use_sp:use_sp ((insn lsr 10) land 0x1F) sf,
     get_reg_lv ~use_sp:true ((insn lsr 5) land 0x1F) sf,
     get_reg_lv ~use_sp:use_sp (insn land 0x1F) sf)

  let make_regs_ld_st ?(use_sp = false) sf rm rn rd =
    (get_reg_lv ~use_sp:use_sp rm sf,
     get_reg_lv ~use_sp:true rn sf,
     get_reg_lv ~use_sp:use_sp rd sf)


  (* imm12 : immediate 21:10 *)
  let get_imm12 insn = (insn lsr 10) land 0xfff

  (* imm16 : immediate 20:5 *)
  let get_imm16 insn = (insn lsr 5) land 0xffff

  (* immr : immediate 21:16 *)
  let get_immr insn = (insn lsr 16) land 0b111111

  (* imms : immediate 15:10 *)
  let get_imms insn = (insn lsr 10) land 0b111111

  (* imm7 : immediate 21:15 *)
  let get_imm7 insn = (insn lsr 15) land 0b1111111

  (* 30:29:opc, used in logic insn *)
  let get_opc insn = (insn lsr 29) land 3

  (* shift *)
  let get_shifted_imm s insn imm sz =
    let shift = (insn lsr 22) land 3 in
    match shift with
        | 0b10 | 0b11 -> error s.a (Printf.sprintf "Reserved shift value 0x%x in opcode 0x%x" shift insn)
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
  let sf_zero_rd insn sf =
    if sf = 0 then begin
        let rd_top = P((reg_from_num (insn land 0x1F)), 32, 63) in
        [Set ( V(rd_top), const 0 32)]
    end else []

  (* compute n z and set c v flags for value in reg *)
  let flags_stmts sz reg cf vf =
        (* NF: negative flag, check MSB of reg,
           ZF: zero flag, is reg zero ?,
           CF: carry flag,
           VF: Overflow flag
        *)
        [ Set ( nf_v, TernOp(Cmp(EQ, (msb_stmts reg sz), const1 sz), const1 1, const0 1));
          Set ( zf_v, TernOp(Cmp(EQ, reg, const0 sz), const1 1, const0 1));
          (* XXX do CF and VF *)
          Set ( cf_v, cf);
          Set ( vf_v, vf)]


  let decode_bitmasks sz _n immr _imms _is_imm =
        (* TODO / XXX :https://www.meriac.com/archex/A64_v82A_ISA/shared_pseudocode.xml#impl-aarch64.DecodeBitMasks.4 *)
        const immr sz

  let extend_reg reg ext_type shift =
    let ext_op = match ext_type with
            | 0 -> ZeroExt 8
            | 1 -> ZeroExt 16
            | 2 -> ZeroExt 32
            | 3 -> ZeroExt 64
            | 4 -> SignExt 8
            | 5 -> SignExt 16
            | 6 -> SignExt 32
            | 7 -> SignExt 64
            | _ -> L.abort(fun p->p "invalid shift")
    in
    UnOp(ext_op, BinOp(Shl, reg, shift))
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
        let cf = carry_stmts sz op1 op_s op2 in
        let vf = overflow_stmts sz (Lval dst) op1 op_s op2 in
        core_stmts @ (flags_stmts sz (Lval dst) cf vf)
    end else
        core_stmts

  (* ADD/ ADDS / SUB / SUBS (32/64) with immediate *)
  let add_sub_imm s insn sf =
    let%decode insn' = insn "31:31:sf:F:0,30:30:op:F:0,29:29:S:F:0,28:24:_:F:10001,23:22:shift:F:xx,21:10:imm12:F:xxxxxxxxxxxx,9:5:Rn:F:xxxxx,4:0:Rd:F:xxxxx" in
    let s_b = s_v = 1 in
    let sz = sf2sz sf_v in
    let shift = get_shifted_imm s insn imm12_v sz in
    let rd, rn, _, post = get_regs ~use_sp:true insn sf in
    (add_sub_core sz rd rn op_v shift s_b @ sf_zero_rd insn sf) @ post

  (* ADD/ ADDS / SUB / SUBS (32/64) with register *)
  let add_sub_reg s insn _is_extend =
    let sf, sz = get_sf insn in
    let shift = (insn lsr 22) land 3 in
    let imm6 = get_imms insn in
    if (sf = 0 && (imm6 lsr 5) = 1) || (shift = 3) then
        (error s.a (Printf.sprintf "Invalid opcode 0x%x" insn));
    let op = (insn lsr 30) land 1 in
    let s_b = get_s_bool insn in
    let rd, rn, rm, post = get_regs insn sf in
    let shifted_rm =  get_shifted_reg sz insn rm imm6 in
    (add_sub_core sz rd rn op shifted_rm s_b) @ post

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
  let logic_imm s insn sf =
    let opc = get_opc insn in
    let n = (insn lsr 22) land 1 in
    if sf = 0 && n = 1 then (error s.a (Printf.sprintf "Invalid opcode 0x%x" insn));
    let sz = sf2sz sf in
    let rd, post = get_Rd_lv ~use_sp:true insn sf in
    let rn = get_Rn_exp insn sf in
    let immr = get_immr insn in
    let imms = get_imms insn in
    let imm_res = decode_bitmasks sz n immr imms true in
    logic_core sz rd rn opc imm_res (opc = 0b11) @ sf_zero_rd insn sf @ post

  (* AND / ORR / EOR / ANDS (32/64) with register *)
  let logic_reg s insn =
    let sf, sz = get_sf insn in
    let imm6 = get_imms insn in
    if sf = 0 && (imm6 lsr 5) = 1 then
        (error s.a (Printf.sprintf "Invalid opcode 0x%x" insn));
    let opc = get_opc insn in
    let rd, rn, rm, post = get_regs insn sf in
    let n = (insn lsr 21) land 1 in
    let shifted_rm = get_shifted_reg sz insn rm imm6 in
    let shifted_rm' = if n = 1 then UnOp(Not, shifted_rm) else shifted_rm in
    logic_core sz rd rn opc shifted_rm' (opc = 0b11) @ sf_zero_rd insn sf @ post

  (* MOVZ move immediate with optional shift *)
  let mov_wide s insn sf =
    let sz = sf2sz sf in
    let opc = get_opc insn in
    let hw = ((insn lsr 21) land 3) in
    if (sf = 0 && hw > 1) || (opc = 0b01) then error s.a (Printf.sprintf "Invalid opcode 0x%x" insn);
    let rd, post = get_Rd_lv insn sf in
    let imm16 = const (get_imm16 insn) sz in
    let shift = hw lsl 4 in
    let imm = if shift > 0 then BinOp(Shl, imm16, const shift sz) else imm16 in
    let imm = match opc with
        | 0b00 -> (* MOVN *) UnOp(Not, imm)
        | 0b10 -> (* MOVZ *) imm
        | 0b11 -> (* MOVK *)
                (* compute 0x...FFFF0000 mask *)
                let mask = Z.logxor (Z.sub (Z.shift_left Z.one sz) Z.one) (Z.of_int (0xFFFF lsl shift)) in
                (* only replace the bits corresponsding to imm in the destination *)
                BinOp(Or, BinOp(And, Lval(rd), Const (Word.of_int mask sz)), imm)
        | _ -> error s.a "Impossible error"; in

    [ Set (rd, imm) ] @ sf_zero_rd insn sf @ post

  (* ADR/ADRP *)
  let pc_rel_addr s insn sf =
    let op = (insn lsr 31) land 1 in
    let immlo = (insn lsr 29) land 3 in
    let immhi = (insn lsr 5) land 0x7ffff in
    let imm = (immhi lsl 2) lor immlo in
    let rd, post = get_Rd_lv  insn sf in
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

  (* data processing with immediates *)
  let data_processing_imm (s: state) (insn: int): (Asm.stmt list) =
    let op0 = (insn lsr 23) land 7 in
    let sf, _ = get_sf insn in
    let stmts = match op0 with
        | 0b000 | 0b001 -> pc_rel_addr s insn sf
        | 0b010 | 0b011 -> add_sub_imm s insn sf
        | 0b100         -> logic_imm s insn sf
        | 0b101 -> mov_wide s insn sf
        | 0b110 -> (* XXX *) error s.a (Printf.sprintf "Bitfield (imm) not decoded (0x%x)" insn)
        | 0b111 -> (* XXX *) error s.a (Printf.sprintf "Extract (imm) not decoded (0x%x)" insn)
        | _ -> error s.a (Printf.sprintf "Unknown opcode 0x%x" insn)
    in stmts

  let data_proc_2src s insn =
    (* XXX *)
    error s.a (Printf.sprintf "Data processing (2 sources) not decoded yet (0x%x)" insn)

  let data_proc_1src s insn =
    (* XXX *)
    error s.a (Printf.sprintf "Data processing (1 source) not decoded yet (0x%x)" insn)

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
            else (* op2 = 1xxx *)
                add_sub_reg s insn (op2 land 1)
        else
            []
    end

  (* LDR / STR (register offset) *)
  let load_store_reg_off insn =
    let%decode insn' = insn "31:30:size:F:10,29:27:_:F:111,26:26:V:F:0,25:24:_:F:00,23:22:opc:F:00,21:21:_:F:1,20:16:Rm:F:xxxxx,15:13:option:F:xxx,12:12:S:F:x,11:10:_:F:10,9:5:Rn:F:xxxxx,4:0:Rt:F:xxxxx" in
    let sz = sf2sz (size_v lsr 1) in
    let rm, rn, rt = make_regs_ld_st (size_v lsr 1) rm_v rn_v rt_v in
    let shl_amount = if s_v = 1 then size_v else 0 in
    let offset = extend_reg (Lval rm) option_v (const shl_amount sz) in
    let addr = BinOp(Add, Lval rn, offset) in
    if opc_v = 1 then
        (* load *)
        [Set(rt, Lval(M(addr, sz)))]
    else
        (* store *)
        [Set(M(addr, sz), Lval(rt))]

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
    let%decode insn' = insn "31:30:size:F:10,29:27:_:F:111,26:26:V:F:0,25:24:_:F:00,23:22:opc:F:10,21:21:_:F:0,20:12:imm9:F:xxxxxxxxx,11:10:op5:F:01,9:5:Rn:F:xxxxx,4:0:Rt:F:xxxxx" in
    let mem_sz = match size_v with
        | 0 -> 8
        | 1 -> 16
        | 2 -> 32
        | _ -> L.abort (fun p->p "impossible size")
    in
    let sz = sf2sz (opc_v lsr 1) in
    let _, rn, rt = make_regs_ld_st (size_v lsr 1) 0 rn_v rt_v in
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
        [Set(rt, Lval(M(addr, mem_sz)))]@post
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
    let%decode insn' = insn "31:30:size:F:01,29:27:_:F:111,26:26:V:F:0,25:24:_:F:01,23:22:opc:F:00,21:10:imm12:F:xxxxxxxxxxxx,9:5:Rn:F:xxxxx,4:0:Rt:F:xxxxx" in
    let mem_sz = match size_v with
        | 0 -> 8
        | 1 -> 16
        | 2 -> 32
        | 3 -> 64
        | _ -> L.abort (fun p->p "impossible size")
    in
    let sz = sf2sz (opc_v lsr 1) in
    let _, rn, rt = make_regs_ld_st (size_v lsr 1) 0 rn_v rt_v in
    let offset = BinOp(Shl, UnOp(SignExt 64, const imm12_v 12), const size_v 64) in
    let addr = BinOp(Add, Lval(rn), offset) in
    if opc_v = 1 then
        (* load *)
        [Set(rt, Lval(M(addr, mem_sz)))]
    else
        (* store *)
        [Set(M(addr, mem_sz), Lval(rt))]

  (* STP / STNP / LDP *)
  let load_store_pair insn op3 =
    let l = (insn lsr 22) land 1 in
    let imm7 = get_imm7 insn in
    let sf, sz = get_sf insn in
    let offset = BinOp(Shl, UnOp(SignExt 64, const imm7 7), const (sf+2) 64) in
    let rt2, rn, rt = get_regs_pair insn sf in
    let addr, post = match op3 with
        (* no index *)
        | 0b00 | 0b10 -> BinOp(Add, Lval(rn), offset), []
        (* post index *)
        | 0b01 -> offset, [Set(rn, BinOp(Add, Lval(rn), offset))]
        (* pre index *)
        | 0b11 -> BinOp(Add, Lval(rn), offset), [Set(rn, BinOp(Add, Lval(rn), offset))]
        | _ -> L.abort (fun p->p "Impossible value in load_store_pair")
    in
    if l = 1 then
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
    (* unallocated opcodes *)
    if (op0 = 0 && op1 = 0 && op2 = 1 &&
        op3 land 1 = 0 && (op4 land 0x1F) != 0) ||
       (op0 = 1 && op1 = 0 && op2 = 1) ||
       (op1 = 0 && op2 = 0 && op3 > 1) ||
       (op1 = 1 && op3 > 1) then
            error s.a (Printf.sprintf "Unallocated opcode 0x%x" insn);
    (* SIMD *)
    if (op0 = 0) then
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
      let%decode insn' = insn "31:25:_:F:0101010,24:24:o1:F:0,23:5:imm19:F:xxxxxxxxxxxxxxxxxxx,4:4:o0:F:0,3:0:cond:F:xxxx" in
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
      let%decode insn' = insn "31:25:_:F:1101011,24:21:opc:F:x,20:16:op2:F:11111,15:10:op3:F:000000,9:5:Rn:F:xxxxx,4:0:op4:F:00000" in
      (* pc is 8 bytes ahead because of pre-fetching. *)
      let current_pc = Z.add (Address.to_int s.a) (Z.of_int 4) in
      let pre =  if opc_v = 1 then [  Set( V(T(x30)), Const (Word.of_int current_pc 64)) ] else [] in
      pre @ [Call(R(Lval(get_reg_lv rn_v 0)))]

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
      let pre =  if op_v = 1 then [  Set( V(T(x30)), Const (Word.of_int current_pc 64)) ] else [] in
      pre @ [Call(A(Address.add_offset s.a signed_offset))]

  let branch (s: state) (insn: int): (Asm.stmt list) =
    let op0 = (insn lsr 29) land 7 in
    let op1 = (insn lsr 22) land 15 in
    if op0 = 0b010 && op1 <= 7 then
        b_cond s insn
    else if op0 = 0b110 && op1 > 7 then
        b_uncond_reg s insn
    else if (op0 land 3) = 0 then
        b_uncond_imm s insn
    else
        error s.a (Printf.sprintf "Unsupported branch opcode 0x%08x" insn)


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
      | _ 			  -> (*end of buffer *) None

  let forget_reserved_registers_aapcs () =
    [ Directive (Forget (V (T x1))) ; (* scratch registers r1 -> r3 *)
      Directive (Forget (V (T x2))) ;
      Directive (Forget (V (T x3))) ;
    ]


  let type_directives_aapcs _typing_rule =
    let epilogue = [] in
    let _off = !Config.stack_width / 8 in
    let _sz, prologue = 0, []
    in
    prologue, epilogue @ (forget_reserved_registers_aapcs ())


  let taint_directives_aapcs taint_ret taint_args =
    let taint_arg taint =
      match taint with
      | Config.No_taint -> []
      | Config.Buf_taint -> [ Directive (Taint (None, M (Lval (V (T x0)), !Config.operand_sz))) ]
      | Config.Addr_taint -> [ Directive (Taint (None, V (T x0))) ]
    in
    let taint_ret' =
      match taint_ret with
      | None -> []
      | Some t -> taint_arg t
    in
    List.fold_left (fun l arg -> (taint_arg arg)@l) [] taint_args, taint_ret'


  let default_stub_aapcs () = []


  let get_stub name =
    match !Config.call_conv with
    | Config.AAPCS ->
       begin
         try
           Hashtbl.find Imports.aapcs_stubs name
         with Not_found -> default_stub_aapcs ()
       end
    | _ -> L.abort (fun p -> p "calling convention not managed for ARM")

  let replace_types type_directive =
    Hashtbl.iter (fun name typing_rule ->
      try
        L.debug (fun p -> p "types for %s ?" name);
        let a, fundec = Imports.search_by_name name in
        let prologue, epilogue = type_directive typing_rule in
        L.debug (fun p -> p "replace type for %s: %s %s" name (Asm.string_of_stmts prologue true) (Asm.string_of_stmts epilogue true));
        Hashtbl.replace Imports.tbl a
          { fundec with Imports.prologue = fundec.Imports.prologue@prologue ;
            Imports.epilogue = fundec.Imports.epilogue@epilogue ; Imports.stub = get_stub name}
      with Not_found ->
        L.analysis (fun p -> p "from config file: Typing information for function %s without import address => ignored." name); ()
    ) Config.typing_rules

  let replace_taint taint_directives funame taint_ret taint_args =
    let a, fundec = Imports.search_by_name funame in
    let prologue, epilogue = taint_directives taint_ret taint_args in
    Hashtbl.replace Imports.tbl a
      { fundec with Imports.prologue = fundec.Imports.prologue@prologue ;
        Imports.epilogue = fundec.Imports.epilogue@epilogue ;  }


    (** initialization of the import table *)
  let init_imports () =
    Imports.init();
    (* creates the import table from import section *)
    let add_import_to_table a (libname, fname) =
      L.debug(fun p -> p "loading import %s.%s at %x" libname fname (Z.to_int a));
      let a' = Data.Address.of_int Data.Address.Global a !Config.address_sz in
      let fun_desc =  {
        Imports.libname = libname;
        Imports.name = fname;
        Imports.prologue = [];
        Imports.stub = [];
        Imports.epilogue = [];
      } in
      Hashtbl.add Imports.tbl a' fun_desc in
    Hashtbl.iter add_import_to_table  Config.import_tbl;
    begin
      match !Config.call_conv with
      | Config.AAPCS -> replace_types type_directives_aapcs
      | cc -> L.analysis (fun p -> p "Calling convention %s not managed for ARM. Typing directives ignored"
      (Config.call_conv_to_string cc))
    end;
    (* adds tainting information to prologue and epilogue *)
    Hashtbl.iter (fun (libname, funame) (callconv, taint_ret, taint_args) ->
      try
        match callconv with
        | Config.AAPCS ->
           replace_taint taint_directives_aapcs funame taint_ret taint_args
        | cc -> L.analysis (fun p -> p "Calling convention %s not supported for ARM. Tainting rule ignored for %s.%s " (Config.call_conv_to_string cc) libname funame)
      with
        Not_found ->
          L.analysis (fun p -> p"Typing information for function without import address ignored"); ()
      | Failure msg -> L.abort (fun p -> p "%s" msg)

    ) Config.tainting_rules



  let init () =
    init_imports()
end
