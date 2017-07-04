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
  let r0 = Register.make ~name:"r0" ~size:64;;
  let r1 = Register.make ~name:"r1" ~size:64;;
  let r2 = Register.make ~name:"r2" ~size:64;;
  let r3 = Register.make ~name:"r3" ~size:64;;
  let r4 = Register.make ~name:"r4" ~size:64;;
  let r5 = Register.make ~name:"r5" ~size:64;;
  let r6 = Register.make ~name:"r6" ~size:64;;
  let r7 = Register.make ~name:"r7" ~size:64;;
  let r8 = Register.make ~name:"r8" ~size:64;;
  let r9 = Register.make ~name:"r9" ~size:64;;
  let r10 = Register.make ~name:"r10" ~size:64;;
  let r11 = Register.make ~name:"r11" ~size:64;;
  let r12 = Register.make ~name:"r12" ~size:64;;
  let r13 = Register.make ~name:"r13" ~size:64;;
  let r14 = Register.make ~name:"r15" ~size:64;;
  let r15 = Register.make ~name:"r14" ~size:64;;
  let r16 = Register.make ~name:"r16" ~size:64;;
  let r17 = Register.make ~name:"r17" ~size:64;;
  let r18 = Register.make ~name:"r18" ~size:64;;
  let r19 = Register.make ~name:"r19" ~size:64;;
  let r20 = Register.make ~name:"r20" ~size:64;;
  let r21 = Register.make ~name:"r21" ~size:64;;
  let r22 = Register.make ~name:"r22" ~size:64;;
  let r23 = Register.make ~name:"r23" ~size:64;;
  let r24 = Register.make ~name:"r24" ~size:64;;
  let r25 = Register.make ~name:"r25" ~size:64;;
  let r26 = Register.make ~name:"r26" ~size:64;;
  let r27 = Register.make ~name:"r27" ~size:64;;
  let r28 = Register.make ~name:"r28" ~size:64;;
  let r29 = Register.make ~name:"r29" ~size:64;;
  let r30 = Register.make ~name:"r30" ~size:64;;
  let pc = Register.make ~name:"pc" ~size:64;;
  let sp = Register.make ~name:"sp" ~size:64;; (* stack pointer *)

  (* condition flags are modeled as registers of size 1 *)
  let nflag = Register.make ~name:"N" ~size:1;;
  let zflag = Register.make ~name:"Z" ~size:1;;
  let cflag = Register.make ~name:"C" ~size:1;;
  let vflag = Register.make ~name:"V" ~size:1;;

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
    | 13 -> r13
    | 14 -> r14
    | 15 -> r15
    | 16 -> r16
    | 17 -> r17
    | 18 -> r18
    | 19 -> r19
    | 20 -> r20
    | 21 -> r21
    | 22 -> r22
    | 23 -> r23
    | 24 -> r24
    | 25 -> r25
    | 26 -> r26
    | 27 -> r27
    | 28 -> r28
    | 29 -> r29
    | 30 -> r30
    | _ -> L.abort (fun p -> p "Unknown register number %i" n)

  let reg n =
    T (reg_from_num n)

  (* helper to get register with the right size according to sf value *)
  (* 1 is 64 bits *)
  let reg_sf n sf =
    if sf == 1 then
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
  let sf2sz sf = if sf == 1 then 64 else 32

  (* sf : 32 bit or 64 bits ops *)
  let get_sf insn = (insn lsr 31) land 1
  let get_sf_bool insn = ((insn lsr 31) land 1) == 1

  (* S : set flags ? *)
  let get_s insn = (insn lsr 30) land 1
  let get_s_bool insn = ((insn lsr 30) land 1) == 1

  (* Rn / Rd : registers *)
  let get_Rn insn sf = reg_sf ((insn lsr 5) land 0x1F) sf
  let get_Rd insn sf = reg_sf (insn land 0x1F) sf

  let get_Rd_lv insn sf = V (get_Rd insn sf)
  let get_Rn_exp insn sf = Lval (V (get_Rn insn sf))

  (* imm12 : immediate 21:10 *)
  let get_imm12 insn = (insn lsr 10) land 0xfff

  (* immr : immediate 21:16 *)
  let get_immr insn = (insn lsr 16) land 0b111111

  (* imms : immediate 15:10 *)
  let get_imms insn = (insn lsr 10) land 0b111111

  (* 30:29:opc, used in logic insn *)
  let get_opc insn = (insn lsr 29) land 3

  (* shift *)
  let get_shift_op s insn imm sz =
    let shift = (insn lsr 22) land 3 in
    match shift with
        | 0b10 | 0b11 -> error s.a (Printf.sprintf "Reserved shift value 0x%x in opcode 0x%x" shift insn)
        | 0b00 -> const imm sz
        | 0b01 -> const (imm lsl 12) sz
        | _ -> error s.a "Impossible error !"

  (******************************)
  (* Common IL generation       *)
  (******************************)

  (* 32 bits ops zero the top 32 bits, this helper does it if needed *)
  let sf_zero_rd insn sf =
    if sf == 0 then begin
        let rd_top = P((reg_from_num ((insn lsr 5) land 0x1F)), 32, 63) in
        [Set ( V(rd_top), const 0 32)]
    end else []

  (* compute n z and set c v flags for value in reg *)
  let flags_stmts sz reg cf vf =
        (* NF: negative flag, check MSB of reg,
           ZF: zero flag, is reg zero ?,
           CF: carry flag,
           VF: Overflow flag
        *)
        [ Set ( nf_v, TernOp(Cmp(EQ, (msb_stmts reg sz), const1 sz), const 1 sz, const 0 sz));
          Set ( zf_v, TernOp(Cmp(EQ, reg, const0 sz), const 1 sz, const 0 sz));
          Set ( cf_v, cf);
          Set ( vf_v, vf)]


  let decode_bitmasks sz _n immr _imms _is_imm =
        (** TODO / XXX :https://www.meriac.com/archex/A64_v82A_ISA/shared_pseudocode.xml#impl-aarch64.DecodeBitMasks.4 *)
        const immr sz

  (******************************)
  (* Actual instruction decoder *)
  (******************************)

  (* ADD/ ADDS / SUB / SUBS (32/64) *)
  let add_sub_imm s insn sf rn rd =
    let op = (insn lsr 30) land 1 in (* add or sub ? *)
    let s_b = get_s_bool insn in
    let sz = sf2sz sf in
    let imm12 = get_imm12 insn in
    let shift = get_shift_op s insn imm12 sz in
    let op_s = if op == 0 then Add else Sub in
    let core_stmts =
        [ Set (rd, BinOp(op_s, rn, shift)) ] @ sf_zero_rd insn sf
        in
    (* flags ? *)
    if s_b then begin
        let cf = carry_stmts sz rn op_s shift in
        let vf = overflow_stmts sz (Lval rd) rn op_s shift in
        core_stmts @ (flags_stmts sz (Lval rd) cf vf)
    end else
        core_stmts

  (* AND / ORR / EOR / ANDS (32/64) *)
  let logic_imm s insn sf rn rd =
    let opc = get_opc insn in
    let n = (insn lsr 22) land 1 in
    if sf == 0 && n == 1 then (error s.a (Printf.sprintf "Invalid opcode 0x%x" insn));
    let sz = sf2sz sf in
    let immr = get_immr insn in
    let imms = get_imms insn in
    let imm_res = decode_bitmasks sz n immr imms true in
    let op = match opc with
               | 0b00 | 0b11 -> And
               | 0b01 -> Or
               | 0b10 -> Xor
               | _ -> error s.a "Impossible error !" in
    let core_stmts =
        [ Set (rd, BinOp(op, rn, imm_res)) ] @ sf_zero_rd insn sf
        in
    (* flags ? *)
    if opc == 0b11 then begin
        let cf = carry_stmts sz rn op imm_res in
        let vf = overflow_stmts sz (Lval rd) rn op imm_res in
        core_stmts @ (flags_stmts sz (Lval rd) cf vf)
    end else
        core_stmts

  let data_processing_imm (s: state) (insn: int): (Asm.stmt list) =
    let op0 = (insn lsr 23) land 7 in
    let sf = get_sf insn in
    let rd = get_Rd_lv insn sf in
    let rn = get_Rn_exp insn sf in
    let stmts = match op0 with
        | 0b010 | 0b011 -> add_sub_imm s insn sf rn rd
        | 0b100         -> logic_imm s insn sf rn rd
        | 0b101 -> error s.a (Printf.sprintf "Move wide imm not decoded (0x%x)" insn)
        | 0b110 -> error s.a (Printf.sprintf "Bitfield (imm) not decoded (0x%x)" insn)
        | 0b111 -> error s.a (Printf.sprintf "Extract (imm) not decoded (0x%x)" insn)
        | _ -> error s.a (Printf.sprintf "Unknown opcode 0x%x" insn)
    in stmts

  let data_proc_2src s insn =
      error s.a (Printf.sprintf "Data processing (2 sources) not decoded yet (0x%x)" insn)

  let data_proc_1src s insn =
      error s.a (Printf.sprintf "Data processing (1 source) not decoded yet (0x%x)" insn)

  let add_sub_reg s insn _is_extend =
      error s.a (Printf.sprintf "Add_sub (reg) not decoded yet (0x%x)" insn)

  let logic_reg _s _insn =
      []

  let data_processing_reg (s: state) (insn: int): (Asm.stmt list) =
    let op0 = (insn lsr 30) land 1 in
    let op1 = (insn lsr 28) land 1 in
    let op2 = (insn lsr 21) land 3 in
    if op1 == 1 && op2 == 0b0110 then begin
        if op0 == 0 then
            data_proc_2src s insn
        else
            data_proc_1src s insn
    end
    else begin
        if op1 == 0 then
            if (op2 lsr 3) == 1 then
                logic_reg s insn
            else
                add_sub_reg s insn (op2 land 1)
        else
            []
    end

  let decode (s: state): Cfa.State.t * Data.Address.t =
    let str = String.sub s.buf 0 4 in
    let instruction = build_instruction str in
    let stmts = match (instruction lsr 25) land 0xF with
        (* C4.1 in ARMv8 manual *)
        (* 00xx : unallocated *)
        | 0b0000 | 0b0001 | 0b0010 | 0b0011 -> error s.a (Printf.sprintf "Unallocated opcode 0x%x" instruction)
        (* 100x : data processing (immediate) *)
        | 0b1000 | 0b1001 -> data_processing_imm s instruction
        (* x101 : data processing (immediate) *)
        | 0b0101 | 0b1101 -> data_processing_reg s instruction
        | _ -> error s.a (Printf.sprintf "Unknown opcode 0x%x" instruction)
    in
    let current_pc = Const (Word.of_int (Z.add (Address.to_int s.a) (Z.of_int 8)) 32) in (* pc is 8 bytes ahead because of pre-fetching. *)
    return s str (Set( V (T pc), current_pc) :: stmts)

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

  let init () = ()
end
