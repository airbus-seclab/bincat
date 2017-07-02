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

module Make(Domain: Domain.T) =
struct

  type ctx_t = unit

  open Data
  open Asm


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


  (* condition flags are modeled as registers of size 1 *)
  let nflag = Register.make ~name:"n" ~size:1;;
  let zflag = Register.make ~name:"z" ~size:1;;
  let cflag = Register.make ~name:"c" ~size:1;;
  let vflag = Register.make ~name:"v" ~size:1;;


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

  (** [const c sz] builds the asm constant of size _sz_ from int _c_ *)
  let const c sz = Const (Word.of_int (Z.of_int c) sz)

  let n_is_set = Cmp(EQ, Lval (V (T nflag)), const 1 1)
  let z_is_set = Cmp(EQ, Lval (V (T zflag)), const 1 1)
  let c_is_set = Cmp(EQ, Lval (V (T cflag)), const 1 1)
  let v_is_set = Cmp(EQ, Lval (V (T vflag)), const 1 1)
  let n_is_clear = Cmp(EQ, Lval (V (T nflag)), const 0 1)
  let z_is_clear = Cmp(EQ, Lval (V (T zflag)), const 0 1)
  let c_is_clear = Cmp(EQ, Lval (V (T cflag)), const 0 1)
  let v_is_clear = Cmp(EQ, Lval (V (T vflag)), const 0 1)

  module Cfa = Cfa.Make(Domain)

  module Imports = Armv8aImports.Make(Domain)

  type state = {
    mutable g             : Cfa.t;        (** current cfa *)
    mutable b             : Cfa.State.t;  (** state predecessor *)
    a                     : Address.t;    (** current address to decode *)
    buf                   : string;       (** buffer to decode *)
    endianness            : Config.endianness_t;      (** whether memory access is little endian *)
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

  let return (s: state) (_str: int) (stmts: Asm.stmt list): Cfa.State.t * Data.Address.t =
    s.b.Cfa.State.stmts <- stmts;
    (*    s.b.Cfa.State.bytes <- string_to_char_list str; *)
    s.b, Data.Address.add_offset s.a (Z.of_int 4)

  let ror32 value n =
    (value lsr n) lor ((value lsl (32-n)) land 0xffffffff)

  let data_proc s instruction =
    let rd = (instruction lsr 12) land 0xf in
    let _rn = (instruction lsr 16) land 0xf in
    let is_imm = (instruction lsr 25) land 1 in
    let set_cond_codes = (instruction lsr 20) land 1 in
    let op2_stmt =
      if is_imm = 0 then
        let shift_op = (instruction lsr 4) land 0xff in
        let rm = instruction land 0xf in
        let op3 =
          if shift_op land 1 = 0 then
            const (shift_op lsr 3) 32
          else
            Lval (V (reg (shift_op lsr 4))) in
        match (shift_op lsr 1) land 0x3 with
          | 0b00 -> (* lsl *) BinOp(Shl, Lval (V (reg rm)), op3)
          | 0b01 -> (* lsr *) BinOp(Shr, Lval (V (reg rm)), op3)
          | 0b10 -> (* asr *) error s.a "Asr"
          | 0b11 -> (* ror *) error s.a "Ror"
          | _ as st -> L.abort (fun p -> p "unexpected shift type %x" st)
      else
        let shift = (instruction lsr 8) land 0xf in
        let imm = instruction land 0xff in
        const (ror32 imm (2*shift)) 32
    in let stmt = match (instruction lsr 21) land 0xf with
    | 0b0000 -> (* AND - Rd:= Op1 AND Op2 *) error s.a "AND"
    | 0b0001 -> (* EOR - Rd:= Op1 EOR Op2 *) error s.a "EOR"
    | 0b0010 -> (* SUB - Rd:= Op1 - Op2 *) error s.a "SUB"
    | 0b0011 -> (* RSB - Rd:= Op2 - Op1 *) error s.a "RSB"
    | 0b0100 -> (* ADD - Rd:= Op1 + Op2 *) error s.a "ADD"
    | 0b0101 -> (* ADC - Rd:= Op1 + Op2 + C *) error s.a "ADC"
    | 0b0110 -> (* SBC - Rd:= Op1 - Op2 + C - 1 *) error s.a "SBC"
    | 0b0111 -> (* RSC - Rd:= Op2 - Op1 + C - 1 *) error s.a "RSC"
    | 0b1000 -> (* TST - set condition codes on Op1 AND Op2 *) error s.a "TST"
    | 0b1001 -> (* TEQ - set condition codes on Op1 EOR Op2 *) error s.a "TEQ"
    | 0b1010 -> (* CMP - set condition codes on Op1 - Op2 *) error s.a "CMP"
    | 0b1011 -> (* CMN - set condition codes on Op1 + Op2 *) error s.a "CMN"
    | 0b1100 -> (* ORR - Rd:= Op1 OR Op2 *) error s.a "ORR"
    | 0b1101 -> (* MOV - Rd:= Op2 *) [ Set (V (reg rd), op2_stmt) ]
    | 0b1110 -> (* BIC - Rd:= Op1 AND NOT Op2 *) error s.a "BIC"
    | 0b1111 -> (* MVN - Rd:= NOT Op2 *) error s.a "MVN"
    | _ -> error s.a (Printf.sprintf "Unknown opcode 0x%x" instruction) in
       let stmt_cc = 
         if set_cond_codes = 0
         then
           stmt
         else
           let z_stmt = [ Set(V (T zflag), TernOp (Cmp(EQ, Lval (V (reg rd)), const 0 32),
                                                   const 1 1, const 0 1)) ] in
           let n_stmt = [ Set(V (T nflag), TernOp (Cmp(EQ, BinOp(And, Lval (V (reg rd)), const 0x80000000 32),
                                                       const 0 32),
                                                   const 0 1, const 1 1)) ] in
           stmt @ z_stmt @ n_stmt in
       stmt_cc

  let wrap_cc cc stmts =
    let asm_cond = match cc with
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
    | _ -> L.abort (fun p -> p "Unexpected condiction code %x" cc) in
    [ If (asm_cond, stmts, []) ]


  let decode (s: state): Cfa.State.t * Data.Address.t =
    let str = String.sub s.buf 0 4 in
    let instruction = build_instruction s str in
    let stmts = match (instruction lsr 26) land 0x3 with
    | 0b00 ->
       begin
         match (instruction lsr 22) land 0xf with
         | 0b0000 -> (* multiply *) error s.a "Multiply not implemented"
         | 0b0100 | 0b0101 -> (* single data swap *) error s.a "single data swap not implemented"
         | _ -> (* data processing / PSR transfer *) data_proc s instruction
       end
    | 0b01 -> (* single data transfer *) error s.a "single data transfer implemented" (* XXX: check undefined p.19 *)
    | 0b10 ->
       begin
         match (instruction lsr 25) land 1 with
         | 0 -> (* block data transfer *) error s.a "block data transfer not implemented"
         | 1 -> (* branch *) error s.a "branch not implemented"
         | _ -> error s.a (Printf.sprintf "Unknown opcode 0x%x" instruction)
       end
    | 0b11 ->
       begin
         match (instruction lsr 24) land 3 with
         | 0b11 -> (* software interrupt *) error s.a (Printf.sprintf "software interrup not implemented (swi=%08x)" instruction)
         | _ -> (* coproc *) error s.a "coprocessor operation not implemented"
       end
    | _ -> error s.a (Printf.sprintf "Unknown opcode 0x%x" instruction) in
    let stmts_cc = match (instruction lsr 28) land 0xf with
    | 0xf -> []    (* never *) 
    | 0xe -> stmts (* always *) 
    | _ as cc -> wrap_cc cc stmts in
    return s instruction stmts_cc


  let parse text cfg _ctx state addr _oracle =
    let s =  {
      g = cfg;
      b = state;
      a = addr;
      buf = text;
      endianness = !Config.endianness
    }
    in
    try
      let v', ip' = decode s in
      Some (v', ip', ())
    with
      | Exceptions.Error _ as e -> raise e
      | _  -> (*end of buffer *) None

  let init () = ()
end
