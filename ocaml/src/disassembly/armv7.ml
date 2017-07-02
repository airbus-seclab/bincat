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

  let data_proc s instruction =
    let rd = (instruction lsr 12) land 0xf in
    let _rn = (instruction lsr 16) land 0xf in
    let is_imm = (instruction lsr 25) land 1 in
    let _set_cond_codes = (instruction lsr 20) land 1 in
    let op2_stmt =
      if is_imm = 0 then
        let shift = (instruction lsr 4) land 0xff in
        let rm = instruction land 0xf in
        BinOp(Shl, Lval (V (reg rm)), const shift 32)
      else
        let shift = (instruction lsr 8) land 0xf in
        let imm = instruction land 0xff in
        const (imm lsr shift) 32
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
    | _ -> error s.a (Printf.sprintf "Unknown opcode 0x%x" instruction)
       in
       return s instruction stmt

  let decode (s: state): Cfa.State.t * Data.Address.t =
    let str = String.sub s.buf 0 4 in
    let instruction = build_instruction s str in
    match (instruction lsr 26) land 0x3 with
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
    | _ -> error s.a (Printf.sprintf "Unknown opcode 0x%x" instruction)


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
