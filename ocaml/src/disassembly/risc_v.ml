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

(* implements at least RV32I and RV64I ISA as stated in spec v2.1
https://github.com/riscv/riscv-isa-manual/releases/download/Ratified-IMAFDQC/riscv-spec-20191213.pdf *)
module L = Log.Make(struct let name = "risc_v" end)

(* XLEN refers to the width of an integer register in bits (either 32 or 64), see section 1.3) *)

(* 32I ISA *)
module I32 = struct let xlen = 32 end

(* 64I ISA *)
module I64 = struct let xlen = 64 end
           
module Make(Isa: sig val xlen: int end)(Domain: Domain.T)(Stubs: Stubs.T with type domain_t := Domain.t) =
struct

  type ctx_t = unit

  open Data
  open Asm
  open Decodeutils
     

  module Cfa = Cfa.Make(Domain)
             
  type state = {
    mutable g: Cfa.t; (** current cfa *)
    mutable b: Cfa.State.t; (** state predecessor *)
    a: Address.t; (** current address to decode *)
    buf: string; (** buffer to decode *)
    mutable operand_sz: int; (** operand size in bits *)
    }


  type type_kind =
    | R | I | S
    | B | U | J | IW (* I-immediate kind of word-size *)
 
  (************************************************************************)
  (* Creation of the general purpose registers *)
  (************************************************************************)

  (* correspondence between ABI mnemonics and actual registers can be found
     here: https://github.com/riscv/riscv-elf-psabi-doc/blob/master/riscv-elf.md#named-abis
   *)

  (* page 14: There is no dedicated stack pointer or subroutine return address link register in the Base Integer
     ISA; the instruction encoding allows any x register to be used for these purposes. However, the
     standard software calling convention uses register x1 to hold the return address for a call, with
     register x5 available as an alternate link register. The standard calling convention uses register
     x2 as the stack pointer *)
  let (register_tbl: (int, Register.t) Hashtbl.t) = Hashtbl.create 33;;
  let x0 = Register.make ~name:"x0" ~size:Isa.xlen;; (* hardcoded to zero *)
  let x1 = Register.make ~name:"x1" ~size:Isa.xlen;; (* standard return address ; fallback is x5 *)
  let x2 = Register.make_sp ~name:"x2" ~size:Isa.xlen;; (* standard stack pointer *)
  let x3 = Register.make ~name:"x3" ~size:Isa.xlen;;
  let x4 = Register.make ~name:"x4" ~size:Isa.xlen;;
  let x5 = Register.make ~name:"x5" ~size:Isa.xlen;;
  let x6 = Register.make ~name:"x6" ~size:Isa.xlen;;
  let x7 = Register.make ~name:"x7" ~size:Isa.xlen;;
  let x8 = Register.make ~name:"x8" ~size:Isa.xlen;;
  let x9 = Register.make ~name:"x9" ~size:Isa.xlen;;
  let x10 = Register.make ~name:"x10" ~size:Isa.xlen;;
  let x11 = Register.make ~name:"x11" ~size:Isa.xlen;;
  let x12 = Register.make ~name:"x12" ~size:Isa.xlen;;
  let x13 = Register.make ~name:"x13" ~size:Isa.xlen;;
  let x14 = Register.make ~name:"x14" ~size:Isa.xlen;;
  let x15 = Register.make ~name:"x15" ~size:Isa.xlen;;
  let x16 = Register.make ~name:"x16" ~size:Isa.xlen;;
  let x17 = Register.make ~name:"x17" ~size:Isa.xlen;;
  let x18 = Register.make ~name:"x18" ~size:Isa.xlen;;
  let x19 = Register.make ~name:"x19" ~size:Isa.xlen;;
  let x20 = Register.make ~name:"x20" ~size:Isa.xlen;;
  let x21 = Register.make ~name:"x21" ~size:Isa.xlen;;
  let x22 = Register.make ~name:"x22" ~size:Isa.xlen;;
  let x23 = Register.make ~name:"x23" ~size:Isa.xlen;;
  let x24 = Register.make ~name:"x24" ~size:Isa.xlen;;
  let x25 = Register.make ~name:"x25" ~size:Isa.xlen;;
  let x26 = Register.make ~name:"x26" ~size:Isa.xlen;;
  let x27 = Register.make ~name:"x27" ~size:Isa.xlen;;
  let x28 = Register.make ~name:"x28" ~size:Isa.xlen;;
  let x29 = Register.make ~name:"x29" ~size:Isa.xlen;;
  let x30 = Register.make ~name:"x30" ~size:Isa.xlen;;
  let x31 = Register.make ~name:"x31" ~size:Isa.xlen;;

  let reg_tbl = Hashtbl.create 32;;

  List.iteri (fun i reg -> Hashtbl.add reg_tbl i reg) [
      x0; x1; x2; x3; x4; x5; x6; x7; x8; x9; x10; x11; x12; x13; x14;
      x15; x16; x17; x18; x19; x20; x21; x22; x23; x24; x25; x26; x27;
      x28; x29; x30; x31 ];;

  let get_register (i: int): lval = V ( T(Hashtbl.find reg_tbl i))
                                  
  module Imports = RiscVImports.Make(Domain)(Stubs)


  (* opcode is bits 6 to 0 *)
  let get_opcode (bits: int): int =
    bits land 0x7f

  let get_isn str =
    (Char.code (String.get str 0))
    lor ((Char.code (String.get str 1)) lsl 8)
    lor ((Char.code (String.get str 2)) lsl 16)
    lor ((Char.code (String.get str 3)) lsl 24)

  (* returns an int from the l-th to u-th bits, left-shifted by o *)
  let get_range_immediate bits l u o =
    ((bits lsr l) land (lnot (-1 lsl (u-l+1)))) lsl o

  let get_z_immediate bits o l u = Z.of_int (get_range_immediate bits o l u)

  (* figure 2.4 *)
  let i_core_immediate bits sz =
    let z = get_z_immediate bits 20 31 0 in
    sign_extension z 12 sz

  let i_immediate bits = i_core_immediate bits Isa.xlen
  let i_immediate_w bits = i_core_immediate bits 32

  let s_immediate bits =
    let z1 = get_z_immediate bits 7 11 0 in
    let z2 = get_z_immediate bits 25 31 5 in
    let z = Z.logor z1 z2 in
    sign_extension z 12 Isa.xlen

  let b_immediate bits =
    let z1 = get_z_immediate bits 8 11 1 in
    let z2 = get_z_immediate bits 25 30 5 in
    let z3 = get_z_immediate bits 7 7 11 in
    let z4 = get_z_immediate bits 31 31 12 in
    let z = List.fold_left (fun z' zi -> Z.add z' zi) Z.zero [z1; z2; z3; z4] in  
    sign_extension z 13 Isa.xlen

  let u_immediate bits =
    let z = get_z_immediate bits 12 31 12 in
    sign_extension z 32 Isa.xlen

  let j_immediate bits: Z.t =
    let z1 = get_z_immediate bits 21 30 1 in
    let z2 = get_z_immediate bits 20 20 11 in
    let z3 = get_z_immediate bits 12 19 12 in
    let z4 = get_z_immediate bits 31 31 20 in
    let z = List.fold_left (fun z' zi -> Z.add z' zi) Z.zero [z1; z2; z3; z4] in
    sign_extension z 21 Isa.xlen

  (* the result is signed-extended *)
  let get_immediate kind bits =
    match kind with
    | I -> i_immediate bits
    | S -> s_immediate bits
    | B -> b_immediate bits
    | U -> u_immediate bits 
    | J -> j_immediate bits
    | IW -> i_immediate_w bits
    | R -> L.abort (fun p -> p "no R-immediate defined in the spec")  
 

  (* figure 2.3, row B-type *)
  let b_decode bits =                  
    let funct3 = get_range_immediate bits 12 14 0 in
    let rs1 = get_range_immediate bits 15 19 0 in
    let rs2 = get_range_immediate bits 20 24 0 in
    let offset = get_immediate B bits in
    offset, rs1, rs2, funct3

  (* figure 2.3, row J-type *)
  let j_decode bits =
    let rd = get_range_immediate bits 7 11 0 in
    let imm = get_immediate J bits in
    rd, imm

  (* figure 2.3, row I-type *)
  let i_core_decode bits =
    let rd = get_range_immediate bits 7 11 0 in
    let funct3 = get_range_immediate bits 12 14 0 in
    let rs1 = get_range_immediate bits 15 19 0 in
    rs1, funct3, rd

  let i_decode bits =
    let rs1, funct3, rd = i_core_decode bits in
    get_immediate I bits, rs1, funct3, rd
                    
  (* RV64I special instruction of I-type *)
  let iw_decode bits =
    let rs1, funct3, rd = i_core_decode bits in
    get_range_immediate bits 20 31 0, rs1, funct3, rd
    
  (* figure 2.3, row U-type *)
  let u_decode bits =
    let rd = get_range_immediate bits 7 11 0 in
    let imm = get_immediate U bits in
    imm, rd

  (* figure 2.3, row R-type *)
  let r_decode bits =
    let funct7 = get_range_immediate bits 25 31 0 in
    let rs2 = get_range_immediate bits 20 24 0 in
    let rs1 = get_range_immediate bits 15 19 0 in
    let funct3 = get_range_immediate bits 12 14 0 in
    let rd = get_range_immediate bits 7 11 0 in
    funct7, rs2, rs1, funct3, rd

  (* figure 2.3, row S-type *)
  let s_decode bits =
    let rs1 = get_range_immediate bits 15 19 0 in
    let rs2 = get_range_immediate bits 20 24 0 in
    let funct3 = get_range_immediate bits 12 14 0 in
    let imm = get_immediate S bits in
    imm, rs1, rs2, funct3


  (** fatal error reporting *)
  let error a msg =
    L.abort (fun p -> p "at %s: %s" (Address.to_string a) msg)

  let return s str stmts =
    s.b.Cfa.State.stmts <- stmts;
    s.b.Cfa.State.bytes <- string_to_char_list str;
    s.b, Data.Address.add_offset s.a (Z.of_int 4)
    
  let comparison s bits =
    let offset, rs1, rs2, func3 = b_decode bits in
    let bop =
      match func3 with
      | 0b000 -> (* beq *) EQ
      | 0b001 -> (* bne *) NEQ
      | 0b100 -> (* blt *) LTS
      | 0b101 -> (* bge *) GES
      | 0b110 -> (* bltu *) LT
      | 0b111 -> (* bgeu *) GEQ
      | _ -> L.abort (fun p -> p "undefined comparison opcode")
    in
    (* page 22: the offset is signed-extended and added to the address of the 
       branch instruction to give the target address *)
    let a' = Address.add_offset s.a offset in
    [If (Cmp(bop, Lval (get_register rs1), Lval (get_register rs2)), [Jmp (A a')], [Nop])]

  let const z = Const (Data.Word.of_int z Isa.xlen)
  let const_w z = Const (Data.Word.of_int z 32)
                
  let jal s bits =
    let rd, imm = j_decode bits in
    let a = Data.Address.add_offset s.a imm in
    if rd = 0 then
      (* unconditional jump *)
      [Jmp (A a)]
    else
      (* call *)
      let a' = Data.Address.add_offset s.a (Z.of_int 4) in
      [Set(get_register rd, Const (Data.Address.to_word a' Isa.xlen));
       Call (A a)]

  let jalr s bits =
    let offset, rs1, _funct3, rd = i_decode bits in
    (* The target address is obtained by adding the sign-extended 12-bit I-immediate 
       to the register rs1, then setting the least-significant bit of the result to zero *)
    let target = BinOp (And,
                        BinOp(Add, Lval (get_register rs1), const offset),
                        const (Z.of_int 0xFFFFFFFE))
    in
    if rd = 0 then
      [Jmp (R target)]
    else
      let a' = Z.add (Data.Address.to_int s.a) (Z.of_int 4) in
      [Set(get_register rd, const a');
       Call (R target)]

  let lui bits =
    let imm, rd = u_decode bits in
    if rd = 0 then []
    else [ Set (get_register rd, const imm) ]

  let auipc s bits =
    let imm, rd = u_decode bits in
    if rd = 0 then []
    else
      let c = Z.add (Data.Address.to_int s.a) imm in
      [ Set(get_register rd, const c) ]

 
  let shift_imm bits rs1 is_left =
    let b = if Isa.xlen = 32 then 25 else 26 in
    let hi = get_range_immediate bits b 31 0 in
    let lo = const (Z.of_int (get_range_immediate bits 20 (b-1) 0)) in
    match hi, is_left with
    | 0, true -> BinOp (Shl, rs1, lo)
    | 0, false -> UnOp (ZeroExt Isa.xlen, BinOp (Shr, rs1, lo))
    | 16, _ -> UnOp (SignExt Isa.xlen, BinOp (Shr, rs1, lo))
    | _ -> L.abort (fun p -> p "illegal high bits for shift with immediate")
    
  let reg_imm bits =
    let imm, rs1, funct3, rd = i_decode bits in
    if rd = 0 then
      []
    else
      let rs1 = Lval (get_register rs1) in
      let c = const imm in
      let binop op = BinOp (op, rs1, c) in
      let ternop op = TernOp (Cmp (op, rs1, c), const Z.one, const Z.zero) in 
      let e =
        match funct3 with
        | 0 -> (* addi *) binop Add
        | 1 -> (* slli *) shift_imm bits rs1 true           
        | 2 -> (* slti *) ternop LTS
        | 3 -> (* sltiu *) ternop LT
        | 5 -> (* slri / srai *) shift_imm bits rs1 false
        | 4 -> (* xori *) binop Xor
        | 6 -> (* ori *) binop Or
        | 7 -> (* andi *) binop And
        | _ -> L.abort (fun p -> p "undefined register immediate instruction")
      in
      [ Set (get_register rd, e) ]

  let binop_imm_w op res rs1 rd imm ext =
    [
      Set(V (T res), BinOp(op, imm, rs1));
      Set(rd, UnOp(ext, Lval (V (P(res, 0, 31)))));
      Directive(Remove res)
    ]
    
  let reg_imm_w bits =
    let imm, rs1, funct3, rd = iw_decode bits in
    let rs1 = Lval (V (P (Hashtbl.find reg_tbl rs1, 0, 31))) in
    let rd = get_register rd in
    match imm, funct3 with
    | 0, 1 -> (* slliw *)
       let c = const_w (Z.of_int imm) in
       let res = Register.make (Register.fresh_name()) (32+imm) in
       binop_imm_w Shl res rs1 rd c (ZeroExt Isa.xlen) 
       
    | imm, 0 -> (* addiw *)
       let imm = Const (Word.of_int (sign_extension (Z.of_int imm) 12 32) 32) in
       let res = Register.make (Register.fresh_name()) 33 in
       binop_imm_w Add res rs1 rd imm (SignExt Isa.xlen)
       
    | 0, 5 -> (* srliw *) 
       let c = const_w (Z.of_int imm) in
       let res = Register.make (Register.fresh_name()) (32-imm) in
       binop_imm_w Shl res rs1 rd c (ZeroExt Isa.xlen)
       
    | 32, 5 -> (* sraiw *)
       let c = const_w (Z.of_int imm) in
       let res = Register.make (Register.fresh_name()) (32-imm) in
       binop_imm_w Shl res rs1 rd c (SignExt Isa.xlen)
       
    | _, _ -> L.abort (fun p -> p "undefined register-immediate instruction on words")

  let reg_reg_w bits =
    let funct7, rs2, rs1, funct3, rd = r_decode bits in
    let rs1 = Lval (V (P (Hashtbl.find reg_tbl rs1, 0, 31))) in
    let rs2 = Lval (V (P (Hashtbl.find reg_tbl rs2, 0, 31))) in
    if rd = 0 then
      []
    else
      let rd = get_register rd in
      let op, sz, ext =
        match funct3, funct7 with
        | 0, 0 -> (* addw *) Add, 33, None
        | 0, 32 -> (* subw *) Sub, 33, None
        | 1, 0 -> (* sllw *) Shl, 32, None
        | 5, 0 -> (* srlw *) Shr, 64, Some (ZeroExt 32)
        | 5, 32 -> (* sraw *) Shr, 64, Some (SignExt 32)
        | _, _ -> L.abort (fun p -> p "undefined (funct3, funct3) in .w instruction")
      in
      let aux = Register.make (Register.fresh_name()) sz in
      let e = BinOp(op, rs1, rs2) in
      let paux = Lval (V (P (aux, 0, 31))) in
      let e' =
        match ext with
        | Some ext -> UnOp(ext, paux)
        | None -> paux
      in
      [
        Set(V (T aux), e);
        Set(rd, e');
        Directive(Remove aux)
      ]
      
  let reg_reg bits =
    let funct7, rs2, rs1, funct3, rd = r_decode bits in
    if rd = 0 then
      []
    else
      let r1 = Hashtbl.find reg_tbl rs1 in
      let rs1' = Lval(V (T r1)) in
      let rs2' = Lval(get_register rs2) in
      let rd = get_register rd in
      let bin_set op = [Set(rd, BinOp(op, rs1', rs2'))] in
      let tern_set op = [Set (rd, TernOp(Cmp(op, rs1', rs2'), const Z.one, const Z.zero)) ] in
      let low_bit_mask = const (Z.of_int (if Isa.xlen = 32 then 0x1f else 0x3f)) in
      let reg_mask op = BinOp(op, rs1', BinOp(And, rs2', low_bit_mask)) in
      match funct7, funct3 with
      | 0, 0 -> bin_set Add
      | 32, 0 -> bin_set Sub
      | 0, 1 -> (* sll *) [ Set(rd, reg_mask Shl) ]
      | 0, 2 -> (* slt *) tern_set LTS
      | 0, 3 -> (* sltu *)
         if rs1 = 0 then
           let c = Cmp(NEQ, rs2', const Z.zero) in
           [ Set(rd, TernOp(c, const Z.one, const Z.zero)) ]
         else tern_set LT
        
      | 0, 4 -> bin_set Xor
      | 0, 5 -> (* srl *) [ Set (rd, reg_mask Shr) ]
      | 32, 5 -> (* sra *)
         let e = reg_mask Shr in
         [ Set(rd, UnOp(SignExt Isa.xlen, e)) ]
         
      | 0, 6 -> bin_set Or
      | 0, 7 -> bin_set And
      | _ -> L.abort (fun p -> p "undefined (funct7, funct3) pair in Register Register instruction")

    
  let load bits =
    let imm, rs1, funct3, rd = i_decode bits in
    if rd = 0 then
      []
    else
      let rd = get_register rd in
      let rs1 = get_register rs1 in
      let off = const imm in
      let mem = BinOp(Add, Lval rs1, off) in
      let e =
        match funct3 with
        | 0 -> (* lb *) UnOp(SignExt Isa.xlen, Lval (M(mem, 8)))
        | 1 -> (* lh *) UnOp(SignExt Isa.xlen, Lval (M(mem, 16)))
        | 2 -> (* lw *) Lval (M(mem, 32))
        | 4 -> (* lbu *) Lval (M(mem, 8))
        | 5 -> (* lhu *) Lval (M(mem, 16))
        | _ -> L.abort (fun p -> p "undefined funct3 for load")
      in
      [ Set(rd, e) ]

  let store bits =
    let imm, rs1, rs2, funct3 = s_decode bits in
    let rs2 = Lval (get_register rs2) in
    let rs1 = Hashtbl.find reg_tbl rs1 in
    let imm = const imm in
    let lval, sz =
      match funct3 with
      | 0 -> (* sb *) P (rs1, 0, 8), 0 
      | 1 -> (* sh *) P (rs1, 0, 16), 16
      | 2 -> (* sw *) T rs1, Isa.xlen
      | _ -> L.abort (fun p -> p "undefined store kind")
    in
    let src = M(BinOp(Add, rs2, imm), sz) in 
      [ Set (src, Lval (V lval)) ]
        
  let fence bits =
    let funct3 = get_range_immediate bits 12 14 0 in
    match funct3 with
    | 0 (* fence *) | 1 (* fence.i *) -> []
    | _ -> L.abort (fun p -> p "undefined funct3 for fence instructions")
    
  let decode (s: state): Cfa.State.t * Data.Address.t =
    let str = String.sub s.buf 0 4 in
    let bits = get_isn str in
    let opcode = get_opcode bits in 
    let stmts =
      match opcode with
      (* RV32I *)
      | 0b1100011 -> comparison s bits

      | 0b1100111 -> jal s bits
      | 0b1101111 -> jalr s bits

      | 0b0110111 -> lui bits
      | 0b0010111 -> auipc s bits

      | 0b0010011 -> reg_imm bits

      | 0b0110011 -> reg_reg bits

      | 0b0000011 -> load bits

      | 0b0100011 -> store bits

      | 0b0001111 -> fence bits

      (* RV64I *)
      | 0b0011011 -> reg_imm_w bits
      | 0b0111011 -> reg_reg_w bits
                   
      | _ -> error s.a (Printf.sprintf "unknown opcode %x\n" opcode)
    in
    return s str stmts
    
  let parse (text: string) cfg _ctx state addr _oracle =
     let s =  {
      g = cfg;
      b = state;
      a = addr;
      buf = text;
      operand_sz = Isa.xlen;
    }
    in
    try
      let v', ip' = decode s in
      Some (v', ip', ())
    with
    | Exceptions.Error _ as e -> raise e
    | _  -> (*end of buffer *) None

  let init_registers () = (); [x0, Data.Word.of_int Z.zero Isa.xlen]
                          
  let init () = Imports.init ()
              
  let overflow_expression () = failwith "Not implemented" (* see comment section 2.4, Vol 1 *)
end
