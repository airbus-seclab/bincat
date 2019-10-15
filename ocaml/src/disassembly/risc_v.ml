(*
    This file is part of BinCAT.
    Copyright 2014-2019 - Airbus

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

(* implements at least RV32I and RV64I ISA as stated in spec v2.2 *)
module L = Log.Make(struct let name = "risc_v" end)
module Make(Domain: Domain.T)(Stubs: Stubs.T with type domain_t := Domain.t) =
struct

  type ctx_t = unit

  open Data
  open Asm
     
  module Cfa = Cfa.Make(Domain)
             
  type state = {
    mutable g: Cfa.t; (** current cfa *)
    mutable b: Cfa.State.t; (** state predecessor *)
    a: Address.t; (** current address to decode *)
    buf: string; (** buffer to decode *)
    mutable addr_sz: int; (** address size in bits *)
    mutable c: char list;   (** current decoded bytes in reverse order  *)
    }

  module Imports = RiscVImports.Make(Domain)(Stubs)
  let xlen = !Config.address_sz

  (************************************************************************)
  (* Creation of the general purpose registers *)
  (************************************************************************)
  let (register_tbl: (int, Register.t) Hashtbl.t) = Hashtbl.create 16;;
  let x0 = Register.make ~name:"x0" ~size:xlen;; (* hardcoded to zero see Vol I*)
  let x1 = Register.make ~name:"x1" ~size:xlen;;
  let x2 = Register.make ~name:"x2" ~size:xlen;;
  let x3 = Register.make ~name:"x3" ~size:xlen;;
  let x4 = Register.make ~name:"x4" ~size:xlen;;
  let x5 = Register.make ~name:"x5" ~size:xlen;;
  let x6 = Register.make ~name:"x6" ~size:xlen;;
  let x7 = Register.make ~name:"x7" ~size:xlen;;
  let x8 = Register.make ~name:"x8" ~size:xlen;;
  let x9 = Register.make ~name:"x9" ~size:xlen;;
  let x10 = Register.make ~name:"x10" ~size:xlen;;
  let x11 = Register.make ~name:"x11" ~size:xlen;;
  let x12 = Register.make ~name:"x12" ~size:xlen;;
  let x13 = Register.make ~name:"x13" ~size:xlen;;
  let x14 = Register.make ~name:"x14" ~size:xlen;;
  let x15 = Register.make ~name:"x15" ~size:xlen;;
  let x16 = Register.make ~name:"x16" ~size:xlen;;
  let x17 = Register.make ~name:"x17" ~size:xlen;;
  let x18 = Register.make ~name:"x18" ~size:xlen;;
  let x19 = Register.make ~name:"x19" ~size:xlen;;
  let x20 = Register.make ~name:"x20" ~size:xlen;;
  let x21 = Register.make ~name:"x21" ~size:xlen;;
  let x22 = Register.make ~name:"x22" ~size:xlen;;
  let x23 = Register.make ~name:"x23" ~size:xlen;;
  let x24 = Register.make ~name:"x24" ~size:xlen;;
  let x25 = Register.make ~name:"x25" ~size:xlen;;
  let x26 = Register.make ~name:"x26" ~size:xlen;;
  let x27 = Register.make ~name:"x27" ~size:xlen;;
  let x28 = Register.make ~name:"x28" ~size:xlen;;
  let x29 = Register.make ~name:"x29" ~size:xlen;;
  let x30 = Register.make ~name:"x30" ~size:xlen;;
  let x31 = Register.make ~name:"x31" ~size:xlen;;

  let reg_tbl = Hashtbl.create 32;;

  List.iteri (fun i reg -> Hashtbl.add reg_tbl i reg) [
      x0; x1; x2; x3; x4; x5; x6; x7; x8; x9; x10; x11; x12; x13; x14;
      x15; x16; x17; x18; x19; x20; x21; x22; x23; x24; x25; x26; x27;
      x28; x29; x30; x31 ];;

  let get_register (i: int): lval = V ( T(Hashtbl.find reg_tbl i))
    
  (* helpers to get instruction chunks *)
  let extract_opcode word_str =
    let word = Char.code (String.get word_str 3) in
    word land 0b01111111
                          
  let extract (word_str: string) (l: int) (u: int): int =
    let ubyte = u / 8 in
    let rec get_bytes n =
      if n <= ubyte then
        (Char.code (String.get word_str n))::(get_bytes (n+1))
      else []
    in
    let rec to_int bytes n =
      let cbyte = List.hd bytes in
      let tl = List.tl bytes in
      match n with
      | 0 -> (cbyte lsr l)+(to_int tl (n+1))
      | n when n = ubyte ->
         let n = 8 - (u mod 8) in
         ((cbyte lsr n) lsl n) lsl (ubyte*8)
      | _ -> (cbyte lsl (n*8)) + (to_int tl (n+1))
    in
    let bytes = get_bytes 0 in
    to_int bytes 0
    
  let get_rd word =
    let xi = extract word 7 11 in
    get_register xi, xi=0

  let get_funct3 word = extract word 12 14

  let get_rs1 word =
    let xi = extract word 15 19 in
    get_register xi, xi=0
    
  let get_rs2 word = get_register (extract word 20 24)
                   
  let get_rtype_fields word =
    let rd, _rd_is_x0 = get_rd word in
    let funct3 = get_funct3 word in
    let rs1, _rs1_is_x0 = get_rs1 word in
    let rs2 = get_rs2 word in
    let funct7 = extract word 25 31 in
    funct7, rs2, rs1, funct3, rd
    
  let get_itype_fields word =
    let rd, rd_is_x0 = get_rd word in
    let funct3 = get_funct3 word in
    let rs1, rs1_is_x0 = get_rs1 word in
    let imm = extract word 20 31 in
    imm, (rs1, rs1_is_x0), funct3, (rd, rd_is_x0)
    
  let get_stype_fields word =
    let rs1, _rs1_is_x0 = get_rs1 word in
    let rs2 = get_rs2 word in
    let funct3 = get_funct3 word in
    let imm = ((extract word 25 31) lsl 5) lor (extract word 7 11) in
    imm, rs1, rs2, funct3                  

  let get_btype_fields word =
    let funct3 = get_funct3 word in
    let rs1, _rs1_is_x0 = get_rs1 word in
    let rs2 = get_rs2 word in
    let imm11 = extract word 7 7 in
    let imm12 = extract word 31 31 in
    let imm4_11 = extract word 8 11 in
    let imm5_10 = extract word 25 30 in
    let imm =
      (imm4_11 lsl 1) lor (imm5_10 lsl 5) lor
        (imm11 lsl 11) lor (imm12 lsl 12)
    in
    imm, rs1, rs2, funct3

  let get_utype_fields word =
    let rd, _rd_is_x0 = get_rd word in
    let imm = extract word 12 31 in
    imm, rd               

  let get_jtype_fields word =
    let rd, _rd_is_x0 = get_rd word in
    let imm1_10 = extract word 21 30 in
    let imm11 = extract word 11 11 in
    let imm20 = extract word 20 20 in
    let imm12_19 = extract word 12 19 in
    let imm =
      imm1_10 lor (imm11 lsl 11) lor
        (imm12_19 lsl 12) lor (imm20 lsl 20)
    in
    imm, rd
    
  let sx e = UnOp (SignExt xlen, e)
  let ux e = UnOp (ZeroExt xlen, e)

  let const i len = Const (Word.of_int (Z.of_int i) len)
                  
  let decode_itype word opcode =
    let imm, (rs1, rs1_is_x0), funct3, (rd, rd_is_x0) = get_itype_fields word in
    let imm_const = const imm xlen in
    match opcode with
    | 0b0000011 -> (* LOAD *)
       begin
         if rd_is_x0 then L.abort (fun p -> p "illegal x0 destination in store");
         let binop op sz =
           let e = Lval (M (BinOp (Add, Lval rs1, imm_const), sz)) in
           let e' =
             if sz = xlen then e
             else UnOp(op, e)
           in
           [ Set (rd, e') ]
         in
         match funct3 with
         | 0b000 -> (* LB *) binop (SignExt 8) 8
         | 0b001 -> (* LH *) binop (SignExt 16) 16
         | 0b010 -> (* LW *) binop (SignExt 32) 32
         | 0b011 -> (* LD *)
            if xlen = 64 then binop (SignExt 64) 64
            else L.abort (fun p -> p "no LD instruction in RV32")
           
         | 0b100 -> (* LBU *) binop (ZeroExt 8) 8
         | 0b101 -> (* LHU *) binop (ZeroExt 16) 16
         | 0b111 -> (* LWU *)
            if xlen=32 then L.abort (fun p -> p "no LWU in RV32")
            else binop (ZeroExt xlen) xlen

         |  _ -> L.abort (fun p -> p "illegal load opcode %d in itype instruction" funct3)
       end
    | 0b0010011 ->
       begin
         let binop op = [ Set (rd, BinOp (op, Lval rs1, imm_const)) ] in
         match funct3 with
         | 0b000 -> (* ADDI *)
            if rd_is_x0 && rs1_is_x0 && imm = 0 then
              [ Nop ]
            else binop Add
           
         | 0b010 -> (* SLTI *)
            let len = xlen+1 in
            let e = BinOp (Sub, UnOp(SignExt len, Lval rs1), UnOp(SignExt len, imm_const)) in
            [ Set (rd, UnOp (ZeroExt xlen, BinOp(Shr, e, const len xlen))) ]
            
         | 0b011 -> (* STLIU *)
            [ Set (rd, TernOp(Cmp(LT, Lval rs1, imm_const), const 1 xlen, const 0 xlen)) ]
           
         | 0b100 -> (* XORI *) binop Xor
         | 0b110 -> (* ORI *) binop Or
         | 0b111 -> (* ANDI *) binop And                          
         | 0b001 -> (* SLLI *) binop Shl                          
         | 0b101 ->
            begin
              match imm with
              | 0b0000000 -> (* SRLI *) binop Shr
              | 0b0100000 -> (* SRAI *)
                 [ Set (rd, UnOp (SignExt xlen, BinOp(Shr, Lval rs1, imm_const))) ]
              
              | _ -> L.abort (fun p -> p "illegal immediate %d in I-type instruction" imm)
            end
         | _ -> L.abort (fun p -> p "illegal funct3 value %d in I-type instruction" funct3)
       end
    | _ -> L.abort (fun p -> p "illegal opcode %d in I-type instruction" opcode)
            
  let decode_rtype word =
    let funct7, rs2, rs1, funct3, rd = get_rtype_fields word in
    let rs2_reg = Lval rs2 in
    let rs1_reg = Lval rs1 in
    let binop op =
      [ Set (rd, BinOp (op, rs1_reg, rs2_reg)) ]
    in
    match funct3, funct7 with
    | 0b000, 0b0000000 -> (* ADD *) binop Add 
    | 0b000, 0b0100000 -> (* SUB *) binop Sub 
  
    | 0b001, 0b0000000 -> (* SLL *) binop Shl
       
    | 0b010, 0b0000000 -> (* SLT *)
       (* rd = rs1 < rs2, signed *)
       let len = xlen+1 in
       let e = BinOp (Sub, UnOp(SignExt len, rs1_reg), UnOp(SignExt len, rs2_reg)) in
       [ Set (rd, TernOp(Cmp(LT, e, const 0 len), const 1 xlen, const 0 xlen)) ]
       
    | 0b011, 0b0000000 -> (* SLTU *)
       (* rd = rs1 < rs2, unsigned *)
       [ Set (rd, TernOp(Cmp(LT, rs1_reg, rs2_reg), const 1 xlen, const 0 xlen)) ]
      
    | 0b100, 0b0000000 -> (* XOR *) binop Xor 
    | 0b101, 0b0000000 -> (* SRL *) binop Shr 
       
    | 0b101, 0b0100000 -> (* SRA *)
       [ Set (rd, UnOp (SignExt xlen, BinOp(Shr, Lval rs1, Lval rs2))) ]
       
    | 0b110, 0b0000000 -> (* OR *) binop Or 
    | 0b111, 0b0000000 -> (* AND *) binop And 

    | _ -> L.abort (fun p -> p "illegal combination of funct7=%d and funct3=%d in R-type instruction" funct7 funct3)

  let decode_stype word =
    let imm, rs1, rs2, funct3 = get_stype_fields word in
    let store sz =
      let addr = BinOp (Add, Lval rs1, const imm xlen) in
      [ Set (rs2, Lval (M(addr, sz))) ]
    in
    match funct3 with
    | 0b000 -> (* SB *) store 8
    | 0b001 -> (* SH *) store 16
    | 0b010 -> (* SW *) store 32
    | 0b100 -> (* SD *)
       if xlen = 64 then store 64
       else L.abort (fun p -> p "illegal SD instruction in S-type of RV32")
    | _ -> L.abort (fun p -> p "illegal funct3 %d in S-type instruction" funct3)

  let decode_btype a word =
    let imm, rs1, rs2, funct3 = get_btype_fields word in
    let rs1_exp = Lval rs1 in
    let rs2_exp = Lval rs2 in
    let cond =
      match funct3 with
      | 0b000 -> (* BEQ *) Cmp (EQ, rs1_exp, rs2_exp)
      | 0b001 -> (* BNE *) Cmp (NEQ, rs1_exp, rs2_exp)
      | 0b100 -> (* BLT *) Cmp (LT, rs1_exp, rs2_exp)
      | 0b101 -> (* BGE *) Cmp (GEQ, rs1_exp, rs2_exp) 
      | 0b110 -> (* BLTU *)
         let len = xlen+1 in
         Cmp (LT, BinOp (Sub, UnOp(SignExt len, rs1_exp), UnOp(SignExt len, rs2_exp)),
              const 0 len)
         
      | 0b111 -> (* BGEU *)
         let len = xlen+1 in
         Cmp (GEQ, BinOp (Sub, UnOp(SignExt len, rs1_exp), UnOp(SignExt len, rs2_exp)),
              const 0 len)
         
      | _ -> L.abort (fun p -> p "illegal funct3 in b-type instructions")
    in
    let target = Data.Address.add_offset a (Z.of_int imm) in
    let ip' = Data.Address.add_offset a (Z.of_int 4) in
    [ If (cond, [Jmp (A target)], [Jmp (A ip')]) ]
    
  let decode_utype a opcode word =
    let imm, rd = get_utype_fields word in
    match opcode with
    | 0b0110111 -> (* LUI *) [ Set (rd, const (imm lsl 12) 32) ] 
    | 0b0010111 -> (* AUIPC *)
       let ip' = Data.Address.add_offset a (Z.of_int imm) in
       let c = Const (Word.of_int (Data.Address.to_int ip') 32) in
       [ Set (rd, c) ; Jmp (A ip') ]
    | _ -> L.abort (fun p -> p "illegal funct3 in U-type instruction")

  let z4 = Z.of_int 4
         
  let decode_jal a word =
    let imm, rd = get_jtype_fields word in
    let ip4 = Data.Address.add_offset a z4 in
    let ip' = Data.Address.add_offset a (Z.of_int imm) in
    let c = Const (Word.of_int (Data.Address.to_int ip4) xlen) in
    [ Set (rd, c) ; Jmp (A ip') ]
       
   
  let decode_jalr a word =
    let imm, (rs1, _is_rs1_x0), funct3, (rd, _is_rd_x0) = get_itype_fields word in
    if funct3 <> 0b000 then
      L.abort (fun p -> p "illegal func3 value (%d) in JALR decoding" funct3);
    let ip4 = Data.Address.add_offset a z4 in
    let ip' = BinOp(Add, Lval rs1, const imm xlen) in
    let c = Const (Word.of_int (Data.Address.to_int ip4) xlen) in
    [ Set (rd, c) ; Jmp (R ip') ]

  let return s stmts =
    s.b.Cfa.State.stmts <- stmts;
    s.b.Cfa.State.bytes <- s.c;
    s.b

  let decode (s: state): Cfa.State.t =
    let instruction = String.sub s.buf 0 4 in
    String.iter (fun c -> s.c <- c::s.c) instruction;
    s.c <- List.rev s.c;
    let opcode = extract_opcode instruction in
    match opcode with
    | 0b0110011 -> return s (decode_rtype instruction)
    | 0b0010011 | 0b0000011 -> return s (decode_itype instruction opcode)
    | 0b0100011 -> return s (decode_stype instruction)
    | 0b1100011 -> return s (decode_btype s.a instruction)
    | 0b0110111 | 0b0010111 -> return s (decode_utype s.a opcode instruction)
    | 0b1100111 -> (* JALR *) return s (decode_jalr s.a instruction)
    | 0b1101111 -> return s (decode_jal s.a instruction)
    | _ -> L.abort (fun p -> p "non recognized type of instructions")

         
  let parse text cfg _ctx state addr _oracle =
     let s =  {
      g = cfg;
      b = state;
      a = addr;
      buf = text;
      addr_sz = xlen;
      c = [];
    }
    in
    try
      let v' = decode s in
      let ip' = Data.Address.add_offset addr (Z.of_int (s.addr_sz/8)) in
      Some (v', ip', ())
    with
    | Exceptions.Error _ as e -> raise e
    | _  -> (*end of buffer *) None

let init_registers () = ()
let init () = Imports.init ()

let overflow_expression () = failwith "There is no overflow flag in RISC-V" (* see comment section 2.4, Vol 1 *)
end
