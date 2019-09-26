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
  open Decodeutils
     
  module Cfa = Cfa.Make(Domain)
             
  type state = {
    mutable g: Cfa.t; (** current cfa *)
    mutable b: Cfa.State.t; (** state predecessor *)
    a: Address.t; (** current address to decode *)
    buf: string; (** buffer to decode *)
    mutable addr_sz: int; (** address size in bits *)
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
                     
  let get_opcode str =
    String.get str 25
    

  (* helpers to get instruction chunks *)
  let extract_opcode word = word land 0b1111111
                          
  let extract word l u =
    let n = 32-u in
    (word lsr n) lsl (n+l)
    
  let get_rd word = extract word 7 11
  let get_funct3 word = extract word 12 14
  let get_rs1 word = extract word 15 19
  let get_rs2 word = extract word 20 24
                   
  let get_rtype_fields word =
    let rd = get_rd word in
    let funct3 = get_funct3 word in
    let rs1 = get_rs1 word in
    let rs2 = get_rs2 word in
    let funct7 = extract word 25 31 in
    funct7, rs2, rs1, funct3, rd
    
  let get_itype_fields word =
    let rd = get_rd word in
    let funct3 = get_funct3 word in
    let rs1 = get_rs1 word in
    let imm = extract word 20 31 in
    imm, rs1, funct3, rd
      
  let get_stype_fields word =
    let rs1 = get_rs1 word in
    let rs2 = get_rs2 word in
    let funct3 = get_funct3 word in
    let imm = ((extract word 25 31) lsr 5) lor (extract word 7 11) in
    imm, rs1, rs2, funct3                  
    
  let get_utype_fields word =
    let rd = get_rd word in
    let imm = extract word 12 31 in
    imm, rd               

  let sx e = UnOp (SignExt xlen, e)
  let ux e = UnOp (ZeroExt xlen, e)

  let decode_itype word opcode =
    let imm, rs1, funct3, rd = get_itype fields word in
    let rs1_reg = Lval (get_regsiter rs1) in
    let imm_const = Const imm xlen in
    match opcode with
    | 0b0000011 -> (* load *)
       begin
         if rd = 0 then L.error (fun p -> p "illegal x0 destination in store");
         let binop op sz =
           let e = M (BinOp (Add, rs1_reg, imm_const), sz) in
           let e' =
             if sz = xlen then e
             else op (xlen, e)
           in
           [ Set (rd, e') ]
         in
         match func3 with
         | 0b000 -> (* LB *) binop SignExt 8
         | 0b001 -> (* LH *) binop SignExt 16
         | 0b010 -> (* LW *) binop SignExt 32
         | 0b011 -> (* LD *)
            if xlen = 64 then binop SignExt 64
            else L.error (fun p -> p "no LD instruction in RV32")
           
         | 0b100 -> (* LBU *) binop ZeroExt 8
         | 0b101 -> (* LHU *) binop ZeroExt 16
         | 0b111 -> (* LWU *)
            if xlen=32 then L.error (fun p -> p "no LWU in RV32")
            else binop ZeroExt xlen

         |  L.error (fun p -> p "illegal load opcode %d in itype instruction" fun3)
       end
    | 0b0010011 ->
    let binop op =
      [ Set (rd, BinOp (op, rs1_reg, imm_const)) ]
    in
       match func3 with
       | b000 -> (* addi *)
          if rs1 = 0 and rs2 = 0 and imm = 0 then
            [ Nop ]
          else binop Add
                          
       | b010 -> (* slti *)
          let len = xlen+1 in
          let e = BinOp (Sub, SignExt(len, rs1), SignExt(len, imm_const)) in
          [ Set (rd, ZeroExt(xlen, BinOp(Shr, e, len))) ]
          
       | b011 -> (* stliu *)
          [ Set (rd, TernOp(Cmp(LT, rs1_reg, imm_const))) ]
         
       | b100 -> (* xori *) binop Xor
       | b110 -> (* ori *) binop Or
       | b111 -> (* andi *) binop And
                          
       | b001 -> (* slli *) binop Shl
                          
       | b101 -> 
          match imm with
          | 0b0000000 -> (* srli *) binop Shr
          | 0b0100000 -> (* srai *) [ Set (rd, UnOp (SignExt xlen, BinOp(Shr, rs1_reg, imm_const))) ]
                                  
          | _ -> L.error (fun p -> p "illegal immediate %d in itype instruction" imm)
              
  let decode_rtype word =
    let funct7, rs2, rs1, funct3, rd = get_rtype_fields word in
    let rs2_reg = Lval (get_register rs2) in
    let rs1_reg = Lval (get_register rs1) in
    let rd_reg = get_register rd in
    let binop op =
      [ Set (rd, BinOp (op, rs1_reg, rs2_reg)) ]
    in
    match funct3, funct7 with
    | 0b000, 0b0000000 -> (* add *) binop Add 
    | 0b000, 0b0100000 -> (* sub *) binop Sub 
  
    | 0b001, 0b0000000 -> (* sll *) binop Shl
       
    | 0b010, 0b0000000 -> (* slt *)
       (* rd = rs1 < rs2, signed *)
       let len = xlen+1 in
       let e = BinOp (Sub, SignExt(len, rs1), SignExt(len, rs2)) in
       [ Set (rd, ZeroExt(xlen, BinOp(Shr, e, len))) ]
       
    | 0b011, 0b0000000 -> (* sltu *)
       (* rd = rs1 < rs2, unsigned *)
       [ Set (rd, TernOp(Cmp(LT, rs1_reg, rs2_reg))) ]
      
    | 0b100, 0b0000000 -> (* xor *) binop Xor 
    | 0b101, 0b0000000 -> (* srl *) binop Shr 
       
    | 0b101, 0b0100000 -> (* sra *)
       [ Set (rd, UnOp (SignExt xlen, BinOp(Shr, Lval rs1, Lval rs2))) ]
       
    | 0b110, 0b0000000 -> (* or *) binop Or 
    | 0b111, 0b0000000 -> (* and *) binop And 

    | _ -> L.error (fun p -> p "illegal combination of funct7=%d and funct3=%d in R-type instruction" funct7 funct3)

  let decode_stype word =
    let imm, rs1, rs2, funct3 = get_stype_fields word in
    let store sz =
      let addr = BinOp (Add, Lval rs1, Const imm xlen) in
      let data =
        if sz = xlen then rs2
        else
          [ Set ( M(addr, sz), data ) ]
      in
    match funct3 with
    | 0b000 -> (* SB *) store 8
    | 0b001 -> (* SH *) store 16
    | 0b010 -> (* SW *) store 32
    | 0b100 -> (* SD *)
       if xlen = 64 then store 64
       else L.error (fun p -> p "illegal SD instruction in s-type of RV32")

  let decode_btype word =
    let imm, rd = get_u
  let decode s instr_sz: Cfa.State.t * Data.Address.t =
    let str = String.sub s.buf 0 4 in
    let opcode = extract_opcode str in
    match opcode with
    | 0b0110011 -> return s (decode_rtype word)
    | 0b0010011 | 0b0000011 -> return s (decode_itype word opcode)
    | 0b0100011 -> return s (decode_stype word)
    | 0b1100011 -> return s (decode_btype word)
    | _ -> L.error (fun p -> p "non recognized type of instructions")

  let parse text cfg _ctx state addr oracle =
     let s =  {
      g = cfg;
      b = state;
      a = addr;
      buf = text;
      addr_sz = xlen;
    }
    in
    try
      let v' = decode s A in
      let ip' = Data.Address.add_offset addr (s.addr_sz/8) in
      Some (v', ip', ())
    with
    | Exceptions.Error _ as e -> raise e
    | _  -> (*end of buffer *) None

let init_registers () = ()
  let init () =
    Imports.init ()

  let overflow_expression () = Failwith "Not implemented" (* see comment section 2.4, Vol 1 *)
end
