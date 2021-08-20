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

  module Imports = RiscVImports.Make(Domain)(Stubs)

  type type_kind =
    | R | I | S
    | B | U | J
 
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
  let x2 = Register.make ~name:"x2" ~size:Isa.xlen;; (* standard stack pointer *)
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
                                  

  (* convert a string of bits into an integer array *)
  let fill_bit_array bit_array str len =
    let convert (c: char): int =
      match c with
      | '0' -> 0
      | '1' -> 1
      | _ -> L.abort (fun p -> p "invalid bit char")
    in
    (* we revert the bit orders to get the number as in the spec, ie the first bit of the string is numbered 31 while the last bit of the string is the zeroth bit *)
    String.iteri (fun i c -> Array.set bit_array (convert c) (len-i)) str;;
  

  (* opcode is bits 6 to 0 *)
  let get_opcode (bits: int Array.t): int =
    let rec acc n =
      if n = 0 then
        bits.(n)
      else
        bits.(n) lsl n + (acc (n-1))
    in
    acc 6

 
  (* returns an int from the b-th to u-th bits of bit_array left-shifted by o *)
  let get_range_immediate bits o l u =
    let rec acc i =
      if i > u then 0
      else
        bits.(i) lsl (i+o) + (acc (i-1))
    in
    acc l

  let get_z_immediate bits o l u = Z.of_int (get_range_immediate bits o l u)

  (* figure 2.4 *)
  let i_immediate bits =
    let z1 = Z.of_int bits.(20) in
    let z2 = get_z_immediate bits 1 21 24 in
    let z3 = get_z_immediate bits 5 25 30 in
    let z4 = Z.of_int (bits.(31) lsl 11) in
    let z = List.fold_left (fun z' zi -> Z.add z' zi) Z.zero [z1; z2; z3; z4] in  
    sign_extension z 12 32

  let s_immediate bits =
    let z1 = Z.of_int bits.(7) in
    let z2 = get_z_immediate bits 1 8 11 in
    let z3 = get_z_immediate bits 5 25 30 in
    let z4 = Z.of_int (bits.(31) lsl 11) in
    let z = List.fold_left (fun z' zi -> Z.add z' zi) Z.zero [z1; z2; z3; z4] in  
    sign_extension z 12 32

  let b_immediate bits =
    let z1 = get_z_immediate bits 1 8 11 in
    let z2 = get_z_immediate bits 5 25 30 in
    let z3 = Z.of_int (bits.(7) lsl 11) in
    let z4 = Z.of_int (bits.(31) lsl 12) in
    let z = List.fold_left (fun z' zi -> Z.add z' zi) Z.zero [z1; z2; z3; z4] in  
    sign_extension z 13 32

  let u_immediate bits =
    let z1 = get_z_immediate bits 12 19 12 in
    let z2 = get_z_immediate bits 20 30 20 in
    let z3 = Z.of_int (bits.(31) lsl 31) in
    List.fold_left (fun z' zi -> Z.add z' zi) Z.zero [z1; z2; z3]
    
  let j_immediate bits =
    let z1 = get_z_immediate bits 21 24 1 in
    let z2 = get_z_immediate bits 25 30 5 in
    let z3 = Z.of_int (bits.(20) lsl 6) in
    let z4 = get_z_immediate bits 12 19 12 in
    let z5 = Z.of_int (bits.(31) lsl 20) in
    let z = List.fold_left (fun z' zi -> Z.add z' zi) Z.zero [z1; z2; z3; z4; z5] in
    sign_extension z 21 32
                       
  let get_immediate kind bits =
    match kind with
    | I -> i_immediate bits
    | S -> s_immediate bits
    | B -> b_immediate bits
    | U -> u_immediate bits 
    | J -> j_immediate bits
    | R -> L.abort (fun p -> p "no R-immediate defined in the spec")  
 

  (* figure 2.3, row B-type *)
  let b_decode bits =                  
    let funct3 = get_range_immediate bits 12 14 0 in
    let rs1 = get_range_immediate bits 15 19 0 in
    let rs2 = get_range_immediate bits 20 24 0 in
    let offset = get_immediate B bits in
    offset, rs1, rs2, funct3

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
    let a' = Address.add_offset s.a (sign_extension offset 12 32) in
    [If (Cmp(bop, Lval (get_register rs1), Lval (get_register rs2)), [Jmp (A a')], [Nop])]
      
  let decode (s: state): Cfa.State.t * Data.Address.t =
    let str = String.sub s.buf 0 4 in
    let len = String.length str in
    let bits = Array.make len 0 in
    fill_bit_array bits str len;
    let opcode = get_opcode bits in
    let stmts =
      match opcode with
      | 0b1100011 -> comparison s bits
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
