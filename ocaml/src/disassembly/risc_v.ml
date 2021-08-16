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
  module Cfa = Cfa.Make(Domain)
             
  type state = {
    mutable g: Cfa.t; (** current cfa *)
    mutable b: Cfa.State.t; (** state predecessor *)
    a: Address.t; (** current address to decode *)
    buf: string; (** buffer to decode *)
    mutable addr_sz: int; (** address size in bits *)
    }

  module Imports = RiscVImports.Make(Domain)(Stubs)

  type type_kind =
    | R
    | I
    | S
    | B
    | U
    | J
 
  (************************************************************************)
  (* Creation of the general purpose registers *)
  (************************************************************************)

  (* correspondence between ABI mnemonics and actual registers can be found
     here: https://github.com/riscv/riscv-elf-psabi-doc/blob/master/riscv-elf.md#named-abis
   *)
  let (register_tbl: (int, Register.t) Hashtbl.t) = Hashtbl.create 16;;
  (*  let x0 = Register.make ~name:"x0" ~size:Isa.xlen;; (* hardcoded to zero *) see Vol I*)
  let x1 = Register.make ~name:"x1" ~size:Isa.xlen;;
  let x2 = Register.make ~name:"x2" ~size:Isa.xlen;;
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
  let get_opcode (bit_array: int Array.t): int =
    let rec acc res n =
      if n = 0 then
        res + bit_array.(n)
      else
        acc (res lsl 1 + bit_array.(n)) (n-1)
    in
    acc 0 6

 
  let i_type opcode = failwith "not yet implemented"

  (** fatal error reporting *)
  let error a msg =
    L.abort (fun p -> p "at %s: %s" (Address.to_string a) msg)
    
  let decode s: Cfa.State.t * Data.Address.t =
    let str = String.sub s.buf 0 4 in
    let len = String.length str in
    let bit_array = Array.make len 0 in
    fill_bit_array bit_array str len;
    let opcode = get_opcode bit_array in
    match opcode with
    | 0b0000011 -> (* I-type *) i_type opcode
    | _ -> error s.a (Printf.sprintf "unknown opcode %x\n" opcode)
    
  let parse text cfg _ctx state addr _oracle =
     let s =  {
      g = cfg;
      b = state;
      a = addr;
      buf = text;
      addr_sz = Isa.xlen;
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

let overflow_expression () = failwith "Not implemented" (* see comment section 2.4, Vol 1 *)
end
