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
    }

  module Imports = RiscVImports.Make(Domain)(Stubs)

                   (************************************************************************)
  (* Creation of the general purpose registers *)
  (************************************************************************)
  let (register_tbl: (int, Register.t) Hashtbl.t) = Hashtbl.create 16;;
  (*  let x0 = Register.make ~name:"x0" ~size:!Config.address_sz;; (* hardcoded to zero *) see Vol I*)
  let x1 = Register.make ~name:"x1" ~size:!Config.address_sz;;
  let x2 = Register.make ~name:"x2" ~size:!config.address_sz;;
  let x3 = Register.make ~name:"x3" ~size:!config.address_sz;;
  let x4 = Register.make ~name:"x4" ~size:!Config.address_sz;;
  let x5 = Register.make ~name:"x5" ~size:!Config.address_sz;;
  let x6 = Register.make ~name:"x6" ~size:!Config.address_sz;;
  let x7 = Register.make ~name:"x7" ~size:!Config.address_sz;;
  let x8 = Register.make ~name:"x8" ~size:!Config.address_sz;;
  let x9 = Register.make ~name:"x9" ~size:!Config.address_sz;;
  let x10 = Register.make ~name:"x10" ~size:!Config.address_sz;;
  let x11 = Register.make ~name:"x11" ~size:!Config.address_sz;;
  let x12 = Register.make ~name:"x12" ~size:!Config.address_sz;;
  let x13 = Register.make ~name:"x13" ~size:!Config.address_sz;;
  let x14 = Register.make ~name:"x14" ~size:!Config.address_sz;;
  let x15 = Register.make ~name:"x15" ~size:!Config.address_sz;;
  let x16 = Register.make ~name:"x16" ~size:!Config.address_sz;;
  let x17 = Register.make ~name:"x17" ~size:!Config.address_sz;;
  let x18 = Register.make ~name:"x18" ~size:!Config.address_sz;;
  let x19 = Register.make ~name:"x19" ~size:!Config.address_sz;;
  let x20 = Register.make ~name:"x20" ~size:!Config.address_sz;;
  let x21 = Register.make ~name:"x21" ~size:!Config.address_sz;;
  let x22 = Register.make ~name:"x22" ~size:!Config.address_sz;;
  let x23 = Register.make ~name:"x23" ~size:!Config.address_sz;;
  let x24 = Register.make ~name:"x24" ~size:!Config.address_sz;;
  let x25 = Register.make ~name:"x25" ~size:!Config.address_sz;;
  let x26 = Register.make ~name:"x26" ~size:!Config.address_sz;;
  let x27 = Register.make ~name:"x27" ~size:!Config.address_sz;;
  let x28 = Register.make ~name:"x28" ~size:!Config.address_sz;;
  let x29 = Register.make ~name:"x29" ~size:!Config.address_sz;;
  let x30 = Register.make ~name:"x30" ~size:!Config.address_sz;;
  let x31 = Register.make ~name:"x31" ~size:!Config.address_sz;;

  let get_opcode str =
    String.get str 25
 

  (* helpers to get instruction chuncks *)
  let extract_opcode word = word & 0b1111111
                          
  let extract word l u =
    let n = 32-u in
    (word lsr n) lsl (n+l)
    
  let get_rd word = extract word 7 11
  let get_funct3 word = extract word 12 14
  let get_rs1 word = extract word 15 19
  let get_rs2 word = extract word 20 24
                   
  let extract_rtype_fields word =
    let opcode = extract_opcode word in
    let rd = get_rd word 7 in
    let funct3 = get_funct3 word in
    let rs1 = get_rs1 word in
    let rs2 = get_rs2 word in
    let funct7 = extract word 25 31 in
    funct7, rs2, rs1, funct3, rd, opcode
    
  let extract_itype_fields word =
    let opcode = extract_opcode word in
    let rd = get_rd word in
    let funct3 = get_funct3 word in
    let rs1 = get_rs1 word in
    let imm = extract word 20 31 in
    imm, rs1, funct3, rd, opcode
      
  let extract_stype_fields word =
    let opcode = extract_opcode word in
    let rs1 = get_rs1 word in
    let rs2 = get_rs2 word in
    let funct3 = get_funct3 word in
    let imm = ((extract word 25 31) lsr 5) | (extract word 7 11) in
    imm, rs2, rs1, funct3, opcode                  
    
  let extract_utype_fields word =
    let opcode = extract_opcode word in
    let rd = get_rd word in
    let imm = extract word 12 31 in
    imm, rd, opcode                  
    
  let parse text cfg _ctx state addr oracle =
     let s =  {
      g = cfg;
      b = state;
      a = addr;
      buf = text;
      addr_sz = !Config.address_sz;
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
