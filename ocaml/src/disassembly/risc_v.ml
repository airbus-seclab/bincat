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
module Make(Domain: Domain.T)(Stubs: Stubs.T with type domain_t := Domain.t)(Isa: sig val xlen: int end) =
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

  let get_opcode str =
    String.get str 25
    
  let decode s instr_sz: Cfa.State.t * Data.Address.t =
    let str = String.sub s.buf 0 4 in
    let opcode = get_opcode str in
      match str with
    
  let parse text cfg _ctx state addr oracle =
     let s =  {
      g = cfg;
      b = state;
      a = addr;
      buf = text;
      addr_sz = Isa.xlen;
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
