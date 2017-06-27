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
  let sp = Register.make ~name:"sp" ~size:64;; (* stack pointer *)
  
  (* condition flags are modeled as registers of size 1 *)
  let nflag = Register.make ~name:"N" ~size:1;;
  let zflag = Register.make ~name:"Z" ~size:1;;
  let cflag = Register.make ~name:"C" ~size:1;;
  let vflag = Register.make ~name:"V" ~size:1;;

   
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
    let rec build (res: int) (nth: int): int =
      if nth = 3 then res
      else
        let c = String.get str nth in
        build ((res lsl 2) + (Char.code c)) (nth+1)
    in
    build 0 0

  let return (s: state) (str: string) (stmts: Asm.stmt list): Cfa.State.t * Data.Address.t =
    s.b.Cfa.State.stmts <- stmts;
    s.b.Cfa.State.bytes <- string_to_char_list str;
    s.b, Data.Address.add_offset s.a (Z.of_int 4)
      
  let decode (s: state): Cfa.State.t * Data.Address.t =
    let str = String.sub s.buf 0 4 in
    let instruction = build_instruction str in
    match instruction with
    | 0b11010101000000110010000000011111 -> (* NOP *) return s str [Nop]
    | _ -> error s.a (Printf.sprintf "Unknown opcode 0x%x" instruction)

      
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
