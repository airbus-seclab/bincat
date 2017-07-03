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
  open Decodeutils


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
  let sp = Register.make_sp ~name:"sp" ~size:32;;
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

  let return (s: state) (instruction: int) (stmts: Asm.stmt list): Cfa.State.t * Data.Address.t =
    s.b.Cfa.State.stmts <- stmts;
    s.b.Cfa.State.bytes <- [ Char.chr (instruction land 0xff) ;
                             Char.chr ((instruction lsr 8) land 0xff) ;
                             Char.chr ((instruction lsr 16) land 0xff) ;
                             Char.chr ((instruction lsr 24) land 0xff) ];
    (*    s.b.Cfa.State.bytes <- string_to_char_list str; *)
    s.b, Data.Address.add_offset s.a (Z.of_int 4)

  let ror32 value n =
    (value lsr n) lor ((value lsl (32-n)) land 0xffffffff)

  let block_data_transfer s instruction =
    if instruction land (1 lsl 22) <> 0 then error s.a "LDM/STM with S=1 not implemented"
    else
      let rn = (instruction lsr 16) land 0xf in
      let ascend = instruction land (1 lsl 23) <> 0 in
      let dir_op = if ascend then Add else Sub in
      let ofs = ref (if instruction land (1 lsl 24) = 0 then 0 else 4) in
      let store = instruction land (1 lsl 20) = 0 in
      let stmts = ref [] in
      let reg_count = ref 0 in
      for i = 0 to 15 do
        let regtest = if ascend then i else 15-i in
        if (instruction land (1 lsl regtest)) <> 0 then
          begin
            if store then
              stmts := !stmts @
                [ Set( M (BinOp(dir_op, Lval (V (reg rn)), const !ofs 32), 32),
                            Lval (V (reg regtest))) ]
            else
              begin
                stmts := !stmts @
                  [ Set( V (reg regtest),
                         Lval (M (BinOp(dir_op, Lval (V (reg rn)), const !ofs 32), 32))) ]
              end;
            ofs := !ofs+4;
            reg_count := !reg_count + 1
          end
        else ()
      done;
      if instruction land (1 lsl 21) = 0 then
        !stmts
      else
        !stmts @ [ Set (V (reg rn), BinOp(dir_op, Lval (V (reg rn)), const (4*(!reg_count)) 32)) ]


  let branch s instruction =
    let link_stmt = if (instruction land (1 lsl 24)) <> 0 then
        [ Set( V (T lr), Const (Word.of_int (Z.add (Address.to_int s.a) (Z.of_int 4)) 32)) ]
      else
        [ ] in
    let ofs = (instruction land 0xffffff) lsl 2 in
    let ofs32 = if ofs land 0x2000000 <> 0 then ofs lor 0xfc000000 else ofs in (* sign extend 26 bits to 32 bits *)
    link_stmt @ [ Set (V (T pc), BinOp(Add, Lval (V (T pc)), const ofs32 32)) ; 
                  Jmp (R (Lval (V (T pc)))) ]

  let single_data_transfer s instruction = 
    let rd = (instruction lsr 12) land 0xf in
    let rn = (instruction lsr 16) land 0xf in
    let ofs = if instruction land (1 lsl 25) = 0 then (* immediate value *)
        const (instruction land 0xfff) 32
      else
        error s.a "single data xfer offset from reg not implemented" in
    let length = if (instruction land (1 lsl 22)) = 0 then 32 else 8 in
    let updown = if (instruction land (1 lsl 23)) = 0 then Sub else Add in
    let preindex = (instruction land (1 lsl 24)) <> 0 in
    let writeback = (instruction land (1 lsl 21)) <> 0 in
    let src_or_dst = match preindex,writeback with
      | true, false -> M (BinOp(updown, Lval (V (reg rn)), ofs), length)
      | true, true
      | false, false -> M (Lval (V (reg rn)), length) (* if post-indexing, write back is implied and W=0 *)
      | false, true -> error s.a "Undefined combination (post indexing and W=1)" in
    let stmt,update_pc = if (instruction land (1 lsl 20)) = 0 then (* store *)
        Set (src_or_dst, Lval (V (reg rd))), false
      else (* load *)
        Set (V (reg rd), Lval src_or_dst), rd = 15 in
    let write_back_stmt = Set (V (reg rn), BinOp(updown, Lval (V (reg rn)), ofs)) in
    let stmts' =
      if preindex then
        if writeback then
          [ write_back_stmt ; stmt ]
        else
          [ stmt ]
      else
        [ stmt ; write_back_stmt ] in
    if update_pc then
      stmts' @ [ Jmp (R (Lval (V (T pc)))) ]
    else
      stmts'

  let data_proc s instruction =
    let rd = (instruction lsr 12) land 0xf in
    let rn = (instruction lsr 16) land 0xf in
    let is_imm = (instruction lsr 25) land 1 in
    let set_cond_codes = (instruction lsr 20) land 1 in
    let op2_stmt, op2_carry_stmt =
      if is_imm = 0 then
        let shift_op = (instruction lsr 4) land 0xff in
        let rm = instruction land 0xf in
        let op3, int_shift_count =
          if shift_op land 1 = 0 then
            const (shift_op lsr 3) 32, Some (shift_op lsr 3)
          else
            Lval (V (reg (shift_op lsr 4))), None in
        match (shift_op lsr 1) land 0x3 with
          | 0b00 -> (* lsl *) begin
            match  int_shift_count with
            | Some 0 -> Lval (V (reg rm))
            | _ -> BinOp(Shl, Lval (V (reg rm)), op3)
          end,
            begin
              match int_shift_count with
              | Some 0 -> [] (* lsl 0 => preserve carry *)
              | Some n -> [ Set( V (T cflag),  (* shift count is an immediate, we can directly test the bit *)
                                 TernOp (Cmp (EQ, BinOp(And, Lval (V (reg rm)), const (1 lsl (32-n)) 32),const 0 32),
                                         const 0 1, const 1 1)) ]
              | None -> [ Set ( V (T cflag),   (* shift count comes from a register. We shift again on 33 bits *)
                                TernOp (Cmp (EQ, BinOp(And, 
                                                       BinOp(Shl, UnOp(ZeroExt 33, Lval (V (reg rm))),
                                                             UnOp(ZeroExt 33, op3)),
                                                       const (1 lsl 32) 33), const 0 33),
                                        const 0 1, const 1 1)) ]
            end
          | 0b01 -> (* lsr *)
             begin
               match int_shift_count with
               | Some 0 -> const 0 32 (* 0 actually encodes lsr #32 *)
               | _ -> BinOp(Shr, Lval (V (reg rm)), op3)
             end,
               begin
                 let one33 = const 1 33 in
                 let zero32 = const 0 32 in
                 match int_shift_count with
                 | Some 0 -> [ Set( V (T cflag), (* 0 for lsr means 32 ! *)
                                    TernOp (Cmp (EQ, BinOp(And, Lval (V (reg rm)), const 0x80000000 32), zero32),
                                            const 0 1, const 1 1)) ]
                 | Some n -> [ Set( V (T cflag),  (* shift count is an immediate, we can directly test the bit *)
                                    TernOp (Cmp (EQ, BinOp(And, Lval (V (reg rm)), const (1 lsl (n-1)) 32), zero32),
                                            const 0 1, const 1 1)) ]
                 | None -> [ Set ( V (T cflag),                           (* shift count comes from a register. *)
                                   TernOp (Cmp (EQ,
                                                BinOp(And, one33, (* We shift left 1 and right but on 33 bits *)
                                                      BinOp(Shr,
                                                            BinOp(Shl, UnOp(ZeroExt 33, Lval (V (reg rm))), one33),
                                                            UnOp(ZeroExt 33, op3))),
                                                one33),
                                           const 1 1, const 0 1)) ]
               end
          | 0b10 -> (* asr *) error s.a "Asr shift operation for shifted register not implemented"
          | 0b11 -> (* ror *) error s.a "Ror shift operation for shifted register not implemented"
          | _ as st -> L.abort (fun p -> p "unexpected shift type %x" st)
      else
        let shift = (instruction lsr 8) land 0xf in
        let imm = instruction land 0xff in
        const (ror32 imm (2*shift)) 32,[]
    in let stmt,update_pc = let opcode = (instruction lsr 21) land 0xf in match opcode with
    | 0b0000 -> [ Set (V (reg rd), BinOp(And, Lval (V (reg rn)), op2_stmt) ) ] @ op2_carry_stmt, rd = 15 (* AND - Rd:= Op1 AND Op2 *)
    | 0b0001 -> [ Set (V (reg rd), BinOp(Xor, Lval (V (reg rn)), op2_stmt) ) ] @ op2_carry_stmt, rd = 15 (* EOR - Rd:= Op1 EOR Op2 *)
    | 0b0010 -> [ Set (V (reg rd), BinOp(Sub, Lval (V (reg rn)), op2_stmt) ) ], rd = 15 (* SUB - Rd:= Op1 - Op2 *)
    | 0b0011 -> [ Set (V (reg rd), BinOp(Sub, op2_stmt, Lval (V (reg rn))) ) ], rd = 15  (* RSB - Rd:= Op2 - Op1 *)
    | 0b0100 -> [ Set (V (reg rd), BinOp(Add, Lval (V (reg rn)), op2_stmt) ) ], rd = 15 (* ADD - Rd:= Op1 + Op2 *)
    | 0b0101 -> (* ADC - Rd:= Op1 + Op2 + C *) error s.a "ADC"
    | 0b0110 -> (* SBC - Rd:= Op1 - Op2 + C - 1 *) error s.a "SBC"
    | 0b0111 -> (* RSC - Rd:= Op2 - Op1 + C - 1 *) error s.a "RSC"
    | 0b1100 -> [ Set (V (reg rd), BinOp(Or, Lval (V (reg rn)), op2_stmt) ) ] @ op2_carry_stmt, rd = 15 (* ORR - Rd:= Op1 OR Op2 *)
    | 0b1101 -> [ Set (V (reg rd), op2_stmt) ] @ op2_carry_stmt, rd = 15 (* MOV - Rd:= Op2 *)
    | 0b1110 -> [ Set (V (reg rd), BinOp(And, Lval (V (reg rn)), UnOp(Not, op2_stmt)) ) ] @ op2_carry_stmt, rd = 15
                (* BIC - Rd:= Op1 AND NOT Op2 *)
    | 0b1111 -> [ Set (V (reg rd), UnOp(Not, op2_stmt)) ] @ op2_carry_stmt, rd = 15 (* MVN - Rd:= NOT Op2 *)
    | _ -> (* TST/TEQ/CMP/CMN or MRS/MSR *)
       if (instruction land (1 lsl 20)) = 0 then (* S=0 => MRS/MSR *)
         begin
           match (instruction lsr 18) land 0xf with
           | 0b0011 -> (* MRS *)
              if instruction land (1 lsl 22) = 0 then (* Source PSR: 0=CPSR 1=SPSR *)
                [ Set (V (reg rd), 
                       BinOp(Or,
                             BinOp(Or,
                                   BinOp(Or, BinOp(Shl, UnOp(ZeroExt 32, Lval (V (T nflag))),
                                                   const 31 32),
                                         BinOp(Shl, UnOp(ZeroExt 32, Lval (V (T zflag))),
                                               const 30 32)),
                                   BinOp(Or, BinOp(Shl, UnOp(ZeroExt 32, Lval (V (T cflag))),
                                                   const 29 32),
                                         BinOp(Shl, UnOp(ZeroExt 32, Lval (V (T vflag))),
                                               const 28 32))),
                             const 0b10000 32)) ], false (* 0b10000 means user mode *)
              else error s.a "MRS from SPSR not supported"
           | 0b1010 -> (* MSR *) 
              if instruction land (1 lsl 22) = 0 then (* Source PSR: 0=CPSR 1=SPSR *)
                let zero32 = const 0 32 in
                [ Set (V (T nflag), TernOp(Cmp (EQ, BinOp(And, op2_stmt, const (1 lsl 31) 32), zero32),
                                           const 0 1, const 1 1)) ;
                  Set (V (T zflag), TernOp(Cmp (EQ, BinOp(And, op2_stmt, const (1 lsl 30) 32), zero32),
                                           const 0 1, const 1 1)) ;
                  Set (V (T cflag), TernOp(Cmp (EQ, BinOp(And, op2_stmt, const (1 lsl 29) 32), zero32),
                                           const 0 1, const 1 1)) ;
                  Set (V (T vflag), TernOp(Cmp (EQ, BinOp(And, op2_stmt, const (1 lsl 28) 32), zero32),
                                           const 0 1, const 1 1)) ], false
              else error s.a "MSR to SPSR not supported"
           | _ -> error s.a "unkonwn MSR/MRS opcode"
         end
       else
         begin
           match opcode with
           | 0b1000 -> (* TST - set condition codes on Op1 AND Op2 *) error s.a "TST"
           | 0b1001 -> (* TEQ - set condition codes on Op1 EOR Op2 *) error s.a "TEQ"
           | 0b1010 -> (* CMP - set condition codes on Op1 - Op2 *) error s.a "CMP"
           | 0b1011 -> (* CMN - set condition codes on Op1 + Op2 *) error s.a "CMN"
           | _ -> L.abort (fun p -> p "unexpected opcode %x" opcode)
         end in
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
    if update_pc then
      stmt_cc @ [ Jmp (R (Lval (V (T pc)))) ]
    else
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
         if ((instruction lsr 4) land 0xf) = 0x9 then
           match (instruction lsr 23) land 0x7 with
           | 0b000 -> (* multiply *) error s.a "Multiply not implemented"
           | 0b010 -> (* single data swap *) error s.a "single data swap not implemented"
           | _ -> L.abort (fun p -> p "Unexpected opcode %x" instruction)
         else (* data processing / PSR transfer *) 
           data_proc s instruction
       end
    | 0b01 -> single_data_transfer s instruction
    | 0b10 ->
       begin
         match (instruction lsr 25) land 1 with
         | 0 -> block_data_transfer s instruction (* block data transfer *)
         | 1 -> branch s instruction
         | _ -> error s.a (Printf.sprintf "Unknown opcode 0x%x" instruction)
       end
    | 0b11 ->
       begin
         match (instruction lsr 24) land 3 with
         | 0b11 -> (* software interrupt *) error s.a (Printf.sprintf "software interrupt not implemented (swi=%08x)" instruction)
         | _ -> (* coproc *) error s.a "coprocessor operation not implemented"
       end
    | _ -> error s.a (Printf.sprintf "Unknown opcode 0x%x" instruction) in
    let stmts_cc = match (instruction lsr 28) land 0xf with
    | 0xf -> []    (* never *) 
    | 0xe -> stmts (* always *) 
    | _ as cc -> wrap_cc cc stmts in
    let current_pc = Const (Word.of_int (Z.add (Address.to_int s.a) (Z.of_int 8)) 32) in (* pc is 8 bytes ahead because of pre-fetching. *)
    (* XXX: 12 bytes if a register is used to specify a shift amount *)
    return s instruction (Set( V (T pc), current_pc) :: stmts_cc)


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
