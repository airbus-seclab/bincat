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

  let preg n a b =
    P ((reg_from_num n), a, b)

  let n_is_set = Cmp(EQ, Lval (V (T nflag)), const 1 1)
  let z_is_set = Cmp(EQ, Lval (V (T zflag)), const 1 1)
  let c_is_set = Cmp(EQ, Lval (V (T cflag)), const 1 1)
  let v_is_set = Cmp(EQ, Lval (V (T vflag)), const 1 1)
  let n_is_clear = Cmp(EQ, Lval (V (T nflag)), const 0 1)
  let z_is_clear = Cmp(EQ, Lval (V (T zflag)), const 0 1)
  let c_is_clear = Cmp(EQ, Lval (V (T cflag)), const 0 1)
  let v_is_clear = Cmp(EQ, Lval (V (T vflag)), const 0 1)

  module Cfa = Cfa.Make(Domain)

  module Imports = Armv7Imports.Make(Domain)

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

  let single_data_swap _s instruction =
    let rd = (instruction lsr 12) land 0xf in
    let rn = (instruction lsr 16) land 0xf in
    let rm = instruction land 0xf in
    let work_on_byte = instruction land (1 lsl 22) <> 0 in
    let length,src,mem,dst  = if work_on_byte then
        8, (V (preg rm 0 7)), (M (Lval (V (reg rn)), 8)), (V (preg rd 0 7))
      else
        32, (V (reg rm)), M (Lval (V (reg rn)), 32), (V (reg rd)) in
    let stmts =
      if rm = rd then
        let tmpreg = Register.make (Register.fresh_name ()) length in
        [ Set (V (T tmpreg), Lval mem)  ;
          Set (mem, Lval dst) ;
          Set (dst, Lval (V (T tmpreg))) ;
          Directive (Remove tmpreg) ]
      else
        [ Set (dst, Lval mem)  ;
          Set (mem, Lval src)  ] in
    if work_on_byte then
      stmts @ [ Set( V (preg rd 8 31), const 0 24 ) ]
    else
      stmts


  let mul_mla _s instruction =
    let rd = (instruction lsr 16) land 0xf in
    let rn = (instruction lsr 12) land 0xf in
    let rs = (instruction lsr 8) land 0xf in
    let rm = instruction land 0xf in
    let accumulate = instruction land (1 lsl 21) <> 0 in
    let set_cc = instruction land (1 lsl 20) <> 0 in
    let tmpreg = Register.make (Register.fresh_name ()) 64 in
    let accu_stmt = if accumulate then
        Set (V (reg rd), BinOp(Add, Lval (V (P (tmpreg, 0, 31))),
                               Lval (V (reg rn))))
      else
        Set (V (reg rd), Lval (V (P (tmpreg, 0, 31)))) in
    let cc_stmts = if set_cc then
        [ Set(V (T zflag), TernOp (Cmp(EQ, Lval (V (reg rd)), const 0 32),
                                   const 1 1, const 0 1)) ;
          Set(V (T nflag), Lval (V (preg rd 31 31))) ;
          Directive (Forget (V (T cflag))) ]
      else
        [] in
    let stmt = Set (V (T tmpreg), BinOp(Mul, Lval (V (reg rm)), Lval (V (reg rs)))) in
    stmt :: accu_stmt :: Directive (Remove tmpreg) :: cc_stmts


  let block_data_transfer s instruction =
    if instruction land (1 lsl 22) <> 0 then error s.a "LDM/STM with S=1 not implemented"
    else
      let rn = (instruction lsr 16) land 0xf in
      let ascend = instruction land (1 lsl 23) <> 0 in
      let dir_op = if ascend then Add else Sub in
      let ofs = ref (if instruction land (1 lsl 24) = 0 then 0 else 4) in
      let store = instruction land (1 lsl 20) = 0 in
      let stmts = ref [] in
      let update_pc = ref false in
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
                         Lval (M (BinOp(dir_op, Lval (V (reg rn)), const !ofs 32), 32))) ];
                if i = 15 then update_pc := true
              end;
            ofs := !ofs+4;
            reg_count := !reg_count + 1
          end
        else ()
      done;
      if instruction land (1 lsl 21) = 0 then
        stmts := !stmts @
          [ Set (V (reg rn), BinOp(dir_op, Lval (V (reg rn)), const (4*(!reg_count)) 32)) ];
      if !update_pc then
        stmts := !stmts @ [ Jmp (R (Lval (V (T pc)))) ];
      !stmts

  let branch s instruction =
    let link = (instruction land (1 lsl 24)) <> 0 in
    let link_stmt,jmp_or_call_stmt = 
      if link then
        ([ Set( V (T lr), Const (Word.of_int (Z.add (Address.to_int s.a) (Z.of_int 4)) 32)) ], [ Call (R (Lval (V (T pc)))) ]) 
      else
        ([ ], [ Jmp (R (Lval (V (T pc)))) ]) in
    let ofs = (instruction land 0xffffff) lsl 2 in
    let ofs32 = if ofs land 0x2000000 <> 0 then ofs lor 0xfc000000 else ofs in (* sign extend 26 bits to 32 bits *)
    link_stmt
    @ [ Set (V (T pc), BinOp(Add, Lval (V (T pc)), const ofs32 32)) ]
    @ jmp_or_call_stmt


  let single_data_transfer s instruction = 
    let rd = (instruction lsr 12) land 0xf in
    let rn = (instruction lsr 16) land 0xf in
    let ofs = if instruction land (1 lsl 25) = 0 then (* immediate value *)
        const (instruction land 0xfff) 32
      else
        let rm = instruction land 0xf in
        let shift_op = (instruction lsr 4) land 0xff in
        if shift_op land 1 = 1 then error s.a "Shift register cannot be specified for single data transfer instructions"
        else
          let shift_type = (shift_op lsr 1) land 3 in
          let shift_amount = (shift_op lsr 3) land 0x1f in
          match  shift_type with
          | 0b00 -> (* logical shift left *)
             if shift_amount = 0 then
              Lval (V (reg rm))
            else
              BinOp(Shl, Lval (V (reg rm)), const shift_amount 32)
          | 0b01 -> (* logical shift right *)
             let actual_shift = if shift_amount = 0 then 32 else shift_amount in
             BinOp(Shl, Lval (V (reg rm)), const actual_shift 32)
          | 0b10 -> (* asr *) error s.a "single data xfer offset from reg with asr not implemented"
          | 0b11 -> (* ror *) error s.a "single data xfer offset from reg with ror not implemented"
          | _ -> error s.a "unexpected shift type insingle data xfer" in
    let updown = if (instruction land (1 lsl 23)) = 0 then Sub else Add in
    let preindex = (instruction land (1 lsl 24)) <> 0 in
    let writeback = (instruction land (1 lsl 21)) <> 0 in
    let length, dst_or_src = if (instruction land (1 lsl 22)) = 0 then
        32, (V (reg rd))
      else
        8, (V (preg rd 0 7)) in
    let src_or_dst = match preindex,writeback with
      | true, false -> M (BinOp(updown, Lval (V (reg rn)), ofs), length)
      | true, true
      | false, false -> M (Lval (V (reg rn)), length) (* if post-indexing, write back is implied and W=0 *)
      | false, true -> error s.a "Undefined combination (post indexing and W=1)" in
    let stmts,update_pc = if (instruction land (1 lsl 20)) = 0 then (* store *)
        [ Set (src_or_dst, Lval dst_or_src)], false
      else (* load *)
        begin
          let load_stmt = Set (dst_or_src, Lval src_or_dst) in
          let stmts' =
            if length = 32 then
              [ load_stmt ]
            else
              [ load_stmt ;
                Set (V (preg rd 8 31), const 0 24) ] in
          stmts', rd = 15
        end in
    let write_back_stmt = Set (V (reg rn), BinOp(updown, Lval (V (reg rn)), ofs)) in
    let stmts' =
      if preindex then
        if writeback then
          write_back_stmt :: stmts
        else
          stmts
      else
        stmts @ [ write_back_stmt ] in
    if update_pc then
      stmts' @ [ Jmp (R (Lval (V (T pc)))) ]
    else
      stmts'

  let data_proc s instruction =
    let rd = (instruction lsr 12) land 0xf in
    let rn = (instruction lsr 16) land 0xf in
    let is_imm = instruction land (1 lsl 25) <> 0 in
    let set_cond_codes = instruction land (1 lsl 20) <> 0 in
    let op2_stmt, op2_carry_stmt =
      if is_imm then
        let shift = (instruction lsr 8) land 0xf in
        let imm = instruction land 0xff in
        const (ror32 imm (2*shift)) 32, [ Set( V (T cflag), const ((imm lsr (2*shift-1)) land 1) 0)]
      else
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
          | st -> L.abort (fun p -> p "unexpected shift type %x" st)
    in
    let to33bits x = UnOp(ZeroExt 33, x) in
    let to33bits_s x = UnOp(SignExt 33, x) in
    let bit31 = const 0x80000000 32 in
    let zflag_update_exp res_exp = Set(V (T zflag), TernOp (Cmp(EQ, res_exp, const 0 32),
                                                            const 1 1, const 0 1)) in
    let _nflag_update_exp res_exp = Set(V (T nflag), TernOp (Cmp(EQ, BinOp(And, res_exp, const 0x80000000 32),
                                                                const 0 32),
                                                            const 0 1, const 1 1)) in
    let nflag_update_from_reg_exp res_reg = Set(V (T nflag), Lval (V (P (res_reg, 31, 31)))) in
    let vflag_update_exp a b res =
      Set(V (T (vflag)), TernOp (BBinOp (LogAnd,
                                         Cmp (EQ, BinOp(And, a, bit31),
                                              BinOp(And, b, bit31)),
                                         Cmp (NEQ, BinOp(And, a, bit31),
                                              BinOp(And, res, bit31))),
                                 const 1 1, const 0 1)) in
    let set_cflag_vflag_after_add_with_carry a b carry =
      let tmpregu = Register.make (Register.fresh_name ()) 33 in
      let tmpregs = Register.make (Register.fresh_name ()) 33 in
      [ Set (V (T tmpregu), BinOp(Add, BinOp(Add, to33bits a, to33bits b),
                                 to33bits carry)) ;
        Set (V (T tmpregs), BinOp(Add, BinOp(Add, to33bits_s a, to33bits_s b),
                                 to33bits carry)) ;
        Set (V (T cflag), Lval (V (P (tmpregu, 32, 32)))) ;
        Set (V (T vflag), TernOp(Cmp(EQ, Lval (V (P (tmpregs, 31, 31))),
                                     Lval (V (P (tmpregs, 32, 32)))),
                                 const 0 1, const 1 1)) ;
        Directive(Remove tmpregu) ;
        Directive(Remove tmpregs) ] in
    let cflag_update_stmts op a b =
      let tmpreg = Register.make (Register.fresh_name ()) 33 in
      [ Set (V (T tmpreg), BinOp(op, to33bits a, to33bits b)) ;
        Set (V (T cflag), Lval (V (P (tmpreg, 32, 32)))) ;
        Directive (Remove tmpreg) ] in
    let cflag_update_stmts_with_carry op a b =
      let tmpreg = Register.make (Register.fresh_name ()) 33 in
      [ Set (V (T tmpreg), BinOp(op, UnOp(ZeroExt 33, Lval (V (T cflag))),
                                 BinOp(op, to33bits a, to33bits b))) ;
        Set (V (T cflag), Lval (V (P (tmpreg, 32, 32)))) ;
        Directive (Remove tmpreg) ] in
    let stmts, flags_stmts, update_pc =
      let opcode = (instruction lsr 21) land 0xf in
      match opcode with
      | 0b0000 -> (* AND - Rd:= Op1 AND Op2 *)
        [ Set (V (reg rd), BinOp(And, Lval (V (reg rn)), op2_stmt) ) ],
        [ zflag_update_exp (Lval (V (reg rd))) ;
          nflag_update_from_reg_exp (reg_from_num rd) ]
        @ op2_carry_stmt,
        rd = 15
      | 0b0001 -> (* EOR - Rd:= Op1 EOR Op2 *)
        [ Set (V (reg rd), BinOp(Xor, Lval (V (reg rn)), op2_stmt) ) ],
        [ zflag_update_exp (Lval (V (reg rd))) ;
          nflag_update_from_reg_exp (reg_from_num rd) ]
        @ op2_carry_stmt,
        rd = 15
      | 0b0010 -> (* SUB - Rd:= Op1 + not Op2 + 1 *)
         let tmpreg = Register.make (Register.fresh_name ()) 33 in
         [ Set (V (reg rd), BinOp(Sub, Lval (V (reg rn)), op2_stmt) ) ],
         [ zflag_update_exp (Lval (V (reg rd))) ;
           nflag_update_from_reg_exp (reg_from_num rd) ;
           vflag_update_exp (Lval (V (reg rn))) (UnOp(Not, op2_stmt)) (Lval (V (reg rd))) ;
           (* sub is computed witn sub a,b = a+(not b)+1, hence the carry *)
           Set (V (T tmpreg), BinOp(Add, BinOp(Add, 
                                               to33bits (Lval (V (reg rn))),
                                               to33bits (UnOp(Not, op2_stmt))),
                                    const 1 33)) ;
           Set (V (T cflag), Lval (V (P (tmpreg, 32, 32)))) ;
           Directive (Remove tmpreg) ],
         rd = 15
      | 0b0011 -> (* RSB - Rd:= Op2 - Op1 *)
         let tmpreg = Register.make (Register.fresh_name ()) 33 in
         [ Set (V (reg rd), BinOp(Sub, op2_stmt, Lval (V (reg rn)))) ],
         [ zflag_update_exp (Lval (V (reg rd))) ;
           nflag_update_from_reg_exp (reg_from_num rd) ;
           vflag_update_exp op2_stmt (UnOp(Not, (Lval (V (reg rn))))) (Lval (V (reg rd))) ;
           Set (V (T tmpreg), BinOp(Add, BinOp(Add, 
                                               to33bits op2_stmt,
                                               to33bits (UnOp(Not, Lval (V (reg rn))))),
                                    const 1 33)) ;
           Set (V (T cflag), Lval (V (P (tmpreg, 32, 32)))) ;
           Directive (Remove tmpreg) ],
         rd = 15
    | 0b0100 -> (* ADD - Rd:= Op1 + Op2 *)
      [ Set (V (reg rd), BinOp(Add, Lval (V (reg rn)), op2_stmt) ) ],
      [ zflag_update_exp (Lval (V (reg rd))) ;
        nflag_update_from_reg_exp (reg_from_num rd) ;
        vflag_update_exp (Lval (V (reg rn))) op2_stmt (Lval (V (reg rd))) ; ]
      @ cflag_update_stmts Add (Lval (V (reg rn))) op2_stmt,
      rd = 15
    | 0b0101 -> (* ADC - Rd:= Op1 + Op2 + C *)
      [ Set (V (reg rd), BinOp(Add, UnOp(ZeroExt 32, Lval (V (T cflag))),
                                BinOp(Add, Lval (V (reg rn)), op2_stmt) )) ],
      [ zflag_update_exp (Lval (V (reg rd))) ;
        nflag_update_from_reg_exp (reg_from_num rd) ;
        vflag_update_exp (Lval (V (reg rn))) op2_stmt (Lval (V (reg rd))) ; ]
      @ cflag_update_stmts_with_carry Add (Lval (V (reg rn))) op2_stmt,
      rd = 15
    | 0b0110 -> (* SBC - Rd:= Op1 - Op2 + C - 1 *)
       [ Set (V (reg rd), BinOp(Sub,
                                BinOp(Add, BinOp(Sub, Lval (V (reg rn)), op2_stmt),
                                      UnOp(ZeroExt 32, Lval (V (T cflag))) ),
                                const 1 32)) ],
       [ zflag_update_exp (Lval (V (reg rd))) ;
         nflag_update_from_reg_exp (reg_from_num rd) ; ]
       @ set_cflag_vflag_after_add_with_carry (Lval (V (reg rn))) (UnOp(Not, op2_stmt)) (Lval (V (T cflag))),
      rd = 15
    | 0b0111 -> (* RSC - Rd:= Op2 - Op1 + C - 1 *)
       [ Set (V (reg rd), BinOp(Sub,
                                BinOp(Add, BinOp(Sub, op2_stmt, Lval (V (reg rn))),
                                      UnOp(ZeroExt 32, Lval (V (T cflag))) ),
                                const 1 32)) ],
       [ zflag_update_exp (Lval (V (reg rd))) ;
         nflag_update_from_reg_exp (reg_from_num rd) ; ]
       @ set_cflag_vflag_after_add_with_carry op2_stmt (UnOp(Not, (Lval (V (reg rn))))) (Lval (V (T cflag))),
      rd = 15
    | 0b1100 -> (* ORR - Rd:= Op1 OR Op2 *)
      [ Set (V (reg rd), BinOp(Or, Lval (V (reg rn)), op2_stmt) ) ],
      [ zflag_update_exp (Lval (V (reg rd))) ;
        nflag_update_from_reg_exp (reg_from_num rd) ]
      @ op2_carry_stmt,
      rd = 15
    | 0b1101 -> (* MOV - Rd:= Op2 *)
      [ Set (V (reg rd), op2_stmt) ],
      [ zflag_update_exp (Lval (V (reg rd))) ;
        nflag_update_from_reg_exp (reg_from_num rd) ]
      @ op2_carry_stmt,
      rd = 15
    | 0b1110 -> (* BIC - Rd:= Op1 AND NOT Op2 *)
      [ Set (V (reg rd), BinOp(And, Lval (V (reg rn)), UnOp(Not, op2_stmt)) ) ],
      [ zflag_update_exp (Lval (V (reg rd))) ;
        nflag_update_from_reg_exp (reg_from_num rd) ]
      @ op2_carry_stmt,
      rd = 15
    | 0b1111 -> (* MVN - Rd:= NOT Op2 *)
      [ Set (V (reg rd), UnOp(Not, op2_stmt)) ],
      [ zflag_update_exp (Lval (V (reg rd))) ;
        nflag_update_from_reg_exp (reg_from_num rd) ]
      @ op2_carry_stmt,
      rd = 15
    | _ -> (* TST/TEQ/CMP/CMN or MRS/MSR *)
       if (instruction land (1 lsl 20)) <> 0 then (* S=1 => TST/TEQ/CMP/CMN *)
         begin
           match opcode with
           | 0b1000 -> (* TST - set condition codes on Op1 AND Op2 *)
              let tmpreg = Register.make (Register.fresh_name ()) 32 in
              [],
              [ Set(V (T tmpreg), BinOp(And, Lval (V (reg rn)), op2_stmt)) ;
                zflag_update_exp (Lval (V (T tmpreg))) ;
                nflag_update_from_reg_exp tmpreg ;
                Directive (Remove tmpreg) ]
              @ op2_carry_stmt,
              false
           | 0b1001 -> (* TEQ - set condition codes on Op1 EOR Op2 *)
              let tmpreg = Register.make (Register.fresh_name ()) 32 in
              [],
              [ Set(V (T tmpreg), BinOp(Xor, Lval (V (reg rn)), op2_stmt)) ;
                zflag_update_exp (Lval (V (T tmpreg))) ;
                nflag_update_from_reg_exp tmpreg ;
                Directive (Remove tmpreg) ]
              @ op2_carry_stmt,
              false
           | 0b1010 -> (* CMP - set condition codes on Op1 - Op2 *)
              let tmpreg = Register.make (Register.fresh_name ()) 33 in
              [],
              [
                Set( V (T tmpreg), BinOp(Add, to33bits (Lval (V (reg rn))),
                                         to33bits(BinOp(Add, UnOp(Not, op2_stmt),
                                                        const 1 32)))) ;
                zflag_update_exp (Lval (V (P (tmpreg, 0, 31)))) ;
                nflag_update_from_reg_exp tmpreg ;
                vflag_update_exp  (Lval (V (reg rn))) (UnOp(Not, op2_stmt)) (Lval (V (P (tmpreg, 0, 31)))) ;
                Set (V (T cflag), Lval (V (P (tmpreg, 32, 32)))) ;
                Directive (Remove tmpreg) ],
              false
           | 0b1011 -> (* CMN - set condition codes on Op1 + Op2 *)
              let tmpreg = Register.make (Register.fresh_name ()) 33 in
              [], 
              [ Set( V (T tmpreg), BinOp(Add, to33bits (Lval (V (reg rn))),
                                         to33bits op2_stmt) ) ;
                Set (V (T cflag), Lval (V (P (tmpreg, 32, 32)))) ;
                zflag_update_exp (Lval (V (P (tmpreg, 0, 31)))) ;
                nflag_update_from_reg_exp tmpreg ;
                vflag_update_exp (Lval (V (reg rn))) op2_stmt (Lval (V (P (tmpreg, 0, 31)))) ;
                Directive (Remove tmpreg) ],
              false
           | _ -> L.abort (fun p -> p "unexpected opcode %x" opcode)
         end
       else  (* MRS/MSR *)
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
                             const 0b10000 32)) ], [], false (* 0b10000 means user mode *)
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
                                           const 0 1, const 1 1)) ], [], false
              else error s.a "MSR to SPSR not supported"
           | _ -> error s.a "unkonwn MSR/MRS opcode"
         end in
    let stmt_cc =
      if set_cond_codes
      then
        stmts @ flags_stmts
      else
        stmts in
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
           | 0b000 -> mul_mla s instruction (* multiply *) 
           | 0b010 -> single_data_swap s instruction (* single data swap *)
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
    | cc -> wrap_cc cc stmts in
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










  let forget_reserved_registers_aapcs () =
    [ Directive (Forget (V (T r1))) ; (* scratch registers r1 -> r3 *)
      Directive (Forget (V (T r2))) ;
      Directive (Forget (V (T r3))) ;
      Directive (Forget (V (T r12))); (* r12: inter procedure call scratch reg *)
(* 
        Return *)
(*     Set( V (T pc), Lval (V (T lr))) ;
      Jmp (R (Lval (V (T pc)))) *)
]


  let type_directives_aapcs _typing_rule =
    let epilogue = [] in
    let _off = !Config.stack_width / 8 in
    let _sz, prologue = 0, []
    in
    prologue, epilogue @ (forget_reserved_registers_aapcs ())


  let taint_directives_aapcs taint_ret taint_args =
    let taint_arg taint =
      match taint with
      | Config.No_taint -> []
      | Config.Buf_taint -> [ Directive (Taint (None, M (Lval (V (T r0)), !Config.operand_sz))) ]
      | Config.Addr_taint -> [ Directive (Taint (None, V (T r0))) ]
    in
    let taint_ret' =
      match taint_ret with
      | None -> []
      | Some t -> taint_arg t
    in
    List.fold_left (fun l arg -> (taint_arg arg)@l) [] taint_args, taint_ret'


  let default_stub_aapcs () = []


  let get_stub name =
    match !Config.call_conv with
    | Config.AAPCS ->
       begin
         try
           Hashtbl.find Imports.aapcs_stubs name
         with Not_found -> default_stub_aapcs ()
       end
    | _ -> L.abort (fun p -> p "calling convention not managed for ARM")

  let replace_types type_directive =
    Hashtbl.iter (fun name typing_rule ->
      try
        L.debug (fun p -> p "types for %s ?" name);
        let a, fundec = Imports.search_by_name name in
        let prologue, epilogue = type_directive typing_rule in
        L.debug (fun p -> p "replace type for %s: %s %s" name (Asm.string_of_stmts prologue true) (Asm.string_of_stmts epilogue true));
        Hashtbl.replace Imports.tbl a
          { fundec with Imports.prologue = fundec.Imports.prologue@prologue ;
            Imports.epilogue = fundec.Imports.epilogue@epilogue ; Imports.stub = get_stub name}
      with Not_found ->
        L.analysis (fun p -> p "from config file: Typing information for function %s without import address => ignored." name); ()
    ) Config.typing_rules

  let replace_taint taint_directives funame taint_ret taint_args =
    let a, fundec = Imports.search_by_name funame in
    let prologue, epilogue = taint_directives taint_ret taint_args in
    Hashtbl.replace Imports.tbl a
      { fundec with Imports.prologue = fundec.Imports.prologue@prologue ;
        Imports.epilogue = fundec.Imports.epilogue@epilogue ;  }


    (** initialization of the import table *)
  let init_imports () =
    Imports.init();
    (* creates the import table from import section *)
    let add_import_to_table a (libname, fname) =
      L.debug(fun p -> p "loading import %s.%s at %x" libname fname (Z.to_int a));
      let a' = Data.Address.of_int Data.Address.Global a !Config.address_sz in
      let fun_desc =  {
        Imports.libname = libname;
        Imports.name = fname;
        Imports.prologue = [];
        Imports.stub = [];
        Imports.epilogue = [];
      } in
      Hashtbl.add Imports.tbl a' fun_desc in
    Hashtbl.iter add_import_to_table  Config.import_tbl;
    begin
      match !Config.call_conv with
      | Config.AAPCS -> replace_types type_directives_aapcs
      | cc -> L.analysis (fun p -> p "Calling convention %s not managed for ARM. Typing directives ignored"
      (Config.call_conv_to_string cc))
    end;
    (* adds tainting information to prologue and epilogue *)
    Hashtbl.iter (fun (libname, funame) (callconv, taint_ret, taint_args) ->
      try
        match callconv with
        | Config.AAPCS ->
           replace_taint taint_directives_aapcs funame taint_ret taint_args
        | cc -> L.analysis (fun p -> p "Calling convention %s not supported for ARM. Tainting rule ignored for %s.%s " (Config.call_conv_to_string cc) libname funame)
      with
        Not_found ->
          L.analysis (fun p -> p"Typing information for function without import address ignored"); ()
      | Failure msg -> L.abort (fun p -> p "%s" msg)

    ) Config.tainting_rules



  let init () =
    init_imports()

end
