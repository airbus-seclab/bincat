(*
    This file is part of BinCAT.
    Copyright 2014-2018 - Airbus Group

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
   Decoder for PowerPC
*)
module L = Log.Make(struct let name = "powerpc" end)

module Make(Domain: Domain.T)(Stubs: Stubs.T with type domain_t := Domain.t) =
struct

  type ctx_t = unit

  open Data
  open Asm
  open Decodeutils

  module Cfa = Cfa.Make(Domain)

  type state = {
    mutable g             : Cfa.t;        (** current cfa *)
    mutable b             : Cfa.State.t;  (** state predecessor *)
    a                     : Address.t;    (** current address to decode *)
    buf                   : string;       (** buffer to decode *)
    endianness            : Config.endianness_t;      (** whether memory access is little endian *)
  }


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
  let r13 = Register.make ~name:"r13" ~size:32;;
  let r14 = Register.make ~name:"r14" ~size:32;;
  let r15 = Register.make ~name:"r15" ~size:32;;
  let r16 = Register.make ~name:"r16" ~size:32;;
  let r17 = Register.make ~name:"r17" ~size:32;;
  let r18 = Register.make ~name:"r18" ~size:32;;
  let r19 = Register.make ~name:"r19" ~size:32;;
  let r20 = Register.make ~name:"r20" ~size:32;;
  let r21 = Register.make ~name:"r21" ~size:32;;
  let r22 = Register.make ~name:"r22" ~size:32;;
  let r23 = Register.make ~name:"r23" ~size:32;;
  let r24 = Register.make ~name:"r24" ~size:32;;
  let r25 = Register.make ~name:"r25" ~size:32;;
  let r26 = Register.make ~name:"r26" ~size:32;;
  let r27 = Register.make ~name:"r27" ~size:32;;
  let r28 = Register.make ~name:"r28" ~size:32;;
  let r29 = Register.make ~name:"r29" ~size:32;;
  let r30 = Register.make ~name:"r30" ~size:32;;
  let r31 = Register.make ~name:"r31" ~size:32;;

  let lr = Register.make ~name:"lr" ~size:32;;
  let ctr = Register.make ~name:"ctr" ~size:32;;
  let cr = Register.make ~name:"cr" ~size:32;;

  (* condition flags are modeled as registers of size 1 *)

  (* fields from Fixed Point Exception Register (XER) *)
  let so = Register.make ~name:"so" ~size:1;;
  let ov = Register.make ~name:"ov" ~size:1;;
  let ca = Register.make ~name:"ca" ~size:1;;
  let tbc = Register.make ~name:"tbc" ~size:7;;

  module Imports = PowerpcImports.Make(Domain)(Stubs)

  let reg n =
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
    | 13 -> r13
    | 14 -> r14
    | 15 -> r15
    | 16 -> r16
    | 17 -> r17
    | 18 -> r18
    | 19 -> r19
    | 20 -> r20
    | 21 -> r21
    | 22 -> r22
    | 23 -> r23
    | 24 -> r24
    | 25 -> r25
    | 26 -> r26
    | 27 -> r27
    | 28 -> r28
    | 29 -> r29
    | 30 -> r30
    | 31 -> r31
    | _ -> L.abort (fun p -> p "Unknown register number %i" n)

  let treg n =
    T (reg n)

  let preg n a b =
    P ((reg n), a, b)

  let vt r = V (T r)

  let vp r a b = V (P (r, a, b))

  let vtreg n = V (T (reg n))

  let vpreg n a b = V (P (reg n, a, b))

  let lvt r = Lval (V (T r))

  let lvp r a b = Lval (V (P (r, a, b)))

  let lvtreg n = Lval (V (T (reg n)))

  let lvpreg n a b = Lval (V (P (reg n, a, b)))

  let crbit x = vp cr x x

  (* Update CR[0] according to the latest result. Must be called after XER has been updated for CR[0].so to reflect XER.so *)
  let cr_flags_stmts rc rD =
    if rc == 1 then [
        Set(crbit 31, (* cr[0].lt *)
            TernOp(Cmp (EQ, msb_reg (reg rD), const1 32),
                   const1 1, const0 1)) ;
        Set(crbit 30, (* cr[0].gt *)
            TernOp(BBinOp (LogAnd,
                           Cmp (EQ, msb_reg (reg rD), const0 32),
                           Cmp (NEQ, lvtreg rD, const0 32)),
                   const1 1, const0 1)) ;
        Set(crbit 29, (* cr[0].eq *)
            TernOp(Cmp (EQ, lvtreg rD, const0 32),
                   const1 1, const0 1)) ;
        Set(crbit 28, lvt so) ; (* cr[0].so *)
      ]
    else []

    (* Update XER flag after rD <- rA + rB *)
    let xer_flags_stmts_add oe rA rB rD =
      if oe == 1 then [
          Set(vt ov, TernOp (BBinOp(LogAnd,
                                    Cmp (EQ, msb_reg (reg rA), msb_reg (reg rB)),
                                    Cmp (NEQ, msb_reg (reg rA), msb_reg (reg rD))),
                             const1 1, const0 1)) ;
          Set(vt so, BinOp (Or, lvt ov, lvt so)) ;
        ]
      else []

    (* Update XER flag after rD <- rB - rA *)
    let xer_flags_stmts_sub oe rA rB rD =
      if oe == 1 then [
          Set(vt ov, TernOp (BBinOp(LogAnd,
                                    Cmp (NEQ, msb_reg (reg rA), msb_reg (reg rB)),
                                    Cmp (NEQ, msb_reg (reg rB), msb_reg (reg rD))),
                             const1 1, const0 1)) ;
          Set(vt so, BinOp (Or, lvt ov, lvt so)) ;
        ]
      else []

    (* Update XER flag after rD <- neg rA *)
    let xer_flags_stmts_neg oe rA =
      if oe == 1 then [
          Set(vt ov, TernOp (Cmp (EQ, lvtreg rA, const 0x80000000 32),
                             const1 1, const0 1)) ;
          Set(vt so, BinOp (Or, lvt ov, lvt so)) ;
        ]
      else []


  (* fatal error reporting *)
  let error a msg =
    L.abort (fun p -> p "at %s: %s" (Address.to_string a) msg)

  let not_implemented s isn isn_name =
    L.abort (fun p -> p "at %s: instruction %s not implemented yet (isn=%08x)" (Address.to_string s.a) isn_name isn)

  (* split field decoding *)

  let decode_split_field x =
    ((x lsr 5) land 0x1f) lor ((x land 0x1f) lsl 5)

  (* PPC Forms decoding *)

  let decode_B_Form isn =
    let bo = (isn lsr 21) land 0x1f in
    let bi = (isn lsr 16) land 0x1f in
    let bd = (isn lsr 2) land 0x3fff in
    let aa = (isn lsr 1) land 1 in
    let lk = isn land 1 in
    bo, bi, bd, aa, lk

  let decode_D_Form isn =
    let op1 = (isn lsr 21) land 0x1f in
    let op2 = (isn lsr 16) land 0x1f in
    let imm = (isn land 0xffff) in
    op1, op2, imm

  let decode_X_Form isn =
    let rSD = (isn lsr 21) land 0x1f in
    let rA = (isn lsr 16) land 0x1f in
    let rB = (isn lsr 11) land 0x1f in
    let rc = (isn land 1) in
    rSD, rA, rB, rc

  let decode_XO_Form isn =
    let rD = (isn lsr 21) land 0x1f in
    let rA = (isn lsr 16) land 0x1f in
    let rB = (isn lsr 11) land 0x1f in
    let oe = (isn lsr 10) land 1 in
    let rc = (isn land 1) in
    rD, rA, rB, oe, rc

  let decode_XL_Form isn =
    let rD = (isn lsr 21) land 0x1f in
    let rA = (isn lsr 16) land 0x1f in
    let rB = (isn lsr 11) land 0x1f in
    let lk = (isn land 1) in
    rD, rA, rB, lk

  let decode_XFX_Form isn =
    let rSD = (isn lsr 21) land 0x1f in
    let regnum = (isn lsr 11) land 0x3ff in
    rSD,regnum

  (* Operation decoders *)


  (* Branching *)

  let wrap_with_bi_bo_condition bi bo exprs =
    let dec_ctr = Set( vt ctr, BinOp(Sub, lvt ctr, const1 32)) in
    let cmp0_ctr cond = Cmp(cond, lvt ctr, const0 32) in
    let cmpbi_cr cond = Cmp(cond, Lval (crbit (31-bi)), const 0 1) in
    match bo lsr 1 with
    | 0b0000 -> [ dec_ctr ; If (BBinOp(LogAnd, cmp0_ctr NEQ, cmpbi_cr EQ), exprs, []) ]
    | 0b0001 -> [ dec_ctr ; If (BBinOp(LogAnd, cmp0_ctr EQ, cmpbi_cr EQ), exprs, []) ]
    | 0b0010 | 0b0011 -> [ If (cmpbi_cr EQ, exprs, []) ]
    | 0b0100 -> [ dec_ctr ; If (BBinOp(LogAnd, cmp0_ctr NEQ, cmpbi_cr NEQ), exprs, []) ]
    | 0b0101 -> [ dec_ctr ; If (BBinOp(LogAnd, cmp0_ctr EQ, cmpbi_cr NEQ), exprs, []) ]
    | 0b0110 | 0b0111 -> [ If (cmpbi_cr NEQ, exprs, []) ]
    | 0b1000 | 0b1100 -> [ dec_ctr ; If (cmp0_ctr NEQ, exprs, []) ]
    | 0b1001 | 0b1101 -> [ dec_ctr ; If (cmp0_ctr EQ, exprs, []) ]
    | _ -> exprs

  let decode_branch state isn =
    let li = isn land 0x03fffffc in
    let aa = (isn lsr 1) land 1 in
    let lk = isn land 1 in
    let signext_li = if li land 0x02000000 == 0 then li else li lor 0xfc000000 in
    let cia = Z.to_int (Address.to_int state.a) in
    let update_lr = if lk == 0 then [] else [ Set (vt lr, const (cia+4) 32) ] in
    let jump = if aa == 1
               then [ Jmp (R (const signext_li 32)) ]
               else [ Jmp (R (const ((cia+signext_li) land 0xffffffff) 32)) ] in
    update_lr @ jump

  let decode_branch_condition state isn=
    let bo, bi, bd, aa, lk = decode_B_Form isn in
    let signext_bd = if bd land 0x2000 == 0 then (bd lsl 2) else (bd lsl 2) lor 0xffff0000 in
    let cia = Z.to_int (Address.to_int state.a) in
    let update_lr = if lk == 0 then [] else [ Set (vt lr, const (cia+4) 32) ] in
    let jump = if aa == 1
               then Jmp (R (const signext_bd 32))
               else Jmp (R (const ((cia+signext_bd) land 0xffffffff) 32)) in
    wrap_with_bi_bo_condition bi bo (jump :: update_lr)

  let decode_bclr_bcctr state isn lr_or_ctr=
    let bo, bi, _, lk = decode_XL_Form isn in
    let cia = Z.to_int (Address.to_int state.a) in
    let update_lr = if lk == 0 then [] else [ Set (vt lr, const (cia+4) 32) ] in
    let jump = Jmp (R (lvt lr_or_ctr)) in
    wrap_with_bi_bo_condition bi bo (jump :: update_lr)


  (* special *)

  let decode_mfspr state isn =
    let rD, sprn = decode_XFX_Form isn in
    let sprf = decode_split_field sprn in
    match sprf with
    | 1 -> (* XER *)
       [ Set (vtreg rD, const0 32) ;
         Set (vpreg rD 31 31, lvt so) ;
         Set (vpreg rD 30 30, lvt ov) ;
         Set (vpreg rD 28 29, lvt ca) ;
         Set (vpreg rD 0 6, lvt tbc) ]
    | 8 -> (* LR *)
       [ Set (vtreg rD, lvt lr) ]
    | 9 -> (* CTR *)
       [ Set (vtreg rD, lvt ctr) ]
    | n -> error state.a (Printf.sprintf "mtspr to SPR #%i not supported yet" n)

  let decode_mtspr state isn =
    let rS, sprn = decode_XFX_Form isn in
    let sprf = decode_split_field sprn in
    match sprf with
    | 1 -> (* XER *)
       [ Set (vt so, lvpreg rS 31 31) ;
         Set (vt ov, lvpreg rS 30 30) ;
         Set (vt ca, lvpreg rS 29 29) ;
         Set (vt tbc, lvpreg rS 0 6) ]
    | 8 -> (* LR *)
       [ Set (vt lr, lvtreg rS) ]
    | 9 -> (* LR *)
       [ Set (vt ctr, lvtreg rS) ]
    | n -> error state.a (Printf.sprintf "mtspr to SPR #%i not supported yet" n)

  let decode_mtcrf _state isn =
    let rS, crm1 = decode_XFX_Form isn in
    let crm = (crm1 lsr 1) land 0xff in
    if crm == 0xff then (* shortcut for special case when all CR fields are set with rS *)
      [ Set (vt cr, lvtreg rS) ]
    else
      let stmts = ref [] in
      for i = 0 to 7 do
        if (crm lsr i) land 1 == 1 then
          stmts := Set (vp cr (i*4) (i*4+3), lvpreg rS (i*4) (i*4+3)) :: !stmts
      done;
      !stmts


  (* compare *)

  let decode_cmp _state isn =
    let crfD, rA, rB, _ = decode_X_Form isn in
    let ltbit = 31-crfD in
    let gtbit = 30-crfD in
    let eqbit = 29-crfD in
    let sobit = 28-crfD in
    let tmpreg = Register.make (Register.fresh_name ()) 33 in
    [
      Set (vt tmpreg, BinOp(Sub, to33bits_s (lvtreg rA), to33bits_s (lvtreg rB))) ;
      Set (crbit ltbit, TernOp (Cmp (NEQ, msb_reg tmpreg, const0 33),
                                          const1 1, const0 1)) ;
      Set (crbit gtbit, TernOp (BBinOp(LogAnd, Cmp (EQ, msb_reg tmpreg, const0 33),
                                            Cmp(NEQ, lvt tmpreg, const0 33)),
                                                        const1 1, const0 1)) ;
      Set (crbit eqbit, TernOp (Cmp (EQ, lvtreg rA, lvtreg rB),
                                      const1 1, const0 1)) ;

      Set (crbit sobit, lvt so) ;
      Directive (Remove tmpreg) ;
    ]

  let decode_cmpl _state isn =
    let crfD, rA, rB, _ = decode_X_Form isn in
    [
      Set (crbit (31-crfD), TernOp (Cmp (LT, lvtreg rA, lvtreg rB), const1 1, const0 1)) ;
      Set (crbit (30-crfD), TernOp (Cmp (GT, lvtreg rA, lvtreg rB), const1 1, const0 1)) ;
      Set (crbit (29-crfD), TernOp (Cmp (EQ, lvtreg rA, lvtreg rB), const1 1, const0 1)) ;
      Set (crbit (28-crfD), lvt so) ;
    ]

  let decode_cmpli _state isn =
    let crfD, rA, uimm = decode_D_Form isn in
    [
      Set (crbit (31-crfD), TernOp (Cmp (LT, lvtreg rA, const uimm 32), const1 1, const0 1)) ;
      Set (crbit (30-crfD), TernOp (Cmp (GT, lvtreg rA, const uimm 32), const1 1, const0 1)) ;
      Set (crbit (29-crfD), TernOp (Cmp (EQ, lvtreg rA, const uimm 32), const1 1, const0 1)) ;
      Set (crbit (28-crfD), lvt so) ;
    ]

  (* logic *)

  let decode_logic _state isn op =
    let rS, rA, rB, rc = decode_X_Form isn in
    Set (vtreg rA, BinOp (op, lvtreg rS, lvtreg rB)) :: (cr_flags_stmts rc rA)

  let decode_logic_complement _state isn op =
    let rS, rA, rB, rc = decode_X_Form isn in
    Set (vtreg rA, BinOp (op, lvtreg rS, UnOp(Not, lvtreg rB))) :: (cr_flags_stmts rc rA)

  let decode_logic_imm _state isn op =
    let rS, rA, uimm = decode_D_Form isn in
    [ Set (vtreg rA, BinOp(op, lvtreg rS, const uimm 32) ) ]

  let decode_logic_imm_shifted _state isn op =
    let rS, rA, uimm = decode_D_Form isn in
    [ Set (vtreg rA, BinOp(op, lvtreg rS, const (uimm lsl 16) 32) ) ]

  let decode_logic_imm_dot _state isn op =
    let rS, rA, uimm = decode_D_Form isn in
    Set (vtreg rA, BinOp(op, lvtreg rS, const uimm 32)) :: (cr_flags_stmts 1 rA)

  let decode_logic_imm_shifted_dot _state isn op =
    let rS, rA, uimm = decode_D_Form isn in
    Set (vtreg rA, BinOp(op, lvtreg rS, const (uimm lsl 16) 32) ) :: (cr_flags_stmts 1 rA)

  let decode_cntlzw _state isn =
    let rS, rA, _, rc = decode_X_Form isn in
    let zero x y = Cmp (EQ, lvpreg rS x y, const0 (y-x+1)) in
    let rec check_zero a b n =
      if a == b then
        TernOp (zero a b, const (n+1) 32, const n 32)
      else
        let mid = (a+b+1)/2 in
        TernOp (zero mid b,
                check_zero a (mid-1) (n+b-mid+1),
                if mid == b
                then const n 32
                else check_zero mid b n) in
    Set (vtreg rA, check_zero 0 31 0) :: (cr_flags_stmts rc rA)

  (* arithmetics *)

  let decode_addis _state isn =
    let rD, rA, simm = decode_D_Form isn in
    match rA == 0 with
    | true -> [ Set (vtreg rD, const (simm lsl 16) 32) ]
    | false -> [ Set (vtreg rD, BinOp(Add, lvtreg rA, const (simm lsl 16) 32)) ]

  let decode_addi _state isn =
    let rD, rA, simm = decode_D_Form isn in
    match rA == 0 with
    | true -> [ Set (vtreg rD, sconst simm 16 32) ]
    | false -> [ Set (vtreg rD, BinOp(Add, lvtreg rA, sconst simm 16 32)) ]

  let decode_addic _state isn update_cr =
    let rD, rA, simm = decode_D_Form isn in
    let tmpreg = Register.make (Register.fresh_name ()) 33 in
    [
      Set (vt tmpreg, BinOp(Add, to33bits (lvtreg rA), to33bits (sconst simm 16 32))) ;
      Set (vpreg rD 0 31, lvp tmpreg 0 31) ;
      Set (vt ca, lvp tmpreg 32 32) ;
      Directive (Remove tmpreg) ;
    ] @ (cr_flags_stmts update_cr rD)

  let decode_add _state isn =
    let rD, rA, rB, oe, rc = decode_XO_Form isn in
    Set (vtreg rD, BinOp(Add, lvtreg rA, lvtreg rB)) :: ((xer_flags_stmts_add oe rA rB rD) @ (cr_flags_stmts rc rD))


  let add_with_carry_out expA expB rD =
    let tmpreg = Register.make (Register.fresh_name ()) 33 in
    [
      Set (vt tmpreg, BinOp(Add, expA, expB)) ;
      Set (vpreg rD 0 31, lvp tmpreg 0 31) ;
      Set (vt ca, TernOp (Cmp (EQ, lvp tmpreg 32 32, const1 1),
                          const1 1, const0 1)) ;
      Directive (Remove tmpreg) ;
    ]

  let decode_addc _state isn =
    let rD, rA, rB, oe, rc = decode_XO_Form isn in
    (add_with_carry_out (to33bits (lvtreg rA)) (to33bits (lvtreg rB)) rD)
    @ (xer_flags_stmts_add oe rA rB rD) 
    @ (cr_flags_stmts rc rD)

  let decode_adde _state isn =
    let rD, rA, rB, oe, rc = decode_XO_Form isn in
    (add_with_carry_out (BinOp(Add, to33bits (lvtreg rA), to33bits (lvtreg rB))) (to33bits (lvt ca)) rD)
    @ (xer_flags_stmts_add oe rA rB rD)
    @ (cr_flags_stmts rc rD)

  let decode_addme _state isn =
    let rD, rA, _, oe, rc = decode_XO_Form isn in
    let isn_stmts = add_with_carry_out (to33bits (lvtreg rA)) (BinOp (Add, const 0xffffffff 33, to33bits (lvt ca))) rD in
    let xer_stmts =
      if oe == 1 then [
          Set(vt ov, TernOp (BBinOp(LogAnd,
                                    Cmp (EQ, lvtreg rA, const 0x80000000 32),
                                    Cmp (EQ, lvtreg rD, const 0x7fffffff 32)),
                             const1 1, const0 1)) ;
          Set(vt so, BinOp (Or, lvt ov, lvt so)) ;
        ]
      else [] in
    isn_stmts @ xer_stmts @ (cr_flags_stmts rc rD)

  let decode_addze _state isn =
    let rD, rA, _, oe, rc = decode_XO_Form isn in
    let xer_stmts =
      if oe == 1 then [
          Set(vt ov, TernOp (BBinOp(LogAnd,
                                    Cmp (EQ, lvtreg rD, const 0x80000000 32),
                                    Cmp (EQ, lvtreg rA, const 0x7fffffff 32)),
                             const1 1, const0 1)) ;
          Set(vt so, BinOp (Or, lvt ov, lvt so)) ;
        ]
      else [] in
    (add_with_carry_out (to33bits (lvtreg rA)) (to33bits (lvt ca)) rD)
    @ xer_stmts
    @ (cr_flags_stmts rc rD)

  let decode_sub _state isn =
    let rD, rA, rB, oe, rc = decode_XO_Form isn in
    Set (vtreg rD, BinOp(Sub, lvtreg rB, lvtreg rA)) :: ((xer_flags_stmts_sub oe rA rB rD) @ (cr_flags_stmts rc rD))

  let decode_neg _state isn =
    let rD, rA, _, oe, rc = decode_XO_Form isn in
    Set (vtreg rD, BinOp(Add, UnOp(Not, lvtreg rA), const1 32)) :: ((xer_flags_stmts_neg oe rA) @ (cr_flags_stmts rc rD))

  (* CR operations *)

  let decode_cr_op _state isn op =
    let crD, crA, crB, _ = decode_XL_Form isn in
    [ Set (crbit (31-crD), BinOp (op, Lval (crbit (31-crA)), Lval (crbit (31-crB)))) ]

  let decode_cr_op_complement _state isn op =
    let crD, crA, crB, _ = decode_XL_Form isn in
    [ Set (crbit (31-crD), BinOp (op, Lval (crbit (31-crA)), UnOp(Not, Lval (crbit (31-crB))))) ]

  let decode_cr_op_not _state isn op =
    let crD, crA, crB, _ = decode_XL_Form isn in
    [ Set (crbit (31-crD), UnOp(Not, BinOp (op, Lval (crbit (31-crA)), Lval (crbit (31-crB))))) ]


  (* Decoding and switching *)

  let return (s: state) (instruction: int) (stmts: Asm.stmt list): Cfa.State.t * Data.Address.t =
    s.b.Cfa.State.stmts <- stmts;
    s.b.Cfa.State.bytes <-
        [ Char.chr (instruction land 0xff) ;
          Char.chr ((instruction lsr 8) land 0xff) ;
          Char.chr ((instruction lsr 16) land 0xff) ;
          Char.chr ((instruction lsr 24) land 0xff) ];
    s.b, Data.Address.add_offset s.a (Z.of_int 4)

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

  let decode_010011 s isn =
    match (isn lsr 1) land 0x3ff with
    | 0b0000000000-> not_implemented s isn "mcrf"
    | 0b0000010000-> decode_bclr_bcctr s isn lr        (* bclr *)
    | 0b0000100001-> decode_cr_op_not s isn Or         (* crnor *)
    | 0b0000110010-> not_implemented s isn "rfi"
    | 0b0010000001-> decode_cr_op_complement s isn And (* crandc *)
    | 0b0010010110-> not_implemented s isn "isync"
    | 0b0011000001-> decode_cr_op s isn Xor            (* crxor  *)
    | 0b0011100001-> decode_cr_op_not s isn And        (* crnand *)
    | 0b0100000001-> decode_cr_op s isn And            (* crand  *)
    | 0b0100100001-> decode_cr_op_not s isn Xor        (* creqv  *)
    | 0b0110100001-> decode_cr_op_complement s isn Or  (* crorc  *)
    | 0b0111000001-> decode_cr_op s isn Or             (* cror   *)
    | 0b1000010000-> decode_bclr_bcctr s isn ctr       (* bcctr  *)
    | _ -> error s.a (Printf.sprintf "decode_010011: unknown opcode 0x%x" isn)

  let decode_011110 s isn =
    match (isn lsr 1) land 0xf with
    | 0b0000 | 0b0001 -> not_implemented s isn "rldicl??"
    | 0b0010 | 0b0011 -> not_implemented s isn "rldicr??"
    | 0b0100 | 0b0101 -> not_implemented s isn "rldic??"
    | 0b0110 | 0b0111 -> not_implemented s isn "rldimi??"
    | 0b1000 -> not_implemented s isn "rldcl??"
    | 0b1001 -> not_implemented s isn "rldcr??"
    | _ -> error s.a (Printf.sprintf "decode_011110: unknown opcode 0x%x" isn)

  let decode_011111 s isn =
    match (isn lsr 1) land 0x3ff with
    | 0b0000000000 -> decode_cmp s isn
    | 0b0000000100 -> not_implemented s isn "tw"
    | 0b0000001000 | 0b1000001000 -> not_implemented s isn "subfc??"
    | 0b0000001001 -> not_implemented s isn "mulhdu??"
    | 0b0000001010 | 0b1000001010 -> decode_addc s isn
    | 0b0000001011 -> not_implemented s isn "mulhwu??"
    | 0b0000010011 -> not_implemented s isn "mfcr"
    | 0b0000010100 -> not_implemented s isn "lwarx"
    | 0b0000010101 -> not_implemented s isn "ld??"
    | 0b0000010111 -> not_implemented s isn "lwzx"
    | 0b0000011000 -> not_implemented s isn "slw??"
    | 0b0000011010 -> decode_cntlzw s isn
    | 0b0000011011 -> not_implemented s isn "sld??"
    | 0b0000011100 -> decode_logic s isn And (* and *)
    | 0b0000100000 -> decode_cmpl s isn
    | 0b0000101000 | 0b1000101000 -> decode_sub s isn
    | 0b0000110101 -> not_implemented s isn "ldux"
    | 0b0000110110 -> not_implemented s isn "dcbst"
    | 0b0000110111 -> not_implemented s isn "lwzux"
    | 0b0000111010 -> not_implemented s isn "cntlzd??"
    | 0b0000111100 -> decode_logic_complement s isn And (* andc *)
    | 0b0001000100 -> not_implemented s isn "td"
    | 0b0001001001 -> not_implemented s isn "mulhd??"
    | 0b0001001011 -> not_implemented s isn "mulhw??"
    | 0b0001010011 -> not_implemented s isn "mfmsr"
    | 0b0001010100 -> not_implemented s isn "ldarx"
    | 0b0001010110 -> not_implemented s isn "dcbf"
    | 0b0001010111 -> not_implemented s isn "lbzx"
    | 0b0001101000 | 0b1001101000 -> decode_neg s isn
    | 0b0001110111 -> not_implemented s isn "lbzux"
    | 0b0001111100 -> not_implemented s isn "nor??"
    | 0b0010001000 | 0b1010001000 -> not_implemented s isn "subfe??"
    | 0b0010001010 | 0b1010001010 -> decode_adde s isn
    | 0b0010010000 -> decode_mtcrf s isn
    | 0b0010010010 -> not_implemented s isn "mtmsr"
    | 0b0010010101 -> not_implemented s isn "stdx"
    | 0b0010010110 -> not_implemented s isn "stwcx."
    | 0b0010010111 -> not_implemented s isn "stwx"
    | 0b0010110101 -> not_implemented s isn "stdux"
    | 0b0010110111 -> not_implemented s isn "stwux"
    | 0b0011001000 | 0b1011001000 -> not_implemented s isn "subfze??"
    | 0b0011001010 | 0b1011001010 -> decode_addze s isn
    | 0b0011010010 -> not_implemented s isn "mtsr"
    | 0b0011010110 -> not_implemented s isn "stdcx."
    | 0b0011010111 -> not_implemented s isn "stbx"
    | 0b0011101000 | 0b1011101000 -> not_implemented s isn "subfme??"
    | 0b0011101001 | 0b1011101001 -> not_implemented s isn "mulld"
    | 0b0011101010 | 0b1011101010 -> decode_addme s isn
    | 0b0011101011 | 0b1011101011 -> not_implemented s isn "mullw??"
    | 0b0011110010 -> not_implemented s isn "mtsrin"
    | 0b0011110110 -> not_implemented s isn "dcbtst"
    | 0b0011110111 -> not_implemented s isn "stbux"
    | 0b0100001010 | 0b1100001010 ->  decode_add s isn
    | 0b0100010110 -> not_implemented s isn "dcbt"
    | 0b0100010111 -> not_implemented s isn "lhzx"
    | 0b0100011100 -> not_implemented s isn "eqv??"
    | 0b0100110010 -> not_implemented s isn "tlbie"
    | 0b0100110110 -> not_implemented s isn "eciwx"
    | 0b0100110111 -> not_implemented s isn "lhzux"
    | 0b0100111100 -> decode_logic s isn Xor (* xor *)
    | 0b0101010011 -> decode_mfspr s isn
    | 0b0101010101 -> not_implemented s isn "lwax"
    | 0b0101010111 -> not_implemented s isn "lhax"
    | 0b0101110010 -> not_implemented s isn "tlbia"
    | 0b0101110011 -> not_implemented s isn "mftb"
    | 0b0101110101 -> not_implemented s isn "lwaux"
    | 0b0101110111 -> not_implemented s isn "lhaux"
    | 0b0110010111 -> not_implemented s isn "sthx"
    | 0b0110011100 -> decode_logic_complement s isn Or (* orc *)
    | 0b1100111010 | 0b1100111011 -> not_implemented s isn "sradi??"
    | 0b0110110010 -> not_implemented s isn "slbie"
    | 0b0110110110 -> not_implemented s isn "ecowx"
    | 0b0110110111 -> not_implemented s isn "sthux"
    | 0b0110111100 -> decode_logic s isn Or (* or *)
    | 0b0111001001 | 0b1111001001 -> not_implemented s isn "divdu??"
    | 0b0111001011 | 0b1111001011 -> not_implemented s isn "divwu??"
    | 0b0111010011 -> decode_mtspr s isn
    | 0b0111010110 -> not_implemented s isn "dcbi"
    | 0b0111011100 -> not_implemented s isn "nand??"
    | 0b0111101001 | 0b1111101001 -> not_implemented s isn "divd??"
    | 0b0111101011 | 0b1111101011 -> not_implemented s isn "divw??"
    | 0b0111110010 -> not_implemented s isn "slbia"
    | 0b1000000000 -> not_implemented s isn "mcrxr"
    | 0b1000010101 -> not_implemented s isn "lswx"
    | 0b1000010110 -> not_implemented s isn "lwbrx"
    | 0b1000010111 -> not_implemented s isn "lfsx"
    | 0b1000011000 -> not_implemented s isn "srw??"
    | 0b1000011011 -> not_implemented s isn "srd??"
    | 0b1000110110 -> not_implemented s isn "tlbsync"
    | 0b1000110111 -> not_implemented s isn "lfsu??"
    | 0b1001010011 -> not_implemented s isn "mfsr"
    | 0b1001010101 -> not_implemented s isn "lswi"
    | 0b1001010110 -> not_implemented s isn "sync"
    | 0b1001010111 -> not_implemented s isn "lfdx"
    | 0b1001110111 -> not_implemented s isn "lfdux"
    | 0b1010010011 -> not_implemented s isn "mfsrin"
    | 0b1010010101 -> not_implemented s isn "stswx"
    | 0b1010010110 -> not_implemented s isn "stwbrx"
    | 0b1010010111 -> not_implemented s isn "stfsx"
    | 0b1010110111 -> not_implemented s isn "stfsux"
    | 0b1011010101 -> not_implemented s isn "stswi"
    | 0b1011010111 -> not_implemented s isn "stfdx"
    | 0b1011110111 -> not_implemented s isn "stfdux"
    | 0b1100010110 -> not_implemented s isn "lhbrx"
    | 0b1100011000 -> not_implemented s isn "sraw??"
    | 0b1100011010 -> not_implemented s isn "srad??"
    | 0b1100111000 -> not_implemented s isn "srawi??"
    | 0b1101010110 -> not_implemented s isn "eieio"
    | 0b1110010110 -> not_implemented s isn "sthbrx"
    | 0b1110011010 -> not_implemented s isn "extsh??"
    | 0b1110111010 -> not_implemented s isn "extsb??"
    | 0b1111010110 -> not_implemented s isn "icbi"
    | 0b1111010111 -> not_implemented s isn "stfiwx"
    | 0b1111011010 -> not_implemented s isn "extsw"
    | 0b1111110110 -> not_implemented s isn "dcbz"
    | _ -> error s.a (Printf.sprintf "decode_011111: unknown opcode 0x%x" isn)

  let decode_111010 s isn =
    match isn land 0x3 with
    | 0b00 -> not_implemented s isn "ld"
    | 0b01 -> not_implemented s isn "ldu"
    | 0b10 -> not_implemented s isn "lwa"
    | _ -> error s.a (Printf.sprintf "decode_111010: unknown opcode 0x%x" isn)

  let decode_111011 s isn =
    match (isn lsr 1) land 0x1f with
    | 0b10010 -> not_implemented s isn "fdivs??"
    | 0b10100 -> not_implemented s isn "fsubs??"
    | 0b10101 -> not_implemented s isn "adds??"
    | 0b10110 -> not_implemented s isn "fsqrts??"
    | 0b11000 -> not_implemented s isn "fres??"
    | 0b11001 -> not_implemented s isn "fmuls??"
    | 0b11100 -> not_implemented s isn "fmsubs??"
    | 0b11101 -> not_implemented s isn "fmadds??"
    | 0b11110 -> not_implemented s isn "fnmsubs??"
    | 0b11111 -> not_implemented s isn "fnmadds??"
    | _ -> error s.a (Printf.sprintf "decode_111011: unknown opcode 0x%x" isn)

  let decode_111110 s isn =
    match isn land 0x3 with
    | 0b00 -> not_implemented s isn "std"
    | 0b01 -> not_implemented s isn "stdu"
    | _ -> error s.a (Printf.sprintf "decode_111110: unknown opcode 0x%x" isn)

  let decode_111111 s isn =
    match (isn lsr 1) land 0x1f with
    | 0b10111 -> not_implemented s isn "fsel??"
    | 0b11001 -> not_implemented s isn "fmul??"
    | 0b11100 -> not_implemented s isn "fmsub??"
    | 0b11101 -> not_implemented s isn "fmadd??"
    | 0b11110 -> not_implemented s isn "fnmsub??"
    | 0b11111 -> not_implemented s isn "fnmadd??"
    | _ ->
       match (isn lsr 1) land 0x3ff with
       | 0b0000000000 -> not_implemented s isn "fcmpu"
       | 0b0000001100 -> not_implemented s isn "frsp??"
       | 0b0000001110 -> not_implemented s isn "fctiw??"
       | 0b0000001111 -> not_implemented s isn "fctiwz??"
       | 0b0000010010 -> not_implemented s isn "fdiv??"
       | 0b0000010100 -> not_implemented s isn "fsub??"
       | 0b0000010101 -> not_implemented s isn "fadd??"
       | 0b0000010110 -> not_implemented s isn "fsqrt??"
       | 0b0000011010 -> not_implemented s isn "frsqrte??"
       | 0b0000100000 -> not_implemented s isn "fcmpo"
       | 0b0000100110 -> not_implemented s isn "mtfsb1??"
       | 0b0000101000 -> not_implemented s isn "fneg??"
       | 0b0001000000 -> not_implemented s isn "mcrfs"
       | 0b0001000110 -> not_implemented s isn "mtfsb0??"
       | 0b0001001000 -> not_implemented s isn "fmr??"
       | 0b0010000110 -> not_implemented s isn "mtfsfi??"
       | 0b0010001000 -> not_implemented s isn "fnabs??"
       | 0b0100001000 -> not_implemented s isn "fabs??"
       | 0b1001000111 -> not_implemented s isn "mffs??"
       | 0b1011000111 -> not_implemented s isn "mtfsf??"
       | 0b1100101110 -> not_implemented s isn "fctid??"
       | 0b1100101111 -> not_implemented s isn "fctidz??"
       | 0b1101001110 -> not_implemented s isn "fcfid??"
       | _ -> error s.a (Printf.sprintf "decode_11111: unknown opcode 0x%x" isn)


  let decode s: Cfa.State.t * Data.Address.t =
    let str = String.sub s.buf 0 4 in
    let isn  = build_instruction s str in
    let stmts = match (isn lsr 26) land 0x3f with
      | 0x60 -> []
(*      | 0b000000 ->  *)
(*      | 0b000001 ->  *)
      | 0b000010 -> not_implemented s isn "tdi"
      | 0b000011 -> not_implemented s isn "twi"
(*      | 0b000100 -> *)
(*      | 0b000101 -> *)
(*      | 0b000110 -> *)
      | 0b000111 -> not_implemented s isn "mulli"
      | 0b001000 -> not_implemented s isn "subfic"
(*      | 0b001001 ->  *)
      | 0b001010 -> decode_cmpli s isn
      | 0b001011 -> not_implemented s isn "cmpi"
      | 0b001100 -> decode_addic s isn 0 (* addic  *)
      | 0b001101 -> decode_addic s isn 1 (* addic. *)
      | 0b001110 -> decode_addi s isn
      | 0b001111 -> decode_addis s isn
      | 0b010000 -> decode_branch_condition s isn (* bc bca bcl bcla *)
      | 0b010001 -> not_implemented s isn "sc"
      | 0b010010 -> decode_branch s isn
      | 0b010011 -> decode_010011 s isn (* mcrf bclr?? crnor rfi crandc isync crxor crnand crand creqv crorc cror bcctr?? *)
      | 0b010100 -> not_implemented s isn "rlwimi??"
      | 0b010101 -> not_implemented s isn "rlwinm??"
(*      | 0b010110 ->  *)
      | 0b010111 -> not_implemented s isn "rlwnm??"
      | 0b011000 -> decode_logic_imm s isn Or              (* ori    *)
      | 0b011001 -> decode_logic_imm_shifted s isn Or      (* oris   *)
      | 0b011010 -> decode_logic_imm s isn Xor             (* xor    *)
      | 0b011011 -> decode_logic_imm_shifted s isn Xor     (* xori   *)
      | 0b011100 -> decode_logic_imm_dot s isn And         (* andi.  *)
      | 0b011101 -> decode_logic_imm_shifted_dot s isn And (* andis. *)
      | 0b011110 -> decode_011110 s isn (* rldicl?? rldicr?? rldic?? rldimi?? rldcl?? rldcr??*)
      | 0b011111 -> decode_011111 s isn (* cmp rw subfc?? mulhdu?? addc?? mulhwu?? mfcr lwarx ldx lwzx slw?? cntlzw?? sld?? and?? cmpl subf?? ldux dcbst lwzux cntlzd??.... *)
      | 0b100000 -> not_implemented s isn "lwz"
      | 0b100001 -> not_implemented s isn "lwzu"
      | 0b100010 -> not_implemented s isn "lbz"
      | 0b100011 -> not_implemented s isn "lbzu"
      | 0b100100 -> not_implemented s isn "stw"
      | 0b100101 -> not_implemented s isn "stwu"
      | 0b100110 -> not_implemented s isn "stb"
      | 0b100111 -> not_implemented s isn "stbu"
      | 0b101000 -> not_implemented s isn "lhz"
      | 0b101001 -> not_implemented s isn "lhzu"
      | 0b101010 -> not_implemented s isn "lha"
      | 0b101011 -> not_implemented s isn "lhau"
      | 0b101100 -> not_implemented s isn "sth"
      | 0b101101 -> not_implemented s isn "sthu"
      | 0b101110 -> not_implemented s isn "lmw"
      | 0b101111 -> not_implemented s isn "stmw"
      | 0b110000 -> not_implemented s isn "lfs"
      | 0b110001 -> not_implemented s isn "lfsu"
      | 0b110010 -> not_implemented s isn "lfd"
      | 0b110011 -> not_implemented s isn "lfdu"
      | 0b110100 -> not_implemented s isn "stfs"
      | 0b110101 -> not_implemented s isn "stfsu"
      | 0b110110 -> not_implemented s isn "stfd"
      | 0b110111 -> not_implemented s isn "stfdu"
(*      | 0b111000 ->  *)
(*      | 0b111001 ->  *)
      | 0b111010 -> decode_111010 s isn (* ld ldu lwa *)
      | 0b111011 -> decode_111011 s isn (* fdivs?? fsubs?? f... *)
(*      | 0b111100 ->  *)
(*      | 0b111101 ->  *)
      | 0b111110 ->  decode_111110 s isn (* std stdu *)
      | 0b111111 -> decode_111111 s isn (* fcmpu frsp?? ... *)

      | _ -> error s.a (Printf.sprintf "Unknown opcode 0x%x" isn) in
    return s isn stmts


  let parse text cfg _ctx state addr _oracle =

    let s =  {
      g = cfg;
      b = state;
      a = addr;
      buf = text;
      endianness = !Config.endianness;
    }
    in
    try
      let v', ip' = decode s in
      Some (v', ip', ())
    with
      | Exceptions.Error _ as e -> raise e
      | _  -> (*end of buffer *) None


  let init () =
    Imports.init ()

  let overflow_expression () = Lval (V (P (cr, 28, 28)))

end
