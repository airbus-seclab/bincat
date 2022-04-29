(*
    This file is part of BinCAT.
    Copyright 2014-2022 - Airbus

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
(* https://wiki.raptorcs.com/wiki/File:PowerISA_public.v3.1.pdf *)

module L = Log.Make(struct let name = "powerpc" end)

open Data
open Asm
open Decodeutils

let ith_bit v n sz = (v lsr (sz-n-1)) land 0b1
                
(* split field decoding *)

  let decode_split_field x =
    ((x lsr 5) land 0x1f) lor ((x land 0x1f) lsl 5)

  (* PPC Forms decoding *)

  (* ST type as in prefix opcode for PPC64 *)
  type st_t = { r: int; ie: int; } (* manual reference 1.6.3.1 *)
  type prefix_t =
    | LoadStore of st_t
                 
  
  let decode_I_Form isn =
    let li = isn land 0x03fffffc in
    let aa = (isn lsr 1) land 1 in
    let lk = isn land 1 in
    li, aa, lk
    
  let decode_B_Form isn =
    let bo = (isn lsr 21) land 0x1f in
    let bi = (isn lsr 16) land 0x1f in
    let bd = (isn lsr 2) land 0x3fff in
    let aa = (isn lsr 1) land 1 in
    let lk = isn land 1 in
    bo, bi, bd, aa, lk

  let decode_D_L_Form prefix isn =
    let op1 = (isn lsr 23) land 0x07 in
    let op2 = (isn lsr 16) land 0x1f in
    let imm = (isn land 0xffff) in
    let l = (isn lsr 21) land 0x01 in
    let imm', sz =
      match prefix with
      | Some LoadStore st -> (st.ie lsl 18) lor imm, 34 (* IE is concatenated on the left *)
      | _ -> imm, 16
    in
    op1, l, op2, imm', sz

    let decode_D_Form prefix isn =
    let op1 = (isn lsr 21) land 0x1f in
    let op2 = (isn lsr 16) land 0x1f in
    let imm = (isn land 0xffff) in
    let imm', sz =
      match prefix with
      | Some LoadStore st -> (st.ie lsl 18) lor imm, 34 (* IE is concatenated on the left *)
      | _ -> imm, 16
    in
    op1, op2, imm', sz

  let decode_M_Form isn =
    let rS = (isn lsr 21) land 0x1f in
    let rA = (isn lsr 16) land 0x1f in
    let rBsh = (isn lsr 11) land 0x1f in
    let mb = (isn lsr 6) land 0x1f in
    let me = (isn lsr 1) land 0x1f in
    let rc = (isn land 1) in
    rS, rA, rBsh, mb, me, rc

  let decode_X_Form isn =
    let rSD = (isn lsr 21) land 0x1f in
    let rA = (isn lsr 16) land 0x1f in
    let rB = (isn lsr 11) land 0x1f in
    let rc = (isn land 1) in
    rSD, rA, rB, rc

    let decode_X_L_Form isn =
    let rSD = (isn lsr 23) land 0x07 in
    let rA = (isn lsr 16) land 0x1f in
    let rB = (isn lsr 11) land 0x1f in
    let rc = (isn land 1) in
    let l = (isn lsr 21) land 0x1 in
    rSD, l, rA, rB, rc

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

  let decode_DS_Form isn =
    let ds = (isn lsr 2) land 0x3fff in
    let ra = (isn lsr 16) land 0x1f in
    let rs = (isn lsr 21) land 0x1f in
    rs, ra, ds
    
  let z4 = Z.of_int 4
         
module PPC =
  struct
    let size = 32
    let mode = ref 32
             
    let decode_conditional_core_XL_form a isn lr lr_or_ctr wrapper =
      let bo, bi, _, lk = decode_XL_Form isn in
      let cia = Address.to_int a in
      let c = zconst (Z.add cia z4) 32 in
      let update_lr = if lk == 0 then [] else [ Set (V (T lr), c) ] in
      let if_jump = Jmp (R (Lval (V (P(lr_or_ctr, 0, 29))))) in

      (wrapper bi bo [if_jump] a) @ update_lr

    let decode_conditional_lr_XL_form a isn lr wrapper =
      decode_conditional_core_XL_form a isn lr lr wrapper

    let decode_conditional_ctr_XL_form a isn lr _cr ctr wrapper =
      decode_conditional_core_XL_form a isn lr ctr wrapper


    let c80 = const 0x80000000 32
    let c7f = const 0x7fffffff 32
    let cff = const 0xffffffff 32
    let cff_e = const 0xffffffff 33

    let cr_flag_test r _imod = V (T r)

    let msb_reg r _imod = msb_reg r
  end

module PPC64 =
  struct
    let size = 64
    let mode = ref 64
                               
    let c80 = Const (Word.of_int (Z.of_string "0x8000000000000000") 64)
    let c7f = Const (Word.of_int (Z.of_string "0x7fffffffffffffff") 64)
    let cff = Const (Word.of_int (Z.of_string "0xffffffffffffffff") 64)
    let cff_e = Const (Word.of_int (Z.of_string "0xffffffffffffffff") 65)

                       
    let core_conditional_XL_form a isn lr =
      let bo, bi, _, lk = decode_XL_Form isn in
      let cia = Address.to_int a in
      let c = zconst (Z.add cia z4) 64 in
      let update_lr = if lk == 0 then [] else [ Set (V (T lr), c) ] in
      bo, bi, update_lr
      
    let decode_conditional_lr_XL_form a isn lr wrapper =
      let bo, bi, update_lr = core_conditional_XL_form a isn lr in
      let if_jump = Jmp (R (Lval (V (P(lr, 0, 61))))) in
      (wrapper bi bo [if_jump] a) @ update_lr
      
    let decode_conditional_ctr_XL_form a isn _lr _cr ctr wrapper =
      let bo, bi, update_ctr = core_conditional_XL_form a isn ctr in
      let if_jump = Jmp (R (Lval (V (P(ctr, 0, 61))))) in
      (wrapper bi bo [if_jump] a) @ update_ctr
     
    let cr_flag_test r imod =
      if imod = 32 then V (P(r, 0, 31))
      else V (T r)

    let msb_reg (r: Register.t) (imod: int) =
      let imod' = imod - 1 in
      let sz_min_one = const (imod') imod in
      BinOp(And, (const1 imod), BinOp(Shr, Lval (V (P(r, 0, imod'))), sz_min_one))
      
      
  end

module type Isa =
  sig
    val size: int
    val mode: int ref
    val decode_conditional_lr_XL_form: Address.t -> int -> Register.t -> (int -> int -> (Asm.stmt list) -> Data.Address.t -> (Asm.stmt list)) -> (Asm.stmt list)

    val decode_conditional_ctr_XL_form: Address.t -> int -> Register.t -> Register.t -> Register.t -> (int -> int -> (Asm.stmt list) -> Data.Address.t -> (Asm.stmt list)) -> (Asm.stmt list)


    val c7f: Asm.exp
    val cff: Asm.exp
    val cff_e: Asm.exp
    val c80: Asm.exp
   
    val cr_flag_test: Register.t -> int -> Asm.lval

    val msb_reg: Register.t -> int -> exp
    end
module Make(Isa: Isa)(Domain: Domain.T)(Stubs: Stubs.T with type domain_t := Domain.t)=
struct

  type ctx_t = unit
            
  module Cfa = Cfa.Make(Domain)
               
  type state = {
    mutable g             : Cfa.t;        (** current cfa *)
    mutable b             : Cfa.State.t;  (** state predecessor *)
    mutable a             : Address.t;    (** current address to decode *)
    buf                   : string;       (** buffer to decode *)
    endianness            : Config.endianness_t;      (** whether memory access is little endian *)
    mutable isn           : int list; (** list of 32-bit instruction chunks *)
    mutable prefix: prefix_t option; (* prefix for PPC64 only; field = None for 32-bits *)
  }


  (************************************************************************)
  (* Creation of the general purpose registers *)
  (************************************************************************)
  let (register_tbl: (int, Register.t) Hashtbl.t) = Hashtbl.create 16;;
  let r0 = Register.make ~name:"r0" ~size:Isa.size;;
  let r1 = Register.make ~name:"r1" ~size:Isa.size;;
  let r2 = Register.make ~name:"r2" ~size:Isa.size;;
  let r3 = Register.make ~name:"r3" ~size:Isa.size;;
  let r4 = Register.make ~name:"r4" ~size:Isa.size;;
  let r5 = Register.make ~name:"r5" ~size:Isa.size;;
  let r6 = Register.make ~name:"r6" ~size:Isa.size;;
  let r7 = Register.make ~name:"r7" ~size:Isa.size;;
  let r8 = Register.make ~name:"r8" ~size:Isa.size;;
  let r9 = Register.make ~name:"r9" ~size:Isa.size;;
  let r10 = Register.make ~name:"r10" ~size:Isa.size;;
  let r11 = Register.make ~name:"r11" ~size:Isa.size;;
  let r12 = Register.make ~name:"r12" ~size:Isa.size;;
  let r13 = Register.make ~name:"r13" ~size:Isa.size;;
  let r14 = Register.make ~name:"r14" ~size:Isa.size;;
  let r15 = Register.make ~name:"r15" ~size:Isa.size;;
  let r16 = Register.make ~name:"r16" ~size:Isa.size;;
  let r17 = Register.make ~name:"r17" ~size:Isa.size;;
  let r18 = Register.make ~name:"r18" ~size:Isa.size;;
  let r19 = Register.make ~name:"r19" ~size:Isa.size;;
  let r20 = Register.make ~name:"r20" ~size:Isa.size;;
  let r21 = Register.make ~name:"r21" ~size:Isa.size;;
  let r22 = Register.make ~name:"r22" ~size:Isa.size;;
  let r23 = Register.make ~name:"r23" ~size:Isa.size;;
  let r24 = Register.make ~name:"r24" ~size:Isa.size;;
  let r25 = Register.make ~name:"r25" ~size:Isa.size;;
  let r26 = Register.make ~name:"r26" ~size:Isa.size;;
  let r27 = Register.make ~name:"r27" ~size:Isa.size;;
  let r28 = Register.make ~name:"r28" ~size:Isa.size;;
  let r29 = Register.make ~name:"r29" ~size:Isa.size;;
  let r30 = Register.make ~name:"r30" ~size:Isa.size;;
  let r31 = Register.make ~name:"r31" ~size:Isa.size;;

  let lr = Register.make ~name:"lr" ~size:Isa.size;;
  let ctr = Register.make ~name:"ctr" ~size:Isa.size;;
  let cr = Register.make ~name:"cr" ~size:32;; (* actual cr size is 32 in PPC64 in cr[32:63]*)

  (* condition flags are modeled as registers of size 1 *)

  (* fields from Fixed Point Exception Register (XER) *)
  let so = Register.make ~name:"so" ~size:1;;
  let ov = Register.make ~name:"ov" ~size:1;;
  let ca = Register.make ~name:"ca" ~size:1;;
  let ca32 = Register.make ~name:"ca32" ~size:1;;
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

  let ext_e e = UnOp(ZeroExt (Isa.size+1), e)
  let ext_e_s e = UnOp(SignExt (Isa.size+1), e)

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
                   
  let crbit x = V (P (cr, x, x))

  (* Update CR[0] according to the latest result. Must be called after XER has been updated for CR[0].so to reflect XER.so *)
  let cr_flags_stmts rc rD imod =
    if rc == 1 then [
        Set(crbit 31, (* cr[0].lt *)
            TernOp(Cmp (EQ, Isa.msb_reg (reg rD) imod, const1 imod),
                   const1 1, const0 1)) ;
        Set(crbit 30, (* cr[0].gt *)
            TernOp(BBinOp (LogAnd,
                           Cmp (EQ, Isa.msb_reg (reg rD) imod, const0 imod),
                           Cmp (NEQ, lvpreg rD 0 (imod-1), const0 imod)),
                   const1 1, const0 1)) ;
        Set(crbit 29, (* cr[0].eq *)
            TernOp(Cmp (EQ, Lval (Isa.cr_flag_test (reg rD) imod), const0 imod),
                   const1 1, const0 1)) ;
        Set(crbit 28, lvt so) ; (* cr[0].so *)
      ]
    else []

    (* Update XER flag after rD <- rA + rB *)
    let xer_flags_stmts_add oe rA rB rD =
      if oe == 1 then
        [ 
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
          Set(vt ov, TernOp (Cmp (EQ, lvtreg rA, Isa.c80),
                             const1 1, const0 1)) ;
          Set(vt so, BinOp (Or, lvt ov, lvt so)) ;
        ]
      else []


  (* fatal error reporting *)
  let error a msg =
    L.abort (fun p -> p "at %s: %s" (Address.to_string a) msg)

  let not_implemented s isn isn_name =
    L.abort (fun p -> p "at %s: instruction %s not implemented yet (isn=%08x)" (Address.to_string s.a) isn_name isn)

  let not_implemented_64bits s isn isn_name =
    L.abort (fun p -> p "at %s: instruction %s is 64-bit only (isn=%08x)" (Address.to_string s.a) isn_name isn)

  
  (* Operation decoders *)


  let do_nothing s isn isn_name =
    L.analysis (fun p -> p "%s: instruction %s (isn=%08x) ignored"
                           (Address.to_string s.a) isn_name isn);
    []


  (* Branching *)
                  
  let wrap_with_bi_bo_condition bi bo if_stmts a =
    let bo_0 = ith_bit bo 0 5 in
    let bo_1 = const (ith_bit bo 1 5) 1 in
    let bo_2 = ith_bit bo 2 5 in
    let bo_3 = ith_bit bo 3 5 in
    let stmts =
      if bo_2 <> 0 then []
      else [ Set(vt ctr, BinOp(Sub, lvt ctr, const1 Isa.size)) ]
    in
    let ctr_ok =
      if bo_2 = 0 then
        let cmp = if bo_3 = 1 then EQ else NEQ in
        let len = !Isa.mode in 
        Cmp(cmp, lvp ctr 0 (len-1), const0 len)     
      else BConst true
    in
    let cond_ok =
      let test = crbit (31-bi) in
      if bo_0 = 0 then Cmp(EQ, Lval test, bo_1)
      else BConst true
    in
    let cia = Address.to_int a in
    let c = zconst (Z.add cia z4) Isa.size in
    let else_jmp = Jmp (R c) in
    let ctr_and_cond_ok = BBinOp(LogAnd, ctr_ok, cond_ok) in
    stmts @ [ If (ctr_and_cond_ok, if_stmts, [else_jmp]) ]


  (* auxiliary functions to sign extend z or z+off) on sz bits taking into account the Isa.mode *) 
  let gen_signext z off sz =
    let se_z =
      sign_extension (Z.of_int z) sz !Isa.mode
    in
    let se_z' = 
      match off with
      | None -> se_z
      | Some o -> Z.add o se_z
    in
    let c = Const (Word.of_int se_z' Isa.size) in 
    if !Isa.mode < Isa.size then
      UnOp(ZeroExt Isa.size, c)
    else c
    
  let decode_branch_I_form state isn =
    let li, aa, lk = decode_I_Form isn in
    let cia = Address.to_int state.a in
    let cia' = Z.add cia (Z.of_int 4) in
    let update_lr =
      if lk == 0 then []
      else [ Set (vt lr, zconst cia' Isa.size) ]
    in
    let target =
      if aa == 1 then R (gen_signext li None 24)
      else R (gen_signext li (Some cia) 24)
    in
    let jump_stmt =
      if lk == 0
      then [ Jmp target ]
      else [ Call target ]
    in
    jump_stmt @ update_lr

  let decode_branch_conditional_B_form state isn =
    let bo, bi, bd, aa, lk = decode_B_Form isn in
    let bd = bd lsl 2 in
    let cia = Address.to_int state.a in
    let update_lr =
      if lk == 0 then []
      else [ Set (vt lr, zconst (Z.add cia (Z.of_int 4)) Isa.size) ] in
    let jump =
      if aa == 1 then Jmp (R (gen_signext bd None 14))
      else Jmp (R (gen_signext bd (Some cia) 14))
    in
    (wrap_with_bi_bo_condition bi bo [jump] state.a) @ update_lr

  let decode_conditional_lr_XL_form state isn =
    Isa.decode_conditional_lr_XL_form state.a isn lr wrap_with_bi_bo_condition

  let decode_conditional_ctr_XL_form state isn =
    Isa.decode_conditional_ctr_XL_form state.a isn lr cr ctr wrap_with_bi_bo_condition

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
    | 287 -> (* PV processor version *)
       [ Set (vtreg rD, const !Config.processor_version Isa.size) ]
    | n -> error state.a (Printf.sprintf "mfspr from SPR #%i not supported yet" n)

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
    | 9 -> (* CTR *)
       [ Set (vt ctr, lvtreg rS) ]
    | n -> error state.a (Printf.sprintf "mtspr to SPR #%i not supported yet" n)


  (* compare *)
  let sz_of_cmp l crfD =
    let sz =
      if Isa.size = 32 || l = 0 then 33
      else 65
    in
    sz, 4*crfD
    
  let compare_arithmetical crfD exprA exprB sz =  
    let tmpreg = Register.make (Register.fresh_name ()) sz in
    let ext_e_s e = UnOp(SignExt sz, e) in
    [
      Set (vt tmpreg, BinOp(Sub, ext_e_s exprA, ext_e_s exprB)) ;
      Set (crbit (31-crfD), TernOp (Cmp (NEQ, msb_reg tmpreg, const0 sz),
                                          const1 1, const0 1)) ;
      Set (crbit (30-crfD), TernOp (BBinOp(LogAnd, Cmp (EQ, msb_reg tmpreg, const0 sz),
                                            Cmp(NEQ, lvt tmpreg, const0 sz)),
                                                        const1 1, const0 1)) ;
      Set (crbit (29-crfD), TernOp (Cmp (EQ, exprA, exprB),
                                      const1 1, const0 1)) ;
      Set (crbit (28-crfD), lvt so) ;
      Directive (Remove tmpreg) ;
    ]

  let decode_cmp _state isn =
    let crfD, l, rA, rB, _ = decode_X_L_Form isn in
    let sz, crfD' = sz_of_cmp l crfD in
    let u = sz - 2 in
    compare_arithmetical crfD' (lvpreg rA 0 u) (lvpreg rB 0 u) sz

  let decode_cmpi state isn =
    let crfD, l, rA, simm, sz = decode_D_L_Form state.prefix isn in
    let u, crfD' = sz_of_cmp l crfD in
    let u' = u - 2 in
    compare_arithmetical crfD' (lvpreg rA 0 u') (sconst simm sz (u'+1)) u

  let compare_logical crfD exprA exprB =
    [
      Set (crbit (31-crfD), TernOp (Cmp (LT, exprA, exprB), const1 1, const0 1)) ;
      Set (crbit (30-crfD), TernOp (Cmp (GT, exprA, exprB), const1 1, const0 1)) ;
      Set (crbit (29-crfD), TernOp (Cmp (EQ, exprA, exprB), const1 1, const0 1)) ;
      Set (crbit (28-crfD), lvt so) ;
    ]

  let decode_cmpl _state isn =
    let crfD, l, rA, rB, _ = decode_X_L_Form isn in
    let u, crfD' = sz_of_cmp l crfD in
    let u = u - 2 in
    compare_logical crfD' (lvpreg rA 0 u) (lvpreg rB 0 u) 

  let decode_cmpli state isn =
    let crfD, l, rA, uimm, _sz = decode_D_L_Form state.prefix isn in
    let u, crfD' = sz_of_cmp l crfD in
    let u = u - 2 in
    compare_logical crfD' (lvpreg rA 0 u) (const uimm (u+1))

  (* logic *)

  let decode_logic _state isn op =
    let rS, rA, rB, rc = decode_X_Form isn in
    Set (vtreg rA, BinOp (op, lvtreg rS, lvtreg rB)) :: (cr_flags_stmts rc rA !Isa.mode)

  let decode_logic_complement _state isn op =
    let rS, rA, rB, rc = decode_X_Form isn in
    Set (vtreg rA, BinOp (op, lvtreg rS, UnOp(Not, lvtreg rB))) :: (cr_flags_stmts rc rA !Isa.mode)

  let decode_logic_not _state isn op =
    let rS, rA, rB, rc = decode_X_Form isn in
    Set (vtreg rA, UnOp (Not, BinOp (op, lvtreg rS, lvtreg rB))) :: (cr_flags_stmts rc rA !Isa.mode)

  let decode_logic_imm state isn op =
    let rS, rA, uimm, _sz = decode_D_Form state.prefix isn in
    [ Set (vtreg rA, BinOp(op, lvtreg rS, const uimm Isa.size) ) ]

  let decode_logic_imm_shifted state isn op =
    let rS, rA, uimm, sz = decode_D_Form state.prefix isn in
    [ Set (vtreg rA, BinOp(op, lvtreg rS, const (uimm lsl sz) Isa.size) ) ]

  let decode_logic_imm_dot state isn op =
    let rS, rA, uimm, _sz = decode_D_Form state.prefix isn in
    Set (vtreg rA, BinOp(op, lvtreg rS, const uimm Isa.size)) :: (cr_flags_stmts 1 rA !Isa.mode)

  let decode_logic_imm_shifted_dot state isn op =
    let rS, rA, uimm, sz = decode_D_Form state.prefix isn in
    Set (vtreg rA, BinOp(op, lvtreg rS, const (uimm lsl sz) Isa.size) ) :: (cr_flags_stmts 1 rA !Isa.mode)

  let decode_cntlzw _state isn =
    let rS, rA, _, rc = decode_X_Form isn in
    let zero x y = Cmp (EQ, lvpreg rS x y, const0 (y-x+1)) in
    let rec check_zero a b n =
      if a == b then
        TernOp (zero a b, const (n+1) Isa.size, const n Isa.size)
      else
        let mid = (a+b+1)/2 in
        TernOp (zero mid b,
                check_zero a (mid-1) (n+b-mid+1),
                if mid == b
                then const n Isa.size
                else check_zero mid b n) in
    Set (vtreg rA, check_zero 0 31 0) :: (cr_flags_stmts rc rA !Isa.mode)

  let decode_rlwimi _state isn =
    let rS, rA, sh, mb, me, rc = decode_M_Form isn in
    let rS', pre, post =
      if Isa.size = 32 then
       lvtreg rS, [], []
      else
        let vps = Register.make (Register.fresh_name ()) Isa.size in
        lvt vps, [Set (vt vps, UnOp(ZeroExt Isa.size, lvpreg rS 0 31));
                  Set (vp vps 32 (Isa.size-1), lvpreg rS 0 31) ], [Directive (Remove vps)]
    in
    let tmpreg = Register.make (Register.fresh_name ()) Isa.size in
    let rot = [ Set (vt tmpreg, BinOp(Or,
                                      BinOp(Shl, rS', const sh Isa.size),
                                      BinOp(Shr, rS', const (Isa.size-sh) Isa.size))) ]
    in
    let u = 32-1 in
    let stmts, u' =
      if mb <= me then
        [ Set (vpreg rA (u-me) (u-mb), lvp tmpreg (u-me) (u-mb)) ], None
      else 
        [ Set (vpreg rA 0 (u-mb), lvp tmpreg 0 (u-mb)) ;
          Set (vpreg rA (u-me) u, lvp tmpreg (u-me) u) ], Some (u+1)
    in
    let stmts' =
      match Isa.size, u' with
      | n, _ when n = 32 -> []
      | _, Some u' -> [Set (vpreg rA u' (Isa.size-1), lvp tmpreg u' (Isa.size-1)) ]
      | _ -> []
    in
    let remove = [ Directive (Remove tmpreg) ] in
    pre @ rot @ stmts @ stmts' @ post @ remove @ (cr_flags_stmts rc rA !Isa.mode)


  let build_mask mb me tmpreg =
    let mb' = 31 - mb in
    let me' = 31 - me in
    if mb <= me then
      let before =
        let n = me'- 1 in
        if n >= 0 then
          [ Set (vp tmpreg 0 n, const0 (n+1)) ]
        else []
      in
      let after =
        let n = mb' + 1 in
        if n <= Isa.size-1 then
          [Set(vp tmpreg n (Isa.size-1), const0 (Isa.size-n)) ]
        else
          []
      in
      before @ after
    else
      let mb' = mb' + 1 in
      let me' = me' - 1 in
      if mb' <=  me' then
        [ Set (vp tmpreg mb' me', const0 (me'- mb' + 1)) ]
      else
        []

  let concat32 rS =
    let vps = Register.make (Register.fresh_name ()) Isa.size in
    lvt vps, [Set (vt vps, UnOp(ZeroExt Isa.size, lvpreg rS 0 31));
              Set (vp vps 32 (Isa.size-1), lvpreg rS 0 31) ], [Directive (Remove vps)]

  let decode_rlwinm _state isn =
    let rS, rA, sh, mb, me, rc = decode_M_Form isn in
    let rS', pre, post =
      if Isa.size = 32 then
       lvtreg rS, [], []
      else
        concat32 rS
    in
    let tmpreg = Register.make (Register.fresh_name ()) Isa.size in
    let rot =  [ Set (vt tmpreg, BinOp(Or,
                                      BinOp(Shl, rS', const sh Isa.size),
                                      BinOp(Shr, rS', const (Isa.size-sh) Isa.size))) ]
    in
    let stmts = build_mask mb me tmpreg @ [Set (vtreg rA, lvt tmpreg) ] in
    pre @ rot @ stmts @ post @ [ Directive (Remove tmpreg) ] @ (cr_flags_stmts rc rA !Isa.mode)


  let decode_rlwnm _state isn =
    let rS, rA, rB, mb, me, rc = decode_M_Form isn in
    let lval_sh = BinOp(And, lvpreg rB 0 (Isa.size-1), const 0x1f Isa.size) in
    let lval_msh = BinOp(Sub, const Isa.size Isa.size, lval_sh) in
    let rS', pre, post =
      if Isa.size = 32 then
       lvtreg rS, [], []
      else
        concat32 rS
    in
    let tmpreg = Register.make (Register.fresh_name ()) Isa.size in
    let rot = [ Set (vt tmpreg, BinOp(Or,
                                      BinOp(Shl, rS', lval_sh),
                                      BinOp(Shr, rS', lval_msh))) ]
    in
    let stmts = build_mask mb me tmpreg @ [Set (vtreg rA, lvt tmpreg) ] in
    pre @ rot @ stmts @ post @ [ Directive (Remove tmpreg) ] @ (cr_flags_stmts rc rA !Isa.mode)

  let decode_logic_shift _state isn shift =
    let rS, rA, rB, rc = decode_X_Form isn in
    let post =
      if Isa.size = 32 then []
      else [ Set (vpreg rA 32 63, const0 32) ]
    in
    If (Cmp (EQ, lvpreg rB 5 5, const0 1),
        [ Set (vpreg rA 0 31, BinOp(shift, lvpreg rS 0 31,
                               UnOp(ZeroExt 32, lvpreg rB 0 4)))] @ post,
        [ Set (vtreg rA, const0 Isa.size) ] ) :: (cr_flags_stmts rc rA !Isa.mode)

  let decode_sraw _state isn =
    let rS, rA, rB, rc = decode_X_Form isn in
    let sz = Isa.size * 2 in
    let tmpreg = Register.make (Register.fresh_name ()) sz in
    [
      If (Cmp (EQ, lvpreg rB 5 5, const1 1),
          [ Set (vtreg rA, UnOp (SignExt Isa.size, (lvpreg rS 31 31))) ;
            Set (vt ca, lvpreg rS 31 31) ],
          [ Set (vt tmpreg , UnOp(SignExt sz, lvtreg rS)) ;
            Set (vt tmpreg, BinOp (Shr, lvt tmpreg, UnOp(ZeroExt sz, lvpreg rB 0 4))) ;
            Set (vtreg rA, lvp tmpreg 0 (Isa.size-1)) ;
            Directive (Remove tmpreg) ;
            Set (vt ca, TernOp (BBinOp (LogOr,
                                        Cmp (EQ, lvpreg rS 31 31, const0 1),
                                        Cmp (EQ,
                                             BinOp (Shl, lvpreg rS 0 31,
                                                    BinOp (Sub, const 32 32,
                                                           UnOp (ZeroExt 32, lvpreg rB 0 4))),
                                             const0 32)),
                                const0 1, const1 1))
        ] )
    ] @ (cr_flags_stmts rc rA !Isa.mode)

  let decode_srawi _state isn =
    let sz = Isa.size * 2 in
    let tmpreg = Register.make (Register.fresh_name ()) sz in
    let rS, rA, sh, rc = decode_X_Form isn in
    [
      Set (vt tmpreg , UnOp(SignExt sz, lvtreg rS)) ;
      Set (vt tmpreg, BinOp (Shr, lvt tmpreg, const sh sz)) ;
      Set (vtreg rA, lvp tmpreg 0 (Isa.size-1)) ;
      Directive (Remove tmpreg) ;
      Set (vt ca, TernOp (BBinOp (LogOr,
                                  Cmp (EQ, lvpreg rS 31 31, const0 1),
                                  Cmp (EQ, BinOp (Shl, lvpreg rS 0 31, const (32-sh) 32), const0 32)),
                          const0 1, const1 1)) ;
    ] @ (cr_flags_stmts rc rA !Isa.mode)

  (* arithmetics *)

  let decode_add _state isn =
    let rD, rA, rB, oe, rc = decode_XO_Form isn in
    Set (vtreg rD, BinOp(Add, lvtreg rA, lvtreg rB)) :: ((xer_flags_stmts_add oe rA rB rD) @ (cr_flags_stmts rc rD !Isa.mode))

  let decode_sub _state isn =
    let rD, rA, rB, oe, rc = decode_XO_Form isn in
    Set (vtreg rD, BinOp(Sub, lvtreg rB, lvtreg rA)) :: ((xer_flags_stmts_sub oe rA rB rD) @ (cr_flags_stmts rc rD !Isa.mode))

  let decode_addis state isn =
    let rD, rA, simm, sz = decode_D_Form state.prefix isn in
    let simm' = sconst (simm lsl 16) (sz+16) Isa.size in
    match rA == 0 with
    | true -> [ Set (vtreg rD, simm') ]
    | false -> [ Set (vtreg rD, BinOp(Add, lvtreg rA, simm')) ]

  let decode_addi state isn =
    let rD, rA, simm, sz = decode_D_Form state.prefix isn in
    let simm' = sconst simm sz Isa.size in
    match rA == 0 with
    | true -> [ Set (vtreg rD, simm') ]
    | false -> [ Set (vtreg rD, BinOp(Add, lvtreg rA, simm')) ]

  let decode_addic state isn update_cr =
    let rD, rA, simm, sz  = decode_D_Form state.prefix isn in
    let u = Isa.size-1 in
    let tmpreg = Register.make (Register.fresh_name ()) (Isa.size+1) in
    [
      Set (vt tmpreg, BinOp(Add, ext_e (lvtreg rA), ext_e (sconst simm sz Isa.size))) ;
      Set (vpreg rD 0 u, lvp tmpreg 0 u) ;
      Set (vt ca, lvp tmpreg Isa.size Isa.size) ;
      Directive (Remove tmpreg) ;
    ] @ (cr_flags_stmts update_cr rD !Isa.mode)

  let decode_subfic state isn =
    let rD, rA, simm, sz = decode_D_Form state.prefix isn in
    let n1 = Isa.size+1 in
    let tmpreg = Register.make (Register.fresh_name ()) n1 in
    let simm32p1 = Z.add (sign_extension (Z.of_int simm) sz Isa.size) Z.one in 
    [
      Set (vt tmpreg, BinOp(Add, ext_e ((UnOp (Not, lvtreg rA))), zconst simm32p1 n1)) ;
      Set (vpreg rD 0 (Isa.size-1), lvp tmpreg 0 (Isa.size-1)) ;
      Set (vt ca, lvp tmpreg Isa.size Isa.size) ;
      Directive (Remove tmpreg) ;
    ]

  let add_with_carry_out expA expB rD =
    let tmpreg = Register.make (Register.fresh_name ()) (Isa.size+1) in
    let u = Isa.size-1 in
    [
      Set (vt tmpreg, BinOp(Add, expA, expB)) ;
      Set (vpreg rD 0 u, lvp tmpreg 0 u) ;
      Set (vt ca, TernOp (Cmp (EQ, lvp tmpreg Isa.size Isa.size, const1 1),
                          const1 1, const0 1)) ;
      Directive (Remove tmpreg) ;
    ]

              
  let decode_addc _state isn =
    let rD, rA, rB, oe, rc = decode_XO_Form isn in
    (add_with_carry_out (ext_e (lvtreg rA)) (ext_e (lvtreg rB)) rD)
    @ (xer_flags_stmts_add oe rA rB rD) 
    @ (cr_flags_stmts rc rD !Isa.mode)

  let decode_subfc _state isn =
    let rD, rA, rB, oe, rc = decode_XO_Form isn in
    (add_with_carry_out (BinOp(Add, ext_e (UnOp (Not, (lvtreg rA))), ext_e (lvtreg rB))) (const1 (Isa.size+1)) rD)
    @ (xer_flags_stmts_sub oe rA rB rD)
    @ (cr_flags_stmts rc rD !Isa.mode)

  let decode_adde _state isn =
    let rD, rA, rB, oe, rc = decode_XO_Form isn in
    (add_with_carry_out (BinOp(Add, ext_e (lvtreg rA), ext_e (lvtreg rB))) (ext_e (lvt ca)) rD)
    @ (xer_flags_stmts_add oe rA rB rD)
    @ (cr_flags_stmts rc rD !Isa.mode)

  let decode_subfe _state isn =
    let rD, rA, rB, oe, rc = decode_XO_Form isn in
    (add_with_carry_out (BinOp(Add, ext_e (UnOp (Not, (lvtreg rA))), ext_e (lvtreg rB))) (ext_e (lvt ca)) rD)
    @ (xer_flags_stmts_sub oe rA rB rD)
    @ (cr_flags_stmts rc rD !Isa.mode)

  let decode_subfme _state isn =
    let rD, rA, _, oe, rc = decode_XO_Form isn in
    let isn_stmts = (add_with_carry_out (BinOp(Add, ext_e (UnOp (Not, (lvtreg rA))), Isa.cff_e))
                       (ext_e (lvt ca)) rD) in
    let xer_stmts =
      if oe == 1 then [
          Set(vt ov, TernOp (BBinOp(LogAnd,
                                    Cmp (EQ, lvtreg rA, Isa.c7f),
                                    Cmp (EQ, lvtreg rD, Isa.c7f)),
                             const1 1, const0 1)) ;
          Set(vt so, BinOp (Or, lvt ov, lvt so)) ;
        ]
      else [] in
    isn_stmts @ xer_stmts @ (cr_flags_stmts rc rD !Isa.mode)

  let decode_addme _state isn =
    let rD, rA, _, oe, rc = decode_XO_Form isn in
    let isn_stmts = add_with_carry_out (ext_e (lvtreg rA)) (BinOp (Add, Isa.cff_e, ext_e (lvt ca))) rD in
    let xer_stmts =
      if oe == 1 then [
          Set(vt ov, TernOp (BBinOp(LogAnd,
                                    Cmp (EQ, lvtreg rA, Isa.c80),
                                    Cmp (EQ, lvtreg rD, Isa.c7f)),
                             const1 1, const0 1)) ;
          Set(vt so, BinOp (Or, lvt ov, lvt so)) ;
        ]
      else [] in
    isn_stmts @ xer_stmts @ (cr_flags_stmts rc rD !Isa.mode)

  let decode_subfze _state isn =
    let rD, rA, _, oe, rc = decode_XO_Form isn in
    let xer_stmts =
      if oe == 1 then [
          Set(vt ov, TernOp (BBinOp(LogAnd,
                                    Cmp (EQ, lvtreg rD, Isa.c80),
                                    Cmp (EQ, lvtreg rA, Isa.c80)),
                             const1 1, const0 1)) ;
          Set(vt so, BinOp (Or, lvt ov, lvt so)) ;
        ]
      else [] in
    (add_with_carry_out (ext_e (UnOp (Not, (lvtreg rA)))) (ext_e (lvt ca)) rD)
    @ xer_stmts
    @ (cr_flags_stmts rc rD !Isa.mode)

  let decode_addze _state isn =
    let rD, rA, _, oe, rc = decode_XO_Form isn in
    let xer_stmts =
      if oe == 1 then [
          Set(vt ov, TernOp (BBinOp(LogAnd,
                                    Cmp (EQ, lvtreg rD, Isa.c80),
                                    Cmp (EQ, lvtreg rA, Isa.c7f)),
                             const1 1, const0 1)) ;
          Set(vt so, BinOp (Or, lvt ov, lvt so)) ;
        ]
      else [] in
    (add_with_carry_out (ext_e (lvtreg rA)) (ext_e (lvt ca)) rD)
    @ xer_stmts
    @ (cr_flags_stmts rc rD !Isa.mode)

  let decode_neg _state isn =
    let rD, rA, _, oe, rc = decode_XO_Form isn in
    Set (vtreg rD, BinOp(Add, UnOp(Not, lvtreg rA), const1 Isa.size)) :: ((xer_flags_stmts_neg oe rA) @ (cr_flags_stmts rc rD !Isa.mode))

  let decode_extsb _state isn =
    let rS, rA, _, rc = decode_X_Form isn in
    Set (vtreg rA, UnOp(SignExt Isa.size, lvpreg rS 0 7)) :: (cr_flags_stmts rc rA !Isa.mode)

  let decode_extsh _state isn =
    let rS, rA, _, rc = decode_X_Form isn in
    Set (vtreg rA, UnOp(SignExt Isa.size, lvpreg rS 0 15)) :: (cr_flags_stmts rc rA !Isa.mode)

  let decode_divw _state isn =
    let rD, rA, rB, oe, rc = decode_XO_Form isn in
    let invalid_xer = if oe == 0 then []
                      else [ Set (vt ov, const1 1); Set (vt so, const1 1) ] in
    let invalid_cr = if rc == 0 then []
                     else [ Directive (Forget (vp cr 29 31)); Set (crbit 28, const1 1) ] in
    let undef_up =
      if Isa.size = 32 then []
      else [ Directive (Forget (vpreg rD 32 63)) ]
    in
    let cr_flags =
      if !Isa.mode = 32 then
        cr_flags_stmts rc rD 32
      else
        [ Directive (Forget (vp cr 29 31)); Set (crbit 28, const1 1) ]
    in
    let clear_ov oe = if oe == 1 then [ Set (vt ov, const0 1) ] else [] in
    [
      If (BBinOp(LogOr,
                 Cmp (EQ, lvpreg rB 0 31, const0 32),
                 BBinOp(LogAnd,
                        Cmp (EQ, lvpreg rA 0 31, const 0x80000000 32),
                        Cmp (EQ, lvpreg rB 0 31, const 0xffffffff 32))),
          Directive (Forget (vtreg rD)) :: (invalid_xer @ invalid_cr),
          Set (vpreg rD 0 31, BinOp(IDiv, lvpreg rA 0 31, lvpreg rB 0 31)) :: undef_up @
            ((clear_ov oe) @ cr_flags))
    ]

  let decode_divwu _state isn =
    let rD, rA, rB, oe, rc = decode_XO_Form isn in
    let invalid_xer = if oe == 0 then []
                      else [ Set (vt ov, const1 1); Set (vt so, const1 1) ] in
    let invalid_cr = if rc == 0 then []
                     else [ Directive (Forget (vp cr 29 31)); Set (crbit 28, const1 1) ] in
    let undef_up =
      if Isa.size = 32 then []
      else [ Directive (Forget (vpreg rD 32 63)) ]
    in
    let clear_ov oe = if oe == 1 then [ Set (vt ov, const0 1) ] else [] in
    [
      If (Cmp (EQ, lvpreg rB 0 31, const0 32),
          Directive (Forget (vtreg rD)) :: (invalid_xer @ invalid_cr),
          Set (vpreg rD 0 31, BinOp(Div, lvpreg rA 0 31, lvpreg rB 0 31)) :: undef_up @
            ((clear_ov oe) @ (cr_flags_stmts rc rD 32)))
    ]

  let decode_mulchw _state isn op =
    let rD, rA, rB, rc = decode_X_Form isn in
    Set (vtreg rD, BinOp(op, lvpreg rA 0 15, lvpreg rB 16 31)) :: (cr_flags_stmts rc rD !Isa.mode)

  let decode_mulhhw _state isn op =
    let rD, rA, rB, rc = decode_X_Form isn in
    Set (vtreg rD, BinOp(op, lvpreg rA 16 31, lvpreg rB 16 31)) :: (cr_flags_stmts rc rD !Isa.mode)

  let decode_mulhw _state isn op =
    let rD, rA, rB, rc = decode_X_Form isn in
    let tmpreg = Register.make (Register.fresh_name ()) 64 in
    let undef_up =
      if Isa.size = 32 then []
      else [ Directive (Forget (vpreg rD 32 63)) ]
    in
    let cr_flags =
      if !Isa.mode = 32 then
        cr_flags_stmts rc rD 32
      else
        [ Directive (Forget (vp cr 29 31)); Set (crbit 28, const1 1) ]
    in
    [ Set (vt tmpreg, BinOp(op, lvpreg rA 0 31, lvpreg rB 0 31)) ;
      Set (vtreg rD, lvp tmpreg 32 63) ;
      Directive (Remove tmpreg) ; ]
    @ cr_flags @ undef_up

  let decode_mullhw _state isn op =
    let rD, rA, rB, rc = decode_X_Form isn in
    Set (vtreg rD, BinOp(op, lvpreg rA 0 15, lvpreg rB 0 15)) :: (cr_flags_stmts rc rD !Isa.mode)

  let decode_mulli state isn =
    let rD, rA, simm, sz = decode_D_Form state.prefix isn in
    let tmpreg = Register.make (Register.fresh_name ()) (Isa.size*2) in
    [ Set (vt tmpreg, BinOp (IMul, lvtreg rA, sconst simm sz Isa.size)) ;
      Set (vtreg rD, lvp tmpreg 0 (Isa.size-1)) ;
      Directive (Remove tmpreg) ; ]

  let decode_mullw _state isn =
    let rD, rA, rB, oe, rc = decode_XO_Form isn in
    let tmpreg = Register.make (Register.fresh_name ()) 64 in
    let undef_up =
      if Isa.size = 32 then []
      else [ Directive (Forget (vpreg rD 32 63)) ]
    in
    let ov_stmt = if oe == 0 then []
                  else [ Set (vt ov, TernOp (Cmp (EQ, lvp tmpreg 32 63, const0 32),
                                             const0 1, const1 1)) ;
                         Set (vt so, BinOp (Or, lvt ov, lvt so)) ] in
    [ Set (vt tmpreg, BinOp (IMul, lvpreg rA 0 31, lvpreg rB 0 31)) ;
      Set (vpreg rD 0 31, lvp tmpreg 0 31) ; ]
    @ undef_up
    @ ov_stmt
    @ [ Directive (Remove tmpreg) ]
    @ (cr_flags_stmts rc rD !Isa.mode)

  (* Load and Store *)

  let decode_load_store_form prefix isn indexed update =
    if indexed then
      begin
        let rSD, rA, rB, _ = decode_X_Form isn in
        let ea = (if rA == 0 && not update then lvtreg rB
                  else BinOp (Add, lvtreg rA, lvtreg rB)) in
        (rSD, rA, ea)
      end
      else
        begin
          let rSD, rA, d, sz = decode_D_Form prefix isn in
          let signexp_d = sconst d sz Isa.size in
          let ea = (if rA == 0 && not update then signexp_d
                    else BinOp (Add, lvtreg rA, signexp_d)) in
          (rSD, rA, ea)
        end

  let decode_load state isn ?(reversed=false) ?(algebraic=false) ~indexed ~sz ~update () =
    let rD, rA, ea = decode_load_store_form state.prefix isn indexed update in
    let update_stmts = if update then [ Set (vtreg rA, ea) ] else [] in
    let extmode = if algebraic then SignExt Isa.size else ZeroExt Isa.size in
    let eap n = BinOp (Add, ea, const n Isa.size) in
    let memval =
      match reversed, sz with
      | false, sz when sz = Isa.size -> Lval (M (ea, sz))
      | false,  _ -> UnOp (extmode, Lval (M (ea, sz)))
      | true, 16 -> BinOp (Or,
                           UnOp (ZeroExt Isa.size, Lval (M (ea, 8))),
                           BinOp (Shl, UnOp(extmode, Lval (M (eap 1, 8))), const 8 Isa.size))
      | true, sz ->
         let e = BinOp (Or,
                        BinOp (Or,
                               UnOp(ZeroExt sz, Lval (M (ea, 8))),
                               BinOp(Shl, UnOp(ZeroExt sz, Lval (M (eap 1, 8))), const 8 sz)),
                        BinOp (Or,
                               BinOp(Shl, UnOp(ZeroExt sz, Lval (M (eap 2, 8))), const 16 sz),
                               BinOp(Shl, UnOp(ZeroExt sz, Lval (M (eap 3, 8))), const 24 sz)))
         in
         if sz = Isa.size then e else UnOp(ZeroExt Isa.size, e)
    in
    Set (vtreg rD, memval) :: update_stmts


  let decode_store state isn ?(reversed=false) ~indexed ~sz ~update () =
    let rS, rA, ea = decode_load_store_form state.prefix isn indexed update in
    let update_stmts = if update then [ Set (vtreg rA, ea) ] else [] in
    let regval = match reversed, sz with
      | false, 32 -> lvtreg rS
      | false,  _ -> lvpreg rS 0 (sz-1)
      | true, 16 -> BinOp (Or,
                           UnOp (ZeroExt 16, lvpreg rS 8 15),
                           BinOp (Shl, UnOp(ZeroExt 16, lvpreg rS 0 7), const 8 16))
      | true, 32 -> BinOp (Or,
                           BinOp (Or,
                                  UnOp (ZeroExt 32, lvpreg rS 24 31),
                                  BinOp (Shl, UnOp (ZeroExt 32, lvpreg rS 16 23), const 8 32)),
                           BinOp (Or,
                                  BinOp (Shl, UnOp (ZeroExt 32, lvpreg rS 8 15), const 16 32),
                                  BinOp (Shl, UnOp (ZeroExt 32, lvpreg rS 0 7), const 24 32)))
      | _ -> L.abort (fun p -> p "internal error: unexpected decoding combination: reversed=%b sz=%i"
                                 reversed sz) in
    Set (M (ea, sz), regval) :: update_stmts

    let decode_lmw state isn =
      let rD, rA, d, sz = decode_D_Form state.prefix isn in
      let sd = sign_extension (Z.of_int d) sz 32 in 
      let rec loadreg ea n =
        if n == 32 then []
        else
          let tail = loadreg (Z.add ea z4) (n+1) in
          let ff = Z.sub (Z.shift_left (Z.one) 32) Z.one in
          let ea' = Z.logand ea ff in
          if n != rA || n == 31 then
            let e = Lval (M (BinOp(Add, lvpreg rA 0 31,
                                   zconst ea' 32), 32))
            in
            let e' = if !Isa.mode = 32 then e else UnOp(ZeroExt Isa.size, e) in
            Set (vtreg n, e') :: tail
          else
            tail in
      loadreg sd rD

    let decode_stmw state isn =
      (* TODO: factorize with decode_lmw *)
      let rS, rA, d, sz = decode_D_Form state.prefix isn in
      let sd = sign_extension (Z.of_int d) sz 32  in 
      let rec storereg ea n =
        if n == 32 then []
        else
          let tail = storereg (Z.add ea z4) (n+1) in
          let ff = Z.sub (Z.shift_left (Z.one) 32) Z.one in
          let ea' = Z.logand ea ff in
          if n != rA || n == 31 then
            Set (M (BinOp(Add, lvpreg rA 0 31, zconst ea' 32), 32),
                 lvpreg n 0 31) :: tail
          else
            tail in
      storereg sd rS

    let decode_lswi _state isn =
      let rD, rA, nb, _ = decode_X_Form isn in
      let ea x = if rA == 0 then const x 32 else BinOp(Add, lvpreg rA 0 31, const x 32) in
      let nb' = if nb == 0 then 32 else nb in
      let loadreg = ref [] in
      for n = 0 to nb'-1 do
        let reg = (rD+(n/4)) mod 32 in
        let pos = 24-8*(n mod 4) in
        loadreg := Set (vpreg reg pos (pos+7), Lval (M (ea n, 8))) :: !loadreg
      done;
      if (nb' mod 4) != 0 then
        begin
          let pos = 31-8*(nb' mod 4) in
          let reg = (rD+(nb'/4)) mod 32 in
          loadreg := Set (vpreg reg 0 pos, const0 (pos+1)) :: !loadreg
        end;
      List.rev !loadreg

    let decode_stswi _state isn =
      let rD, rA, nb, _ = decode_X_Form isn in
      let ea x = if rA == 0 then const x 32 else BinOp(Add, lvpreg rA 0 31, const x 32) in
      let nb' = if nb == 0 then 32 else nb in
      let storereg = ref [] in
      for n = 0 to nb'-1 do
        let reg = (rD+(n/4)) mod 32 in
        let pos = 24-8*(n mod 4) in
        storereg := Set (M (ea n, 8), lvpreg reg pos (pos+7)) :: !storereg
      done;
      List.rev !storereg


  (* CR operations *)

  let decode_mtcrf _state isn =
    let rS, crm1 = decode_XFX_Form isn in
    let crm = (crm1 lsr 1) land 0xff in
    if crm == 0xff then (* shortcut for special case when all CR fields are set with rS *)
      [ Set (vt cr, lvpreg rS 0 31) ]
    else
      let stmts = ref [] in
      for i = 0 to 7 do
        if (crm lsr i) land 1 == 1 then
          stmts := Set (vp cr (i*4) (i*4+3), lvpreg rS (i*4) (i*4+3)) :: !stmts
      done;
      !stmts

  let decode_mfcr _state isn =
    let rD, _, _, _ = decode_X_Form isn in
    [ Set (vtreg rD, lvt cr) ]

  let decode_cr_op _state isn op =
    let crD, crA, crB, _ = decode_XL_Form isn in
    [ Set (crbit (31-crD), BinOp (op, Lval (crbit (31-crA)), Lval (crbit (31-crB)))) ]

  let decode_cr_op_complement _state isn op =
    let crD, crA, crB, _ = decode_XL_Form isn in
    [ Set (crbit (31-crD), BinOp (op, Lval (crbit (31-crA)), UnOp(Not, Lval (crbit (31-crB))))) ]

  let decode_cr_op_not _state isn op =
    let crD, crA, crB, _ = decode_XL_Form isn in
    [ Set (crbit (31-crD), UnOp(Not, BinOp (op, Lval (crbit (31-crA)), Lval (crbit (31-crB))))) ]

  let decode_mcrf _state isn =
    let crfD, crfS, _, _ = decode_XL_Form isn in
    if crfD = crfS then []
    else [ Set (vp cr (28-crfD) (31-crfD), lvp cr (28-crfS) (31-crfS)) ]

  let core_std isn update =
    let rs, ra, ds = decode_DS_Form isn in
    let ea = BinOp(Add, lvtreg ra, UnOp(SignExt 64, const (ds lsl 2) 16)) in
    (Set (M(ea, 64), lvtreg rs))::
      (if update then [Set (vtreg ra, ea)]
      else [])
  let decode_std _state isn = core_std isn false

  let decode_stdu _state isn = core_std isn true

                             
  let decode_ld _state isn update =
    let rs, ra, ds = decode_DS_Form isn in
    let ea = BinOp(Add, lvtreg ra, UnOp(SignExt 64, const (ds lsl 2) 16)) in
    (Set (vtreg rs, Lval (M(ea, 64))))::
      (if update then [Set (vtreg ra, ea)]
       else [])
    
    
  (* Decoding and switching *)

  let return (s: state) (stmts: Asm.stmt list): Cfa.State.t * Data.Address.t =
    let bytes =
      List.map (fun isn  ->
          [ Char.chr (isn land 0xff) ;
            Char.chr ((isn lsr 8) land 0xff) ;
            Char.chr ((isn lsr 16) land 0xff) ;
            Char.chr ((isn lsr 24) land 0xff) ]) (List.rev s.isn)
    in
    s.b.Cfa.State.stmts <- stmts;
    s.b.Cfa.State.bytes <- List.fold_left (fun l isn -> l @ isn) [] bytes;
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

  let decode_000100 s isn =
    match (isn lsr 1) land 0x1ff with
   | 0b000001000 -> decode_mulhhw s isn Mul (* mulhhwu *)
   | 0b000001100 -> not_implemented s isn "machhwu"
   | 0b000101000 -> decode_mulhhw s isn IMul (* mulhhw *)
   | 0b000101100 -> not_implemented s isn "machhw"
   | 0b000101110 -> not_implemented s isn "nmachhw"
   | 0b001001100 -> not_implemented s isn "machhwsu"
   | 0b001101100 -> not_implemented s isn "machhws"
   | 0b001101110 -> not_implemented s isn "nmachhws"
   | 0b010001000 -> decode_mulchw s isn Mul (* mulchwu *)
   | 0b010001100 -> not_implemented s isn "macchwu"
   | 0b010101000 -> decode_mulchw s isn IMul (* mulchw *)
   | 0b010101100 -> not_implemented s isn "macchw"
   | 0b010101110 -> not_implemented s isn "nmacchw"
   | 0b011001100 -> not_implemented s isn "macchwsu"
   | 0b011101100 -> not_implemented s isn "macchws"
   | 0b011101110 -> not_implemented s isn "nmacchws"
   | 0b110001000 -> decode_mullhw s isn Mul (* mullhwu *)
   | 0b110001100 -> not_implemented s isn "maclhwu"
   | 0b110101000 -> decode_mullhw s isn IMul (* mullhw *)
   | 0b110101100 -> not_implemented s isn "maclhw"
   | 0b110101110 -> not_implemented s isn "nmaclhw"
   | 0b111001100 -> not_implemented s isn "maclhwsu"
   | 0b111101100 -> not_implemented s isn "maclhws"
   | 0b111101110 -> not_implemented s isn "nmaclhws"
   | _ -> error s.a (Printf.sprintf "decode_000100: unknown opcode 0x%x" isn)


  let decode_010011 s isn =
    match (isn lsr 1) land 0x3ff with
    | 0b0000000000-> decode_mcrf s isn
    | 0b0000010000-> decode_conditional_lr_XL_form s isn (* bclr *)
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
    | 0b1000010000-> decode_conditional_ctr_XL_form s isn (* bcctr  *)
    | _ -> error s.a (Printf.sprintf "decode_010011: unknown opcode 0x%x" isn)

  let decode_011110 s isn =
    match (isn lsr 1) land 0xf with
    | 0b0000 | 0b0001 -> not_implemented_64bits s isn "rldicl??"
    | 0b0010 | 0b0011 -> not_implemented_64bits s isn "rldicr??"
    | 0b0100 | 0b0101 -> not_implemented_64bits s isn "rldic??"
    | 0b0110 | 0b0111 -> not_implemented_64bits s isn "rldimi??"
    | 0b1000 -> not_implemented_64bits s isn "rldcl??"
    | 0b1001 -> not_implemented_64bits s isn "rldcr??"
    | _ -> error s.a (Printf.sprintf "decode_011110: unknown opcode 0x%x" isn)

  let decode_011111 s isn =
    match (isn lsr 1) land 0x3ff with
    | 0b0000000000 -> decode_cmp s isn
    | 0b0000000100 -> not_implemented s isn "tw"
    | 0b0000001000 | 0b1000001000 -> decode_subfc s isn
    | 0b0000001001 -> not_implemented_64bits s isn "mulhdu??"
    | 0b0000001010 | 0b1000001010 -> decode_addc s isn
    | 0b0000001011 -> decode_mulhw s isn Mul (* mulhwu *)
    | 0b0000010011 -> decode_mfcr s isn
    | 0b0000010100 -> not_implemented s isn "lwarx"
    | 0b0000010101 -> not_implemented_64bits s isn "ld??"
    | 0b0000010111 -> decode_load s isn ~sz:32 ~update:false ~indexed:true ()  (* lwzx *)
    | 0b0000011000 -> decode_logic_shift s isn Shl (* slw *)
    | 0b0000011010 -> decode_cntlzw s isn
    | 0b0000011011 -> not_implemented_64bits s isn "sld??"
    | 0b0000011100 -> decode_logic s isn And (* and *)
    | 0b0000100000 -> decode_cmpl s isn
    | 0b0000101000 | 0b1000101000 -> decode_sub s isn
    | 0b0000110101 -> not_implemented_64bits s isn "ldux"
    | 0b0000110110 -> do_nothing s isn "dcbst"
    | 0b0000110111 -> decode_load s isn ~sz:32 ~update:true ~indexed:true ()  (* lwzux *)
    | 0b0000111010 -> not_implemented_64bits s isn "cntlzd??"
    | 0b0000111100 -> decode_logic_complement s isn And (* andc *)
    | 0b0001000100 -> not_implemented_64bits s isn "td"
    | 0b0001001001 -> not_implemented_64bits s isn "mulhd??"
    | 0b0001001011 -> decode_mulhw s isn IMul (* mulhw *)
    | 0b0001010011 -> not_implemented s isn "mfmsr"
    | 0b0001010100 -> not_implemented_64bits s isn "ldarx"
    | 0b0001010110 -> do_nothing s isn "dcbf"
    | 0b0001010111 -> decode_load s isn ~sz:8 ~update:false ~indexed:true ()  (* lbzx *)
    | 0b0001101000 | 0b1001101000 -> decode_neg s isn
    | 0b0001110111 -> decode_load s isn ~sz:8 ~update:true  ~indexed:true ()  (* lbzux  *)
    | 0b0001111100 -> decode_logic_not s isn Or (* nor?? *)
    | 0b0010001000 | 0b1010001000 -> decode_subfe s isn
    | 0b0010001010 | 0b1010001010 -> decode_adde s isn
    | 0b0010010000 -> decode_mtcrf s isn
    | 0b0010010010 -> not_implemented s isn "mtmsr"
    | 0b0010010101 -> not_implemented_64bits s isn "stdx"
    | 0b0010010110 -> not_implemented s isn "stwcx."
    | 0b0010010111 -> decode_store s isn ~sz:32 ~update:false ~indexed:true () (* stwx *)
    | 0b0010110101 -> not_implemented_64bits s isn "stdux"
    | 0b0010110111 -> decode_store s isn ~sz:32 ~update:true ~indexed:true () (* stwux *)
    | 0b0011001000 | 0b1011001000 -> decode_subfze s isn
    | 0b0011001010 | 0b1011001010 -> decode_addze s isn
    | 0b0011010010 -> not_implemented s isn "mtsr"
    | 0b0011010110 -> not_implemented_64bits s isn "stdcx."
    | 0b0011010111 -> decode_store s isn ~sz:8 ~update:false ~indexed:true () (* stbx *)
    | 0b0011101000 | 0b1011101000 -> decode_subfme s isn
    | 0b0011101001 | 0b1011101001 -> not_implemented_64bits s isn "mulld"
    | 0b0011101010 | 0b1011101010 -> decode_addme s isn
    | 0b0011101011 | 0b1011101011 -> decode_mullw s isn
    | 0b0011110010 -> not_implemented s isn "mtsrin"
    | 0b0011110110 -> do_nothing s isn "dcbtst"
    | 0b0011110111 -> decode_store s isn ~sz:8 ~update:true ~indexed:true () (* stbux *)
    | 0b0100001010 | 0b1100001010 ->  decode_add s isn
    | 0b0100010110 -> do_nothing s isn "dcbt"
    | 0b0100010111 -> decode_load s isn ~sz:16 ~update:false ~indexed:true ()  (* lhzx *)
    | 0b0100011100 -> decode_logic_complement s isn Xor (* "eqv??" *)
    | 0b0100110010 -> not_implemented s isn "tlbie"
    | 0b0100110110 -> not_implemented s isn "eciwx"
    | 0b0100110111 -> decode_load s isn ~sz:16 ~update:true ~indexed:true ()  (* lhzux *)
    | 0b0100111100 -> decode_logic s isn Xor (* xor *)
    | 0b0101010011 -> decode_mfspr s isn
    | 0b0101010101 -> not_implemented_64bits s isn "lwax"
    | 0b0101010111 -> decode_load s isn ~sz:16 ~update:false ~indexed:true ~algebraic:true ()  (* lhax *)
    | 0b0101110010 -> not_implemented s isn "tlbia"
    | 0b0101110011 -> not_implemented s isn "mftb"
    | 0b0101110101 -> not_implemented_64bits s isn "lwaux"
    | 0b0101110111 -> decode_load  s isn ~sz:16 ~update:true  ~indexed:true ~algebraic:true ()  (* lhaux *)
    | 0b0110010111 -> decode_store s isn ~sz:16 ~update:false ~indexed:true                 ()  (* sthx *)
    | 0b0110011100 -> decode_logic_complement s isn Or (* orc *)
    | 0b1100111010 | 0b1100111011 -> not_implemented_64bits s isn "sradi??"
    | 0b0110110010 -> not_implemented_64bits s isn "slbie"
    | 0b0110110110 -> not_implemented s isn "ecowx"
    | 0b0110110111 -> decode_store s isn ~sz:16 ~update:true ~indexed:true () (* sthux *)
    | 0b0110111100 -> decode_logic s isn Or (* or *)
    | 0b0111001001 | 0b1111001001 -> not_implemented_64bits s isn "divdu??"
    | 0b0111001011 | 0b1111001011 -> decode_divwu s isn
    | 0b0111010011 -> decode_mtspr s isn
    | 0b0111010110 -> do_nothing s isn "dcbi"
    | 0b0111011100 -> decode_logic_not s isn And (* nand?? *)
    | 0b0111101001 | 0b1111101001 -> not_implemented_64bits s isn "divd??"
    | 0b0111101011 | 0b1111101011 -> decode_divw s isn
    | 0b0111110010 -> not_implemented_64bits s isn "slbia"
    | 0b1000000000 -> not_implemented s isn "mcrxr"
    | 0b1000010101 -> not_implemented s isn "lswx"
    | 0b1000010110 -> decode_load s isn ~sz:32 ~update:false ~indexed:true ~reversed:true ()  (* lwbrx *)
    | 0b1000010111 -> not_implemented s isn "lfsx"
    | 0b1000011000 -> decode_logic_shift s isn Shr (* srw *)
    | 0b1000011011 -> not_implemented_64bits s isn "srd??"
    | 0b1000110110 -> not_implemented s isn "tlbsync"
    | 0b1000110111 -> not_implemented s isn "lfsu??"
    | 0b1001010011 -> not_implemented s isn "mfsr"
    | 0b1001010101 -> decode_lswi s isn
    | 0b1001010110 -> not_implemented s isn "sync"
    | 0b1001010111 -> not_implemented s isn "lfdx"
    | 0b1001110111 -> not_implemented s isn "lfdux"
    | 0b1010010011 -> not_implemented s isn "mfsrin"
    | 0b1010010101 -> not_implemented s isn "stswx"
    | 0b1010010110 -> decode_store s isn ~sz:32 ~update:false ~indexed:true ~reversed:true () (* stwbrx *)
    | 0b1010010111 -> not_implemented s isn "stfsx"
    | 0b1010110111 -> not_implemented s isn "stfsux"
    | 0b1011010101 -> decode_stswi s isn
    | 0b1011010111 -> not_implemented s isn "stfdx"
    | 0b1011110111 -> not_implemented s isn "stfdux"
    | 0b1100010110 -> decode_load s isn ~sz:16 ~update:false ~indexed:true ~reversed:true ()  (* lhbrx *)
    | 0b1100011000 -> decode_sraw s isn
    | 0b1100011010 -> not_implemented_64bits s isn "srad??"
    | 0b1100111000 -> decode_srawi s isn
    | 0b1101010110 -> not_implemented s isn "eieio"
    | 0b1110010110 -> decode_store s isn ~sz:16 ~update:false ~indexed:true ~reversed:true () (* sthbrx *)
    | 0b1110011010 -> decode_extsh s isn
    | 0b1110111010 -> decode_extsb s isn
    | 0b1111010110 -> not_implemented s isn "icbi"
    | 0b1111010111 -> not_implemented s isn "stfiwx"
    | 0b1111011010 -> not_implemented_64bits s isn "extsw"
    | 0b1111110110 -> do_nothing s isn "dcbz"
    | _ -> error s.a (Printf.sprintf "decode_011111: unknown opcode 0x%x" isn)

  let decode_111010 s isn =
    match isn land 0x3 with
    | 0b00 ->
       if Isa.size = 64 then decode_ld s isn false
       else not_implemented_64bits s isn "ld"
      
    | 0b01 ->
       if Isa.size = 64 then decode_ld s isn true
       else not_implemented_64bits s isn "ldu"
      
    | 0b10 -> not_implemented_64bits s isn "lwa"
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
    | 0b00 ->
       if Isa.size = 64 then decode_std s isn
       else not_implemented_64bits s isn "std"
              
    | 0b01 ->
       if Isa.size = 64 then decode_stdu s isn
       else not_implemented_64bits s isn "stdu"
      
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
       | 0b1100101110 -> not_implemented_64bits s isn "fctid??"
       | 0b1100101111 -> not_implemented_64bits s isn "fctidz??"
       | 0b1101001110 -> not_implemented_64bits s isn "fcfid??"
       | _ -> error s.a (Printf.sprintf "decode_11111: unknown opcode 0x%x" isn)


    
  let rec core_decode s off =
    let str = String.sub s.buf off (off+4) in
    let isn  = build_instruction s str in
    s.isn <- isn::s.isn;
      match (isn lsr 26) land 0x3f with
      | 0x60 -> []
(*      | 0b000000 ->  *)
      | 0b000001 -> decode_prefix s isn
      | 0b000010 -> not_implemented_64bits s isn "tdi"
      | 0b000011 -> not_implemented s isn "twi"
      | 0b000100 -> decode_000100 s isn  (* mulchw mulhhw mulhw mullw ... *)
(*      | 0b000101 -> *)
(*      | 0b000110 -> *)
      | 0b000111 -> decode_mulli s isn
      | 0b001000 -> decode_subfic s isn
(*      | 0b001001 ->  *)
      | 0b001010 -> decode_cmpli s isn
      | 0b001011 -> decode_cmpi s isn
      | 0b001100 -> decode_addic s isn 0 (* addic  *)
      | 0b001101 -> decode_addic s isn 1 (* addic. *)
      | 0b001110 -> decode_addi s isn
      | 0b001111 -> decode_addis s isn
      | 0b010000 -> decode_branch_conditional_B_form s isn (* bc bca bcl bcla *)
      | 0b010001 -> not_implemented s isn "sc"
      | 0b010010 -> decode_branch_I_form s isn
       | 0b010011 -> decode_010011 s isn (* mcrf bclr?? crnor rfi crandc isync crxor crnand crand creqv crorc cror bcctr?? *)
      | 0b010100 -> decode_rlwimi s isn
      | 0b010101 -> decode_rlwinm s isn
(*      | 0b010110 ->  *)
      | 0b010111 -> decode_rlwnm s isn
      | 0b011000 -> decode_logic_imm s isn Or              (* ori    *)
      | 0b011001 -> decode_logic_imm_shifted s isn Or      (* oris   *)
      | 0b011010 -> decode_logic_imm s isn Xor             (* xor    *)
      | 0b011011 -> decode_logic_imm_shifted s isn Xor     (* xori   *)
      | 0b011100 -> decode_logic_imm_dot s isn And         (* andi.  *)
      | 0b011101 -> decode_logic_imm_shifted_dot s isn And (* andis. *)
      | 0b011110 -> decode_011110 s isn (* rldicl?? rldicr?? rldic?? rldimi?? rldcl?? rldcr??*)
      | 0b011111 -> decode_011111 s isn (* cmp rw subfc?? mulhdu?? addc?? mulhwu?? mfcr lwarx ldx lwzx slw?? cntlzw?? sld?? and?? cmpl subf?? ldux dcbst lwzux cntlzd??.... *)
      | 0b100000 -> decode_load s isn  ~sz:32 ~update:false ~indexed:false                 ()  (* lwz   *)
      | 0b100001 -> decode_load s isn  ~sz:32 ~update:true  ~indexed:false                 ()  (* lwzu  *)
      | 0b100010 -> decode_load s isn  ~sz:8  ~update:false ~indexed:false                 ()  (* lbz   *)
      | 0b100011 -> decode_load s isn  ~sz:8  ~update:true  ~indexed:false                 ()  (* lbzu  *)
      | 0b100100 -> decode_store s isn ~sz:32 ~update:false ~indexed:false                 ()  (* stw   *)
      | 0b100101 -> decode_store s isn ~sz:32 ~update:true  ~indexed:false                 ()  (* stwu  *)
      | 0b100110 -> decode_store s isn ~sz:8  ~update:false ~indexed:false                 ()  (* stb   *)
      | 0b100111 -> decode_store s isn ~sz:8  ~update:true  ~indexed:false                 ()  (* stbu  *)
      | 0b101000 -> decode_load s isn  ~sz:16 ~update:false ~indexed:false                 ()  (* lhz   *)
      | 0b101001 -> decode_load s isn  ~sz:16 ~update:true  ~indexed:false                 ()  (* lhzu  *)
      | 0b101010 -> decode_load s isn  ~sz:16 ~update:false ~indexed:false ~algebraic:true ()  (* lha   *)
      | 0b101011 -> decode_load s isn  ~sz:16 ~update:true  ~indexed:false ~algebraic:true ()  (* lhau  *)
      | 0b101100 -> decode_store s isn ~sz:16 ~update:false ~indexed:false                 ()  (* sth   *)
      | 0b101101 -> decode_store s isn ~sz:16 ~update:true  ~indexed:false                 ()  (* sthu  *)
      | 0b101110 -> decode_lmw s isn
      | 0b101111 -> decode_stmw s isn
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

      | _ -> error s.a (Printf.sprintf "Unknown opcode 0x%x" isn)

  and decode_prefix s isn =
    (* ref manual: 1.6.3 *)
    let typ = (isn lsr 24) land 0x3 in
    match typ with
    | 0b00 (* eight-byte load/store ins *) ->
       let st = (isn lsr 23) land 0x1 in
       if st = 0 then
         (* signed 8LS *)
         let r = (isn lsr 20) land 0x01 in
         let ie = (isn lsr 17) land 0x3ffff in
         s.prefix <- Some (LoadStore {r = r; ie = ie;});
         s.a <- Data.Address.add_offset s.a z4;
         core_decode s 4
       else
         (* reserved *) 
         L.abort (fun p -> p "decoder stops because of reserved value for bit ST in prefix")
    | 0b01 ->
    (* eight-byte register-to-register ins *)
       L.abort (fun p -> p "eight-byte register-to-register instruction not decoded yet")
    | 0b10 -> 
    (* modified load/store ins *)
       L.abort (fun p -> p "modified load/store instruction not decoded yet")
    | _ -> (* modified register-to-register ins *)
       L.abort (fun p -> p "modified register-to-register instruction not decoded yet")

  let decode s =
    let stmts = core_decode s 0 in
    return s stmts
    
  let parse text cfg _ctx state addr _oracle =

    let s =  {
      g = cfg;
      b = state;
      a = addr;
      buf = text;
      endianness = !Config.endianness;
      isn = [];
      prefix = None;
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
    
  let init_registers () = []
end
