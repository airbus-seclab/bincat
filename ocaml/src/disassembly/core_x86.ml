(*
    This file is part of BinCAT.
    Copyright 2014-2018 - Airbus

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

(***************************************************************************************)
(* core functionalities of the x86 decoders *)
(***************************************************************************************)

module Lcore = Log.Make(struct let name = "core_x86" end)
open Asm
open Data        
open Decodeutils
   
(*************************************************************************)
(* Creation of the general flag registers *)
(*************************************************************************)
let fcf    = Register.make ~name:"cf" ~size:1;;
let fpf    = Register.make ~name:"pf" ~size:1;;
let faf    = Register.make ~name:"af" ~size:1;;
let fzf    = Register.make ~name:"zf" ~size:1;;
let fsf    = Register.make ~name:"sf" ~size:1;;
let _ftf   = Register.make ~name:"tf" ~size:1;;
let fif    = Register.make ~name:"if" ~size:1;;
let fdf    = Register.make ~name:"df" ~size:1;;
let fof    = Register.make ~name:"of" ~size:1;;
let _fiopl = Register.make ~name:"iopl" ~size:2;;
let _fnt   = Register.make ~name:"nt" ~size:1;;
let _frf   = Register.make ~name:"rf" ~size:1;;
let _fvm   = Register.make ~name:"vm" ~size:1;;
let _fac   = Register.make ~name:"ac" ~size:1;;
let _fvif  = Register.make ~name:"vif" ~size:1;;
let _fvip  = Register.make ~name:"vip" ~size:1;;
let _fid   = Register.make ~name:"id" ~size:1;;



  (***********************************************************************)
  (* Creation of the segment registers *)
  (***********************************************************************)
  let cs = Register.make ~name:"cs" ~size:16;;
  let ds = Register.make ~name:"ds" ~size:16;;
  let ss = Register.make ~name:"ss" ~size:16;;
  let es = Register.make ~name:"es" ~size:16;;
  let fs = Register.make ~name:"fs" ~size:16;;
  let gs = Register.make ~name:"gs" ~size:16;;


  

  (***********************************************************************)
  (* Creation of the flags for the mxcsr register *)
  (***********************************************************************)
  let mxcsr_fz = Register.make ~name:"mxcsr_fz" ~size:1;; (* bit 15: Flush to zero  *)
  let mxcsr_round = Register.make ~name:"mxcsr_round" ~size:2;; (* bit 13 and 14: rounding mode st:
                                                                   - bit 14:  round positive
                                                                   - bit 13 : round negative
                                                                   - bit 13 and 14 : round to zero or round to the nearest *)
  let mxcsr_pm = Register.make ~name:"mxcsr_pm" ~size:1;; (* bit 12: Precision mask *)
  let mxcsr_um = Register.make ~name:"mxcsr_um" ~size:1;; (* bit 11: Underflow mask *)
  let mxcsr_om = Register.make ~name:"mxcsr_om" ~size:1;; (* bit 10: Overflow mask *)
  let mxcsr_zm = Register.make ~name:"mxcsr_zm" ~size:1;; (* bit 9: Divide by zero mask *)
  let mxcsr_dm = Register.make ~name:"mxcsr_dm" ~size:1;; (* bit 8: Denormal mask *)
  let mxcsr_im = Register.make ~name:"mxcsr_im" ~size:1;; (* bit 7: Invalid operation mask *)
  let mxcsr_daz = Register.make ~name:"mxcsr_daz" ~size:1;; (* bit 6: Denormals are zero *)
  let mxcsr_pe = Register.make ~name:"mxcsr_pe" ~size:1;; (* bit 5: Precision flag *)
  let mxcsr_ue = Register.make ~name:"mxcsr_ue" ~size:1;; (* bit 4: Underflow flag *)
  let mxcsr_oe = Register.make ~name:"mxcsr_oe" ~size:1;; (* bit 3: Overflow flag *)
  let mxcsr_ze = Register.make ~name:"mxcsr_ze" ~size:1;; (* bit 2: Divide by zero flag *)
  let mxcsr_de = Register.make ~name:"mxcsr_de" ~size:1;; (* bit 1: Denormal flag *)
  let mxcsr_ie = Register.make ~name:"mxcsr_ie" ~size:1;; (* bit 0: Invalid operation flag *)

  
  (* xmm registers *)
  let xmm0 = Register.make ~name:"xmm0" ~size:128;;
  let xmm1 = Register.make ~name:"xmm1" ~size:128;;
  let xmm2 = Register.make ~name:"xmm2" ~size:128;;
  let xmm3 = Register.make ~name:"xmm3" ~size:128;;
  let xmm4 = Register.make ~name:"xmm4" ~size:128;;
  let xmm5 = Register.make ~name:"xmm5" ~size:128;;
  let xmm6 = Register.make ~name:"xmm6" ~size:128;;
  let xmm7 = Register.make ~name:"xmm7" ~size:128;;

  let xmm_tbl = Hashtbl.create 7;;
  List.iteri (fun i r -> Hashtbl.add xmm_tbl i r) [ xmm0 ; xmm1 ; xmm2 ; xmm3 ; xmm4 ; xmm5 ; xmm6 ; xmm7 ];;

  (* floating point unit *)
  let st_ptr = Register.make ~name:"st_ptr" ~size:3;;

  let c0 = Register.make ~name:"C0" ~size:1;;
  let c1 = Register.make ~name:"C1" ~size:1;;
  let c2 = Register.make ~name:"C2" ~size:1;;
  let c3 = Register.make ~name:"C3" ~size:1;;



    (***********************************************************************)
    (* Internal state of the decoder *)
    (***********************************************************************)

    (** GDT and LDT management *)
    type privilege_level =
      | R0
      | R1
      | R2
      | R3

    let privilege_level_of_int i =
        match i with
        | 0 -> R0
        | 1 -> R1
        | 2 -> R2
        | 3 -> R3
        | _ -> failwith "Undefined value"

    type table_indicator =
      | GDT
      | LDT

    (* size of an index in a description table *)
    let index_sz = 64

    (** high level data structure of the content of a segment register *)
    type segment_register_mask = { rpl: privilege_level; ti: table_indicator; index: Word.t }

    (** builds the high level representation of the given segment register *)
    let get_segment_register_mask v =
        let rpl = privilege_level_of_int (Z.to_int (Z.logand v (Z.of_int 3))) in
        let ti =
            match Z.to_int (Z.logand (Z.shift_right v 2) Z.one) with
            | 0 -> GDT
            | 1 -> LDT
            | _ -> Lcore.abort (fun p -> p "Invalid decription table selection")
        in
        { rpl = rpl; ti = ti; index = Word.of_int (Z.shift_right v 3) index_sz }

    (** abstract data type of a segment type *)
    type segment_descriptor_type =
      (* From Vol 3-17, Table 3.1 *)
      (* Stack segments are data segments which must be read/write segments *)
      (* loading the SS register with a segment selector for a nonwritable data segment generates a general-protection exception (#GP) *)
      | Data_r   (* 0000 Data read only *)
      | Data_ra   (* 0001 Data read only, accessed *)
      | Data_rw   (* 0010 Data read/write *)
      | Data_rwa  (* 0011 Data read/write, accessed *)
      | Data_re   (* 0100 Data read only, expand-down *)
      | Data_rea  (* 0101 Data read only, expand-dwon, accessed *)
      | Data_rwe  (* 0110 Data read/write, expand-down *)
      | Data_rwea  (* 0111 Data read/write, expand-down, accessed *)

      | Code_e    (* 1000 Code execute-only *)
      | Code_ea   (* 1001 Code execute-only, accessed *)
      | Code_er   (* 1010 Code execute/read *)
      | Code_era  (* 1011 Code execute/read, accessed *)
      | Code_ec   (* 1100 Code execute-only, conforming *)
      | Code_eca  (* 1101 Code execute-only, conforming, accessed *)
      | Code_erc  (* 1110 Code execute/read, conforming *)
      | Code_erca (* 1111 Code execute/read, conforming, accessed *)
      | UndefSegment

    (** converts the given integer into a segment type *)
    let segment_descriptor_of_int v =
        match v with
        | 0  -> Data_r   (* 0000 Data read only *)
        | 1  -> Data_ra   (* 0001 Data read only, accessed *)
        | 2  -> Data_rw   (* 0010 Data read/write *)
        | 3  -> Data_rwa  (* 0011 Data read/write, accessed *)
        | 4  -> Data_re   (* 0100 Data read only, expand-down *)
        | 5  -> Data_rea  (* 0101 Data read only, expand-dwon, accessed *)
        | 6  -> Data_rwe  (* 0111 Data read/write, expand-down *)
        | 7  -> Data_rwea  (* 0111 Data read/write, expand-down, accessed *)
        | 8  -> Code_e    (* 1000 Code execute-only *)
        | 9  -> Code_ea   (* 1001 Code execute-only, accessed *)
        | 10 -> Code_er   (* 1010 Code execute/read *)
        | 11 -> Code_era  (* 1011 Code execute/read, accessed *)
        | 12 -> Code_ec   (* 1100 Code execute-only, conforming *)
        | 13 -> Code_eca  (* 1101 Code execute-only, conforming, accessed *)
        | 14 -> Code_erc  (* 1110 Code execute/read, conforming *)
        | 15 -> Code_erca (* 1111 Code execute/read, conforming, accessed *)
        | _  -> UndefSegment


    (** abstract data type of an entry of a decription table (GDT or LDT) *)
    type tbl_entry = {
        limit: Z.t;
        base: Z.t;
        typ: segment_descriptor_type;
        s: Z.t;
        dpl: privilege_level;
        p: Z.t;
        avl: Z.t;
        l: Z.t;
        db: Z.t;
        gran: Z.t;}

    (** return a high level representation of a GDT/LDT entry *)
    let tbl_entry_of_int v =
        let ffffff= Z.of_int 0xffffff                  in
        let ffff  = Z.of_int 0xffff                    in
        let f     = Z.of_int 0x0f                      in
        let limit = Z.logand v ffff                        in
        let v'    = Z.shift_right v 16                                     in
        let base  = Z.logand v' ffffff                     in
        let v'    = Z.shift_right v' 24                        in
        let typ   = segment_descriptor_of_int (Z.to_int (Z.logand v' f))   in
        let v'    = Z.shift_right v' 4                     in
        let s     = Z.logand v' Z.one                      in
        let v'    = Z.shift_right v' 1                         in
        let dpl   = Z.logand v' (Z.of_int 3)                   in
        let v'    = Z.shift_right v' 2                     in
        let p     = Z.logand v' Z.one                      in
        let v'    = Z.shift_right v' 1                         in
        let limit = Z.add limit (Z.shift_left (Z.logand v' f) 16)      in
        let v'    = Z.shift_right v' 4                     in
        let avl   = Z.logand v' Z.one                      in
        let v'    = Z.shift_right v' 1                     in
        let l     = Z.logand v' Z.one                      in
        let v'    = Z.shift_right v' 1                     in
        let db    = Z.logand v' Z.one                      in
        let v'    = Z.shift_right v' 1                     in
        let g     = Z.logand v' Z.one                      in
        let v'    = Z.shift_right v' 1                         in
        let base  = Z.add base (Z.shift_left v' 24)      in
        {
            limit = limit;
            base = base;
            typ = typ;
            s = s;
            dpl = privilege_level_of_int (Z.to_int dpl);
            p = p;
            avl = avl;
            l = l;
            db = db;
            gran = g; }

    (** data type of a decription table *)
    type desc_tbl = (Word.t, tbl_entry) Hashtbl.t

    (** decoding context contains all information about
        the segmentation *)
    type ctx_t = {
        mutable data: Register.t;                          (** current segment register for data *)
        gdt: desc_tbl;                                     (** current content of the GDT *)
        ldt: desc_tbl;                                     (** current content of the LDT *)
        idt: desc_tbl;                                     (** current content of the IDT *)
        reg: (Register.t, segment_register_mask) Hashtbl.t (** current value of the segment registers *)
    }

  


                (*******************************************************************************************************)
    (* statements to set/clear the flags *)
    (*******************************************************************************************************)

    (** size of the overflow flag register *)
    let fof_sz = Register.size fof

    (** size of the carry flag register *)
    let fcf_sz = Register.size fcf

    (** size of the sign flag register *)
    let fsf_sz = Register.size fsf

    (** size of the adjust flag *)
    let faf_sz = Register.size faf

    (** size of the zero flag *)
    let fzf_sz = Register.size fzf

    (** size of the parity flag *)
    let fpf_sz = Register.size fpf

    (** size of the interrupt flag *)
    let fif_sz = Register.size fif

    (** size of the direction flag *)
    let fdf_sz = Register.size fdf

    (** produce the statement to set the given flag *)
    let set_flag f = Set (V (T f), Const (Word.one (Register.size f)))

    (** produce the statement to clear the given flag *)
    let clear_flag f = Set (V (T f), Const (Word.zero (Register.size f)))

    (** produce the statement to undefine the given flag *)
    let undef_flag f = Directive (Forget (V (T f)))

    (** produce the statement to set the overflow flag according to the current
        operation whose operands are op1 and op2 and result is res *)
    let overflow_flag_stmts sz res op1 op op2 =
      (* flag is set if both op1 and op2 have the same nth bit and the hightest bit of res differs *)
      Set(V (T fof), overflow_stmts sz res op1 op op2)


    (** produce the statement to set the carry flag according to the current operation whose operands are op1 and op2 and result is res *)
    let carry_flag_stmts sz op1 op op2 =
      Set (V (T fcf), carry_stmts sz op1 op op2)

    let carry_flag_stmts_3 sz op1 op op2 op3 =
      Set (V (T fcf), carry_stmts_3 sz op1 op op2 op3)

    (** produce the statement to set the sign flag wrt to the given parameter *)
    let sign_flag_stmts sz res =
      let c = Cmp (EQ, const 1 sz, BinOp(Shr, res, const (sz-1) sz)) in
      let n = Register.size fsf in
      Set (V (T fsf), TernOp (c, Asm.Const (Word.one n), Asm.Const (Word.zero n)))

    (** produce the statement to set the zero flag *)
    let zero_flag_stmts sz res =
      let c = Cmp (EQ, res, const0 sz) in
      let n = Register.size fzf in
        Set (V (T fzf), TernOp (c, Asm.Const (Word.one n), Asm.Const (Word.zero n)))

    (** produce the statement to set the adjust flag wrt to the given parameters.
     faf is set if there is an overflow on the 4th bit *)
    let adjust_flag_stmts sz op1 op op2 =
      let word_0f = const 0xf sz in
      let word_4 = const 4 8 in
      let one = const 1 sz in
      let op1' = BinOp (And, op1, word_0f)    in
      let op2' = BinOp (And, op2, word_0f)    in
      let res' = BinOp (op, op1', op2') in
      let shifted_res = BinOp(And, BinOp (Shr, res', word_4), one) in
      Set (V (T faf), TernOp(Cmp(EQ, shifted_res, one), const 1 1, const 0 1))

    let adjust_flag_stmts_from_res sz op1 op2 res =
      let word_4 = const 4 8 in
      let one = const 1 sz in
      let comb = BinOp(Xor, res, BinOp (Xor, op1, op2)) in
      let shifted_res = BinOp(And, BinOp (Shr, comb, word_4), one) in
      Set (V (T faf), TernOp( Cmp(EQ, shifted_res, one), const 1 1, const 0 1))

    (** produce the statement to set the parity flag wrt to the given parameters *)
    let parity_flag_stmts sz res =
        (* fpf is set if res contains an even number of 1 in the least significant byte *)
        (* we sum every bits and check whether this sum is even or odd *)
        (* using the modulo of the divison by 2 *)
      let one = const 1 sz in
      let nth i = BinOp (And, BinOp(Shr, res, const i sz), one) in
      let e = ref (BinOp(And, res, one)) in
      for i = 1 to 7 do
        e := BinOp(Xor, !e, nth i)
      done;
      Set (V (T fpf), TernOp (Cmp(EQ, !e, one),
                  Asm.Const (Word.zero fpf_sz),
                  Asm.Const (Word.one fpf_sz)))

    (** builds a value equivalent to the EFLAGS register from the state *)
    let get_eflags () =
      let eflags0 = UnOp (ZeroExt 32, Lval (V (T fcf))) in
      (*  bit 1 : reserved *)
      let eflags2 = BinOp(Shl, UnOp (ZeroExt 32,  Lval (V (T fpf))), const 2 32) in
      (*  bit 3 : reserved *)
      let eflags4 = BinOp(Shl, UnOp (ZeroExt 32, Lval (V (T faf))), const 4 32) in
      (*  bit 5 : reserved *)
      let eflags6 = BinOp(Shl, UnOp(ZeroExt 32, Lval (V (T fzf))), const 6 32) in
      let eflags7 = BinOp(Shl, UnOp(ZeroExt 32, Lval (V (T fsf))), const 7 32) in
      let eflags8 = BinOp(Shl, UnOp(ZeroExt 32, Lval (V (T _ftf))), const 8 32) in
      let eflags9 = BinOp(Shl, UnOp(ZeroExt 32, Lval (V (T fif))), const 9 32) in
      let eflags10 = BinOp(Shl, UnOp(ZeroExt 32, Lval (V (T fdf))), const 10 32) in
      let eflags11 = BinOp(Shl, UnOp(ZeroExt 32, Lval (V (T fof))), const 11 32) in
      let eflags12_13 = BinOp(Shl, UnOp(ZeroExt 32, Lval (V (T _fiopl))), const 12 32) in
      let eflags14 = BinOp(Shl, UnOp(ZeroExt 32, Lval (V (T _fnt))), const 14 32) in
      (*  bit 15 : reserved *)
      let eflags16 = BinOp(Shl, UnOp(ZeroExt 32, Lval (V (T _frf))), const 16 32) in
      let eflags17 = BinOp(Shl, UnOp (ZeroExt 32, Lval (V (T _fvm))), const 17 32) in
      let eflags18 = BinOp(Shl, UnOp (ZeroExt 32, Lval (V (T _fac))), const 18 32) in
      let eflags19 = BinOp(Shl, UnOp (ZeroExt 32, Lval (V (T _fvif))), const 19 32) in
      let eflags20 = BinOp(Shl, UnOp (ZeroExt 32, Lval (V (T _fvip))), const 20 32) in
      let eflags21 = BinOp(Shl, UnOp (ZeroExt 32, Lval (V (T _fid))), const 21 32) in
      let eflags_c0 = eflags0 in
      let eflags_c2 = BinOp(Or, eflags_c0, eflags2) in
      let eflags_c4 = BinOp(Or, eflags_c2, eflags4) in
      let eflags_c6 = BinOp(Or, eflags_c4, eflags6) in
      let eflags_c7 = BinOp(Or, eflags_c6, eflags7) in
      let eflags_c8 = BinOp(Or, eflags_c7, eflags8) in
      let eflags_c9 = BinOp(Or, eflags_c8, eflags9) in
      let eflags_c10 = BinOp(Or, eflags_c9, eflags10) in
      let eflags_c11 = BinOp(Or, eflags_c10, eflags11) in
      let eflags_c12 = BinOp(Or, eflags_c11, eflags12_13) in
      let eflags_c14 = BinOp(Or, eflags_c12, eflags14) in
      let eflags_c16 = BinOp(Or, eflags_c14, eflags16) in
      let eflags_c17 = BinOp(Or, eflags_c16, eflags17) in
      let eflags_c18 = BinOp(Or, eflags_c17, eflags18) in
      let eflags_c19 = BinOp(Or, eflags_c18, eflags19) in
      let eflags_c20 = BinOp(Or, eflags_c19, eflags20) in
      let eflags_c21 = BinOp(Or, eflags_c20, eflags21) in
      eflags_c21

    (** Set the flags from EFLAGS value*)
    let set_eflags eflags =
        let set_f flg value = Set (V (T flg), Lval (V value)) in
            (* XXX check perms and validity *)
            [
            set_f fcf (P(eflags, 0, 0));
            set_f fpf (P(eflags, 2, 2));
            set_f faf (P(eflags, 4, 4));
            set_f fzf (P(eflags, 6, 6));
            set_f fsf (P(eflags, 7, 7));
            set_f _ftf (P(eflags, 8, 8));
            set_f fif (P(eflags, 9, 9));
            set_f fdf (P(eflags, 10, 10));
            set_f fof (P(eflags, 11, 11));
            set_f _fiopl (P(eflags, 12, 13));
            set_f _fnt (P(eflags, 14, 14));
            set_f _frf (P(eflags, 16, 16));
            set_f _fvm (P(eflags, 17, 17));
            set_f _fac (P(eflags, 18, 18));
            set_f _fvif (P(eflags, 19, 19));
            set_f _fvip (P(eflags, 20, 20));
            set_f _fid (P(eflags, 21, 21));
             ]

let overflow_expression () = Lval (V (T fcf))




  (** fatal error reporting *)
  let error a msg =
    Lcore.abort (fun p -> p "at %s: %s" (Address.to_string a) msg)
    

module Make(Arch: sig module Dom: Domain.T val register_tbl: (int, Register.t) Hashtbl.t end) = struct

(** control flow automaton *)
  module Cfa = Cfa.Make(Arch.Dom)

  (** import table *)
  module Imports = X86Imports.Make(Arch.Dom)(Stubs)


  (** complete internal state of the decoder.
    Only the segment field is exported out of the functor (see parse signature) for further reloading *)
    type state = {
        mutable g       : Cfa.t;       (** current cfa *)
        mutable b       : Cfa.State.t; (** state predecessor *)
        a               : Address.t;   (** current address to decode *)
        mutable c         : char list; (** current decoded bytes in reverse order  *)
        mutable addr_sz   : int;       (** current address size in bits *)
        mutable operand_sz: int;       (** current operand size in bits *)
        buf                 : string;      (** buffer to decode *)
        mutable o       : int;     (** current offset to decode into the buffer *)
        mutable rep_prefix: bool option; (** None = no rep prefix ; Some true = rep prefix ; Some false = repne/repnz prefix *)
      mutable segments  : ctx_t;   (** all about segmentation *)
      mutable rep: bool;               (** true whenever a REP opcode has been decoded *)
      mutable repe: bool;              (** true whenever a REPE opcode has been decoded *)
      mutable repne: bool;             (** true whenever a REPNE opcode has been decoded *)
    }             
  let init = Arch.init
           
  (** decoding of one instruction *)
    let decode s =
        let add_sub_mrm s op use_carry sz direction =
            let dst, src = operands_from_mod_reg_rm s sz direction in
            add_sub s op use_carry dst src sz
        in
        let cmp_mrm s sz direction =
            let dst, src = operands_from_mod_reg_rm s sz direction in
            return s (cmp_stmts (Lval dst) src sz)
        in
        let mov_mrm s sz direction =
            let dst, src = operands_from_mod_reg_rm s sz direction in
            return s [ Set (dst, src) ]
        in
        let rec decode s =
            match check_context s (getchar s) with
            | '\x00' -> (* ADD *) add_sub_mrm s Add false 8 0
            | '\x01' -> (* ADD *) add_sub_mrm s Add false s.operand_sz 0
            | '\x02' -> (* ADD *) add_sub_mrm s Add false 8 1
            | '\x03' -> (* ADD *) add_sub_mrm s Add false s.operand_sz 1
            | '\x04' -> (* ADD AL with immediate operand *) add_sub_immediate s Add false eax 8
            | '\x05' -> (* ADD eAX with immediate operand *) add_sub_immediate s Add false eax s.operand_sz
            | '\x06' -> (* PUSH es *) let es' = to_reg es 16 in push s [V es']
            | '\x07' -> (* POP es *) let es' = to_reg es s.operand_sz in pop s [V es']
            | '\x08' -> (* OR *) or_xor_and_mrm s Or 8 0
            | '\x09' -> (* OR *) or_xor_and_mrm s Or s.operand_sz 0
            | '\x0A' -> (* OR *) or_xor_and_mrm s Or 8 1
            | '\x0B' -> (* OR *) or_xor_and_mrm s Or s.operand_sz 1
            | '\x0C' -> (* OR imm8 *) or_xor_and_eax s Or 8 8
            | '\x0D' -> (* OR imm *) or_xor_and_eax s Or s.operand_sz s.operand_sz


            | '\x0E' -> (* PUSH cs *) let cs' = to_reg cs 16 in push s [V cs']
            | '\x0F' -> (* 2-byte escape *) decode_snd_opcode s

            | '\x10' -> (* ADC *) add_sub_mrm s Add true 8 0
            | '\x11' -> (* ADC *) add_sub_mrm s Add true s.operand_sz 0
            | '\x12' -> (* ADC *) add_sub_mrm s Add true 8 1
            | '\x13' -> (* ADC *) add_sub_mrm s Add true s.operand_sz 1

            | '\x14' -> (* ADC AL with immediate *) add_sub_immediate s Add true eax 8
            | '\x15' -> (* ADC eAX with immediate *) add_sub_immediate s Add true eax s.operand_sz
            | '\x16' -> (* PUSH ss *) let ss' = to_reg ss 16 in push s [V ss']
            | '\x17' -> (* POP ss *) let ss' = to_reg ss s.operand_sz in pop s [V ss']

            | '\x18' -> (* SBB *) add_sub_mrm s Sub true 8 0
            | '\x19' -> (* SBB *) add_sub_mrm s Sub true s.operand_sz 0
            | '\x1A' -> (* SBB *) add_sub_mrm s Sub true 8 1
            | '\x1B' -> (* SBB *) add_sub_mrm s Sub true s.operand_sz 1
            | '\x1C' -> (* SBB AL with immediate *) add_sub_immediate s Sub true eax 8
            | '\x1D' -> (* SBB eAX with immediate *) add_sub_immediate s Sub true eax s.operand_sz
            | '\x1E' -> (* PUSH ds *) let ds' = to_reg ds 16 in push s [V ds']
            | '\x1F' -> (* POP ds *) let ds' = to_reg ds 16 in pop s [V ds']

            | '\x20' -> (* AND *) or_xor_and_mrm s And 8 0
            | '\x21' -> (* AND *) or_xor_and_mrm s And s.operand_sz 0
            | '\x22' -> (* AND *) or_xor_and_mrm s And 8 1
            | '\x23' -> (* AND *) or_xor_and_mrm s And s.operand_sz 1
            | '\x24' -> (* AND imm8 *) or_xor_and_eax s And 8 8
            | '\x25' -> (* AND imm *) or_xor_and_eax s And s.operand_sz s.operand_sz

            | '\x26' -> (* data segment = es *) s.segments.data <- es; decode s
            | '\x27' -> (* DAA *) daa s
            | '\x28' -> (* SUB *) add_sub_mrm s Sub false 8 0
            | '\x29' -> (* SUB *) add_sub_mrm s Sub false s.operand_sz 0
            | '\x2A' -> (* SUB *) add_sub_mrm s Sub false 8 1
            | '\x2B' -> (* SUB *) add_sub_mrm s Sub false s.operand_sz 1
            | '\x2C' -> (* SUB AL with immediate *) add_sub_immediate s Sub false eax 8
            | '\x2D' -> (* SUB eAX with immediate *) add_sub_immediate s Sub false eax s.operand_sz
            | '\x2E' -> (* data segment = cs *) s.segments.data <- cs; (* will be set back to default value if the instruction is a jcc *) decode s
            | '\x2F' -> (* DAS *) das s

            | '\x30' -> (* XOR *) or_xor_and_mrm s Xor 8 0
            | '\x31' -> (* XOR *) or_xor_and_mrm s Xor s.operand_sz 0
            | '\x32' -> (* XOR *) or_xor_and_mrm s Xor 8 1
            | '\x33' -> (* XOR *) or_xor_and_mrm s Xor s.operand_sz 1
            | '\x34' -> (* XOR imm8 *) or_xor_and_eax s Xor 8 8
            | '\x35' -> (* XOR imm *) or_xor_and_eax s Xor s.operand_sz s.operand_sz

            | '\x36' -> (* data segment = ss *) s.segments.data <- ss; decode s
            | '\x37' -> (* AAA *) aaa s
            | '\x38' -> (* CMP *) cmp_mrm s 8 0
            | '\x39' -> (* CMP *) cmp_mrm s s.operand_sz 0
            | '\x3A' -> (* CMP *) cmp_mrm s 8 1
            | '\x3B' -> (* CMP *) cmp_mrm s s.operand_sz 1
            | '\x3C' -> (* CMP AL with immediate *)
              let imm = get_imm s 8 8 false in
              return s (cmp_stmts (Lval (V (P (eax, 0, 7)))) imm 8)
            | '\x3D' -> (* CMP eAX with immediate *)
              let i = get_imm s s.operand_sz s.operand_sz false in
              return s (cmp_stmts (Lval (V (P (eax, 0, s.operand_sz-1)))) i s.operand_sz)
            | '\x3E' -> (* data segment = ds *) s.segments.data <- ds (* will be set back to default value if the instruction is a jcc *); decode s
            | '\x3F' -> (* AAS *) aas s

            | c when '\x40' <= c && c <= '\x47' -> (* INC *) let r = find_reg ((Char.code c) - 0x40) s.operand_sz in inc_dec (V r) Add s s.operand_sz
            | c when '\x48' <= c && c <= '\x4f' -> (* DEC *) let r = find_reg ((Char.code c) - 0x48) s.operand_sz in inc_dec (V r) Sub s s.operand_sz

            | c when '\x50' <= c && c <= '\x57' -> (* PUSH general register *) let r = find_reg ((Char.code c) - 0x50) s.operand_sz in push s [V r]
            | c when '\x58' <= c && c <= '\x5F' -> (* POP into general register *) let r = find_reg ((Char.code c) - 0x58) s.operand_sz in pop s [V r]

            | '\x60' -> (* PUSHA *) let l = List.map (fun v -> find_reg_v v s.operand_sz) [0 ; 1 ; 2 ; 3 ; 5 ; 6 ; 7] in push s l
            | '\x61' -> (* POPA *) let l = List.map (fun v -> find_reg_v v s.operand_sz) [7 ; 6 ; 3 ; 2 ; 1 ; 0] in pop s l

            | '\x63' -> (* ARPL *) arpl s
            | '\x64' -> (* segment data = fs *) s.segments.data <- fs; decode s
            | '\x65' -> (* segment data = gs *) s.segments.data <- gs; decode s
            | '\x66' -> (* operand size switch *) switch_operand_size s; decode s
            | '\x67' -> (* address size switch *) s.addr_sz <- if s.addr_sz = 16 then 32 else 16; decode s
            | '\x68' -> (* PUSH immediate *) push_immediate s s.operand_sz
            | '\x69' -> (* IMUL immediate *) let dst, src = operands_from_mod_reg_rm s s.operand_sz 1 in let imm = get_imm s s.operand_sz s.operand_sz true in imul_stmts s dst src imm
            | '\x6a' -> (* PUSH byte *) push_immediate s 8
            | '\x6b' -> (* IMUL imm8 *) let dst, src = operands_from_mod_reg_rm s s.operand_sz 1 in let imm = get_imm s 8 s.operand_sz true in imul_stmts s dst src imm

            | '\x6c' -> (* INSB *) ins s 8
            | '\x6d' -> (* INSW/D *) ins s s.addr_sz
            | '\x6e' -> (* OUTSB *) outs s 8
            | '\x6f' -> (* OUTSW/D *) outs s s.addr_sz

            | c when '\x70' <= c && c <= '\x7F' -> (* JCC: short displacement jump on condition *) let v = (Char.code c) - 0x70 in jcc s v 8

            | '\x80' -> (* grp1 opcode table *) grp1 s 8 8
            | '\x81' -> (* grp1 opcode table *) grp1 s s.operand_sz s.operand_sz
            | '\x82' -> error s.a ("Undefined opcode 0x82")
            | '\x83' -> (* grp1 opcode table *) grp1 s s.operand_sz 8
            | '\x84' -> (* TEST /r8 *) let dst, src = (operands_from_mod_reg_rm s 8 0) in return s (test_stmts dst src 8)
            | '\x85' -> (* TEST /r *) let dst, src = operands_from_mod_reg_rm s s.operand_sz 0 in return s (test_stmts dst src s.operand_sz)
            | '\x86' -> (* XCHG byte registers *)  xchg_mrm s 8
            | '\x87' -> (* XCHG word or double-word registers *) xchg_mrm s s.operand_sz
            | '\x88' -> (* MOV *) mov_mrm s 8 0
            | '\x89' -> (* MOV *) mov_mrm s s.operand_sz 0
            | '\x8A' -> (* MOV *) mov_mrm s 8 1
            | '\x8B' -> (* MOV *) mov_mrm s s.operand_sz 1


            | '\x8c' -> (* MOV with segment as src *)
              let _mod, reg, rm = mod_nnn_rm (Char.code (getchar s)) in
              let dst = find_reg_v rm 16 in
              let src = V (T (to_segment_reg s.a reg)) in
              return s [ Set (dst, Lval src) ]

            | '\x8d' -> (* LEA *) lea s
            | '\x8e' -> (* MOV with segment as dst *)
              let _mod, reg, rm = mod_nnn_rm (Char.code (getchar s)) in
              let dst = V ( T (to_segment_reg s.a reg)) in
              let src = find_reg_v rm 16 in
              return s [ Set (dst, Lval src) ]
            | '\x8f' -> (* POP of word or double word *) let dst, _src = operands_from_mod_reg_rm s s.operand_sz 0 in pop s [dst]

            | '\x90'                  -> (* NOP *) return s [Nop]
            | c when '\x91' <= c && c <= '\x97' -> (* XCHG word or double-word with eAX *) xchg_with_eax s ((Char.code c) - 0x90)
            | '\x98' -> (* CBW *) let dst = V (to_reg eax s.operand_sz) in return s [Set (dst, UnOp (SignExt s.operand_sz, Lval (V (to_reg eax (s.operand_sz / 2)))))]
            | '\x99' -> (* CWD / CDQ *) cwd_cdq s
            | '\x9a' -> (* CALL *)
              let off = int_of_bytes s (s.operand_sz / 8) in
              let cs' = get_base_address s (Hashtbl.find s.segments.reg cs) in
              let a = Data.Address.add_offset (Data.Address.of_int Data.Address.Global cs' s.addr_sz) off in
              call s (A a)
            | '\x9b' -> (* WAIT *) error s.a "WAIT decoder. Interpreter halts"
            | '\x9c' -> (* PUSHF *) pushf s s.operand_sz
            | '\x9d' -> (* POPF *) popf s s.operand_sz
            | '\xa0' -> (* MOV EAX *) mov_with_eax s 8 false
            | '\xa1' -> (* MOV EAX *) mov_with_eax s s.operand_sz false
            | '\xa2' -> (* MOV EAX *) mov_with_eax s 8 true
            | '\xa3' -> (* MOV EAX *) mov_with_eax s s.operand_sz true
            | '\xa4' -> (* MOVSB *) movs s 8
            | '\xa5' -> (* MOVSW *) movs s s.addr_sz
            | '\xa6' -> (* CMPSB *) cmps s 8
            | '\xa7' -> (* CMPSW *) cmps s s.addr_sz
            | '\xa8' -> (* TEST AL, imm8 *) return s (test_stmts (find_reg_v 0 8) (get_imm s 8 8 false) 8)
            | '\xa9' -> (* TEST xAX, imm *) return s (test_stmts (find_reg_v 0 s.operand_sz) (get_imm s s.operand_sz s.operand_sz false) s.operand_sz )
            | '\xaa' -> (* STOS on byte *) stos s 8
            | '\xab' -> (* STOS *) stos s s.addr_sz
            | '\xac' -> (* LODS on byte *) lods s 8
            | '\xad' -> (* LODS *) lods s s.addr_sz
            | '\xae' -> (* SCAS on byte *) scas s 8
            | '\xaf' -> (* SCAS *) scas s s.addr_sz

            | c when '\xb0' <= c && c <= '\xb3' -> (* MOV immediate byte into byte register *) let r = (find_reg_v ((Char.code c) - 0xb0) 8) in return s [Set (r, Const (Word.of_int (int_of_byte s) 8))]
            | c when '\xb4' <= c && c <= '\xb7' -> (* MOV immediate byte into byte register (higher part) *)
              let n = (Char.code c) - 0xb4  in
              let r = V (P (Hashtbl.find register_tbl n, 8, 15)) in
              return s [Set (r, Const (Word.of_int (int_of_byte s) 8))]
            | c when '\xb8' <= c && c <= '\xbf' -> (* mov immediate word or double into word or double register *)
              let r = (find_reg_v ((Char.code c) - 0xb8) s.operand_sz) in return s [Set (r, Const (Word.of_int (int_of_bytes s (s.operand_sz/8)) s.operand_sz))]

            | '\xc0' -> (* shift grp2 with byte size*) grp2 s 8 None
            | '\xc1' -> (* shift grp2 with word or double-word size *) grp2 s s.operand_sz None
            | '\xc2' -> (* RET NEAR and pop word *) return s [ Return; (* pop imm16 *) set_esp Add (T esp) (s.addr_sz + 16); ]
            | '\xc3' -> (* RET NEAR *) return s [ Return; set_esp Add (T esp) s.addr_sz; ]
            | '\xc4' -> (* LES *) load_far_ptr s es
            | '\xc5' -> (* LDS *) load_far_ptr s ds
            | '\xc6' -> (* MOV with byte *) mov_immediate s 8
            | '\xc7' -> (* MOV with word or double *) mov_immediate s s.operand_sz

            | '\xc9' -> (* LEAVE *)
              let sp = V (to_reg esp s.operand_sz) in
              let bp = V (to_reg ebp s.operand_sz) in
              return s ( (Set (sp, Lval bp))::(pop_stmts false s [bp]))
            | '\xca' -> (* RET FAR and pop a word *) return s ([Return ; set_esp Add (T esp) s.addr_sz ; ] @ (pop_stmts false s [V (T cs)] @ (* pop imm16 *) [set_esp Add (T esp) 16]))
            | '\xcb' -> (* RET FAR *) return s ([Return ; set_esp Add (T esp) s.addr_sz; ] @ (pop_stmts false s [V (T cs)]))
            | '\xcc' -> (* INT 3 *) error s.a "INT 3 decoded. Interpreter halts"
            | '\xcd' -> (* INT *) let c = getchar s in error s.a (Printf.sprintf "INT %d decoded. Interpreter halts" (Char.code c))
            | '\xce' -> (* INTO *) error s.a "INTO decoded. Interpreter halts"
            | '\xcf' -> (* IRET *) error s.a "IRET instruction decoded. Interpreter halts"

            | '\xd0' -> (* grp2 shift with one on byte size *) grp2 s 8 (Some (const1 8))
            | '\xd1' -> (* grp2 shift with one on word or double size *) grp2 s s.operand_sz (Some (const1 8))
            | '\xd2' -> (* grp2 shift with CL and byte size *) grp2 s 8 (Some (Lval (V (to_reg ecx 8))))
            | '\xd3' -> (* grp2 shift with CL *) grp2 s s.operand_sz (Some (Lval (V (to_reg ecx 8))))
            | '\xd4' -> (* AAM *) aam s
            | '\xd5' -> (* AAD *) aad s
            | '\xd7' -> (* XLAT *) xlat s
            | c when '\xd8' <= c && c <= '\xdf' -> (* ESC (escape to coprocessor instruction set *) decode_coprocessor c s

            | c when '\xe0' <= c && c <= '\xe2' -> (* LOOPNE/LOOPE/LOOP *) loop s c
            | '\xe3' -> (* JCXZ *) jecxz s

            | '\xe8' -> (* relative call *) relative_call s s.operand_sz
            | '\xe9' -> (* JMP to near relative address (offset has word or double word size) *) relative_jmp s s.operand_sz
            | '\xea' -> (* JMP to near absolute address *) direct_jmp s
            | '\xeb' -> (* JMP to near relative address (offset has byte size) *) relative_jmp s 8


            | '\xf0' -> (* LOCK *) Lcore.analysis(fun p -> p "x86 LOCK prefix ignored"); decode s
            | '\xf1' -> (* undefined *) error s.a "Undefined opcode 0xf1"
            | '\xf2' -> (* REPNE *) s.repne <- true; rep s Word.one
            | '\xf3' -> (* REP/REPE *) s.repe <- true; rep s Word.zero
            | '\xf4' -> (* HLT *) error s.a "Decoder stopped: HLT reached"
            | '\xf5' -> (* CMC *) let fcf' = V (T fcf) in return s [ Set (fcf', UnOp (Not, Lval fcf')) ]
            | '\xf6' -> (* shift to grp3 with byte size *) grp3 s 8
            | '\xf7' -> (* shift to grp3 with word or double word size *) grp3 s s.operand_sz
            | '\xf8' -> (* CLC *) return s (clear_flag fcf fcf_sz)
            | '\xf9' -> (* STC *) return s (set_flag fcf fcf_sz)
            | '\xfa' -> (* CLI *) Lcore.decoder (fun p -> p "entering privilege mode (CLI instruction)"); return s (clear_flag fif fif_sz)
            | '\xfb' -> (* STI *) Lcore.decoder (fun p -> p "entering privilege mode (STI instruction)"); return s (set_flag fif fif_sz)
            | '\xfc' -> (* CLD *) return s (clear_flag fdf fdf_sz)
            | '\xfd' -> (* STD *) return s (set_flag fdf fdf_sz)
            | '\xfe' -> (* INC/DEC grp4 *) grp4 s
            | '\xff' -> (* indirect grp5 *) grp5 s
            | c ->  error s.a (Printf.sprintf "Unknown opcode 0x%x" (Char.code c))

        and rep s c =
        (* rep prefix *)
          try
            (* TODO: remove this hack *)
            (* get the next instruction *)
            let v, ip = decode s in
            begin
              match List.hd v.Cfa.State.stmts with
              | Return -> Lcore.decoder (fun p -> p "simplified rep ret into ret")
              | _ ->
                 (* hack: if we do not have a cmps or a scas remove repe/repne flag *)
                 begin
                   match List.hd s.c with
                    | '\xA6' | '\xA7' | '\xAE' | '\xAF' -> ();
                    | _ -> s.repe <- false; s.repne <- false;
                 end;
                 Lcore.debug (fun p->p "rep decoder: s.repe : %b, s.repne: %b" s.repe s.repne);
                 let ecx_cond  = Cmp (NEQ, Lval (V (to_reg ecx s.addr_sz)), Const (Word.zero s.addr_sz)) in
                 let a'  = Data.Address.add_offset s.a (Z.of_int s.o) in
                 let zf_stmts =
                           if s.repe || s.repne then
                             [ If (Cmp (EQ, Lval (V (T fzf)), Const (c fzf_sz)), [Directive Default_unroll ; Jmp (A a')],
                       [Jmp (A v.Cfa.State.ip) ]) ]
                           else
                             [ Jmp (A v.Cfa.State.ip) ]
                 in
                 let ecx' = V (to_reg ecx s.addr_sz) in
                 let ecx_stmt = Set (ecx', BinOp (Sub, Lval ecx', Const (Word.one s.addr_sz))) in
                 let blk =
                   [
                     If (ecx_cond,
                     v.Cfa.State.stmts @ (ecx_stmt :: zf_stmts),
                     [Directive Default_unroll ; Jmp (A a')])
                   ]
                 in
                 if not (s.repe || s.repne) then
                   v.Cfa.State.stmts <- [ Directive (Type (V (T ecx), Types.T (TypedC.Int (Newspeak.Unsigned, Register.size ecx))));
                              Directive (Unroll (Lval (V (T ecx)), 10000)) ] @ blk
                 else
                   begin
                     let cmp = if s.repne then EQ else NEQ in
                     let stmts =
                       match (List.hd (List.tl v.Cfa.State.bytes)) with
                       | '\xae' -> (unroll_scas cmp s 8)::blk
                       | '\xaf' -> (unroll_scas cmp s s.addr_sz)::blk
                    | _ -> blk
                     in
                     v.Cfa.State.stmts <- stmts
                   end;
                end;
            v, ip
          with No_rep (v, ip) -> v, ip

        and decode_snd_opcode s =
            match getchar s with
            | '\x00' -> grp6 s
            | '\x01' -> grp7 s
            (* CMOVcc *)
            | '\x31' (* RDTSC *) ->  return s [ Directive (Forget (V (T edx))); Directive (Forget (V (T eax)))]
            | c when '\x40' <= c && c <= '\x4f' -> let cond = (Char.code c) - 0x40 in cmovcc s cond

            | '\x10' -> (* MOVSD / MOVSS *) (* TODO: make it more precise *)
               let v, ip = return s [ Directive (Forget (V (T xmm1))) ] in
               raise (No_rep (v, ip))

            | '\x11' -> (* MOVSD / MOVSS *) (* TODO: make it more precise *)
               let sz =
                 if s.repne then 64
                 else if s.repe then 32
                 else error s.a "unknown instruction 0F11"
               in
               let v, ip = mod_rm_on_xmm2 s sz in
               raise (No_rep (v, ip))

            | '\x1F' -> (* long nop *) let _, _ = operands_from_mod_reg_rm s s.operand_sz 0 in return s [ Nop ]

            | '\x28' -> (* MOVAPD *) (* TODO: make it more precise *)
               switch_operand_size s;
              (* because this opcode is 66 0F 29 ; 0x66 has been parsed and hence operand size changed *)
              return s [ Directive (Forget (V (T xmm1))) ]

            | '\x29' -> (* MOVAPD *) (* TODO: make it more precise *)
                 switch_operand_size s; (* because this opcode is 66 0F 29 ; 0x66 has been parsed and hence operand size changed *)
              mod_rm_on_xmm2 s 128

            | '\x2A' -> (* CVTSI2SD / CVTSI2SS *) (* TODO: make it more precise *)
               let c = getchar s in
               let _, reg, _ = mod_nnn_rm (Char.code c) in
               let xmm = Hashtbl.find xmm_tbl reg in
               let forgets = List.map (fun r -> Directive (Forget (V (T r)))) [xmm ; mxcsr_pm] in
               let v, ip = return s forgets in
               raise (No_rep (v, ip))

            | '\x2C' -> (* CVTTSD2SI / CVTTSS2SI *) (* TODO: make it more precise *)
               let c = getchar s in
               let _, reg, _ = mod_nnn_rm (Char.code c) in
               let reg' = Hashtbl.find register_tbl reg in
               let forgets = List.map (fun r -> Directive (Forget (V (T r)))) [reg' ; mxcsr_im ; mxcsr_pm] in
               let v, ip = return s forgets in
               raise (No_rep (v, ip))



            | '\x2F' -> (* COMISS / CMOISD *) (* TODO: make it more precise *)
               let forgets =
                 List.map (fun flag -> Directive (Forget (V (T flag)))) [ fzf ; fpf ; fcf ; mxcsr_ie ; mxcsr_de; xmm1]
               in
               return s forgets

            | c when '\x40' <= c && c <= '\x4f' -> (* CMOVcc *) let cond = (Char.code c) - 0x40 in cmovcc s cond

            | '\x54' -> (* ANDPD *) (* TODO: make it more precise *) return s [ Directive (Forget (V (T xmm1))) ]

            | '\x57' -> (* XORPD *) (* TODO: make it more precise *) return s [ Directive (Forget (V (T xmm1))) ]
            | '\x58' -> (* ADDPS / ADDSD / ADSS *) (* TODO: make it more precise *)
               let forgets =
                 List.map (fun flag -> Directive (Forget (V (T flag)))) [ mxcsr_oe ; mxcsr_ue ;  mxcsr_ie ; mxcsr_pe ; mxcsr_de; xmm1]
               in
               return s forgets

            | '\x59' -> (* MULPS / MULSD / MULSS *) (* TODO: make it more precise *)
               let forgets =
                 List.map (fun flag -> Directive (Forget (V (T flag)))) [ mxcsr_oe ; mxcsr_ue ;  mxcsr_ie ; mxcsr_pe ; mxcsr_de ; xmm1]
               in
               return s forgets

            | '\x5A' -> (* CVTSD2SS *) (* TODO: make it more precise *)
               let forgets = List.map (fun r -> Directive (Forget (V (T r)))) [xmm1 ; mxcsr_om ; mxcsr_um ; mxcsr_im ; mxcsr_pm ; mxcsr_dm] in
               let v, ip = return s forgets in
               raise (No_rep (v, ip))

            | '\x5C' -> (* SUBPS / SUBSD / SUBSS *) (* TODO: make it more precise *)
               let forgets =
                 List.map (fun flag -> Directive (Forget (V (T flag)))) [ mxcsr_oe ; mxcsr_ue ;  mxcsr_ie ; mxcsr_pe ; mxcsr_de ; xmm1]
               in
               return s forgets

            | '\x5E' -> (* DIVPS / DIVSD / DIVSS *) (* TODO: make it more precise *)
               let forgets =
                 List.map (fun flag -> Directive (Forget (V (T flag)))) [ mxcsr_oe ; mxcsr_ue ;  mxcsr_ie ; mxcsr_pe ; mxcsr_de ; mxcsr_ze ; xmm1]
               in
               return s forgets

            | c when '\x80' <= c && c <= '\x8f' -> let cond = (Char.code c) - 0x80 in jcc s cond 32
            | c when '\x90' <= c && c <= '\x9f' -> let cond = (Char.code c) - 0x90 in setcc s cond
            | '\xa0' -> push s [V (T fs)]
            | '\xa1' -> pop s [V (T fs)]
            (*| '\xa2' -> cpuid *)
            | '\xa3' -> let reg, rm = operands_from_mod_reg_rm s s.operand_sz 0 in bt s reg rm
            | '\xa4' -> let reg, rm = operands_from_mod_reg_rm s s.operand_sz 0 in return s (shift_ld_stmt reg rm s.operand_sz (get_imm s 8 8 false))
            | '\xa5' -> let reg, rm = operands_from_mod_reg_rm s s.operand_sz 0 in return s (shift_ld_stmt reg rm s.operand_sz (Lval (V cl)))
            | '\xa8' -> push s [V (T gs)]
            | '\xa9' -> pop s [V (T gs)]

            | '\xab' -> let reg, rm = operands_from_mod_reg_rm s s.operand_sz 0 in bts s reg rm
            | '\xac' -> let reg, rm = operands_from_mod_reg_rm s s.operand_sz 0 in return s (shift_rd_stmt reg rm s.operand_sz (get_imm s 8 8 false))
            | '\xad' -> let reg, rm = operands_from_mod_reg_rm s s.operand_sz 0 in return s (shift_rd_stmt reg rm s.operand_sz (Lval (V cl)))
            | '\xaf' -> let reg, rm = operands_from_mod_reg_rm s s.operand_sz 1 in imul_stmts s reg (Lval reg) rm

            | '\xb0' -> (* CMPXCHG *) let reg, rm = operands_from_mod_reg_rm s 8 0 in cmpxchg s reg rm 8
            | '\xb1' -> (* CMPXCHG *) let reg, rm = operands_from_mod_reg_rm s s.operand_sz 0 in cmpxchg s reg rm s.operand_sz

            | '\xb2' -> load_far_ptr s ss
            | '\xb3' -> let reg, rm = operands_from_mod_reg_rm s s.operand_sz 0 in btr s reg rm
            | '\xb4' -> load_far_ptr s fs
            | '\xb5' -> load_far_ptr s gs

            | '\xb6' -> let reg, rm = operands_from_mod_reg_rm s 8 ~dst_sz:s.operand_sz 1 in
                        return s [ Set (reg, UnOp(ZeroExt s.operand_sz, rm)) ]
            | '\xb7' ->
               let reg, rm = operands_from_mod_reg_rm s 16 ~dst_sz:32 1 in
              return s [ Set (reg, UnOp(ZeroExt 32, rm)) ]

            | '\xba' -> grp8 s
            | '\xbb' -> let reg, rm = operands_from_mod_reg_rm s s.operand_sz 0 in btc s reg rm
            | '\xbc' -> let reg, rm = operands_from_mod_reg_rm s s.operand_sz 1 in bsf s reg rm
            | '\xbd' -> let reg, rm = operands_from_mod_reg_rm s s.operand_sz 1 in bsr s reg rm
            | '\xbe' -> let reg, rm = operands_from_mod_reg_rm s 8  ~dst_sz:s.operand_sz 1 in
                        return s [ Set (reg, UnOp(SignExt s.operand_sz, rm)) ];

            | '\xbf' -> let reg, rm = operands_from_mod_reg_rm s 16 ~dst_sz:32 1 in return s [ Set (reg, UnOp(SignExt 32, rm)) ]

            | '\xc0' -> (* XADD *)  xadd_mrm s 8
            | '\xc1' -> (* XADD *)  xadd_mrm s s.operand_sz

            | '\xc7' -> (* CMPXCHG8B *)  cmpxchg8b_mrm s


            | c        -> error s.a (Printf.sprintf "unknown second opcode 0x%x\n" (Char.code c))
        in
        decode s

  let parse text g is v a ctx =
    let s' = {
        g          = g;
        a          = a;
        o          = 0;
        c          = [];
        addr_sz    = !Config.address_sz;
        operand_sz = !Config.operand_sz;
        segments   = copy_segments is a ctx;
        rep_prefix = None;
        buf        = text;
        b          = v;
        rep        = false;
        repe       = false;
        repne      = false
      }
    in
    try
      let v', ip = decode s' in
      Some (v', ip, s'.segments)
    with
    | Exceptions.Error _ as e -> raise e
    | _               -> (*end of buffer *) None
  end
