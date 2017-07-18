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

(***************************************************************************************)
(* Decoder functor *)
(***************************************************************************************)

module L = Log.Make(struct let name = "decoder" end)

module Make(Domain: Domain.T) =
struct

    (** control flow automaton *)
    module Cfa = Cfa.Make(Domain)

    (** import table *)
    module Imports = Imports.Make(Domain)
      
    open Data
    open Asm


    (************************************************************************)
    (* Generic Helpers *)
    (************************************************************************)

    (** [const c sz] builds the asm constant of size _sz_ from int _c_ *)
    let const c sz = Const (Word.of_int (Z.of_int c) sz)

    (** [const_of_Z z sz] builds the asm constant of size _sz_ from Z _z_ *)
    let const_of_Z z sz = Const (Word.of_int z sz)

    (** sign extension of a Z.int _i_ of _sz_ bits on _nb_ bits *)
    let sign_extension i sz nb =
        if Z.testbit i (sz-1) then
            let ff = (Z.sub (Z.shift_left (Z.one) nb) Z.one) in
            (* ffff00.. mask *)
            let ff00 = (Z.logxor ff ((Z.sub (Z.shift_left (Z.one) sz) Z.one))) in
            Z.logor ff00 i
        else
            i


    (************************************************************************)
    (* Creation of the general purpose registers *)
    (************************************************************************)

    let (register_tbl: (int, Register.t) Hashtbl.t) = Hashtbl.create 8;;

    let eax = Register.make ~name:"eax" ~size:32;;
    let ecx = Register.make ~name:"ecx" ~size:32;;
    let edx = Register.make ~name:"edx" ~size:32;;
    let ebx = Register.make ~name:"ebx" ~size:32;;
    let esp = Register.make_sp ~name:"esp" ~size:32;;
    let ebp = Register.make ~name:"ebp" ~size:32;;
    let esi = Register.make ~name:"esi" ~size:32;;
    let edi = Register.make ~name:"edi" ~size:32;;
    let cl = P(ecx, 0, 7);;

    Hashtbl.add register_tbl 0 eax;;
    Hashtbl.add register_tbl 1 ecx;;
    Hashtbl.add register_tbl 2 edx;;
    Hashtbl.add register_tbl 3 ebx;;
    Hashtbl.add register_tbl 4 esp;;
    Hashtbl.add register_tbl 5 ebp;;
    Hashtbl.add register_tbl 6 esi;;
    Hashtbl.add register_tbl 7 edi;;


    (*************************************************************************)
    (* Creation of the flag registers *)
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
            | _ -> L.abort (fun p -> p "Invalid decription table selection")
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
        let ffffff= Z.of_int 0xffffff   			   in
        let ffff  = Z.of_int 0xffff					   in
        let f 	  = Z.of_int 0x0f					   in
        let limit = Z.logand v ffff    					   in
        let v' 	  = Z.shift_right v 16	                                   in
        let base  = Z.logand v' ffffff 					   in
        let v' 	  = Z.shift_right v' 24	 			           in
        let typ   = segment_descriptor_of_int (Z.to_int (Z.logand v' f))   in
        let v' 	  = Z.shift_right v' 4				 	   in
        let s 	  = Z.logand v' Z.one				 	   in
        let v' 	  = Z.shift_right v' 1        			 	   in
        let dpl   = Z.logand v' (Z.of_int 3)				   in
        let v' 	  = Z.shift_right v' 2				 	   in
        let p 	  = Z.logand v' Z.one				 	   in
        let v' 	  = Z.shift_right v' 1        			 	   in
        let limit = Z.add limit (Z.shift_left (Z.logand v' f) 16)	   in
        let v' 	  = Z.shift_right v' 4				 	   in
        let avl	  = Z.logand v' Z.one				 	   in
        let v' 	  = Z.shift_right v' 1  			 	   in
        let l 	  = Z.logand v' Z.one				 	   in
        let v' 	  = Z.shift_right v' 1   		                   in
        let db 	  = Z.logand v' Z.one				 	   in
        let v' 	  = Z.shift_right v' 1  		    		   in
        let g 	  = Z.logand v' Z.one				 	   in
        let v' 	  = Z.shift_right v' 1  		    		   in
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

    (** abstract data type for the segmentation field in the decoder state *)
    type segment_t = {
        mutable data: Register.t;                          (** current segment register for data *)
        gdt: desc_tbl;                                     (** current content of the GDT *)
        ldt: desc_tbl;                                     (** current content of the LDT *)
        idt: desc_tbl;                                     (** current content of the IDT *)
        reg: (Register.t, segment_register_mask) Hashtbl.t (** current value of the segment registers *)
    }

    (** complete internal state of the decoder.
    Only the segment field is exported out of the functor (see parse signature) for further reloading *)
    type state = {
        mutable g 	    : Cfa.t; 	   (** current cfa *)
        mutable b 	    : Cfa.State.t; (** state predecessor *)
        a 	     	    : Address.t;   (** current address to decode *)
        mutable c         : char list; (** current decoded bytes in reverse order  *)
        mutable addr_sz   : int;   	   (** current address size in bits *)
        mutable operand_sz: int;  	   (** current operand size in bits *)
        buf 	     	    : string;      (** buffer to decode *)
        mutable o 	    : int; 	   (** current offset to decode into the buffer *)
        mutable rep_prefix: bool option; (** None = no rep prefix ; Some true = rep prefix ; Some false = repne/repnz prefix *)
      mutable segments  : segment_t;   (** all about segmentation *)
      mutable rep: bool;               (** true whenever a REP opcode has been decoded *)
      mutable repe: bool;              (** true whenever a REPE opcode has been decoded *)
      mutable repne: bool;             (** true whenever a REPNE opcode has been decoded *)
    }


    (** fatal error reporting *)
    let error a msg =
        L.abort (fun p -> p "at %s: %s" (Address.to_string a) msg)


    (***********************************************************************)
    (* State helpers *)
    (***********************************************************************)

    (** extract from the string code the current byte to decode 
    The offset field of the decoder state is increased *)
    let getchar s =
        let c = String.get s.buf s.o in
        s.o <- s.o + 1;
        s.c <- c::s.c;
        c

    (** int conversion of a byte in the string code *)
    let int_of_byte s = Z.of_int (Char.code (getchar s))

    (** [int_of_bytes s sz] is an integer conversion of sz bytes of the string code s.buf *)
    (* TODO check if Z.of_bits could work *)
    let int_of_bytes s sz =
        let n = ref Z.zero in
        for i = 0 to sz-1 do
            n := Z.add !n (Z.shift_left (int_of_byte s) (i*8));
        done;
        !n;;

    (** helper to get immediate of _imm_sz_ bits into a _sz_ int, doing
        _sign_ext_ if true*)
    let get_imm_int s imm_sz sz sign_ext =
        if imm_sz > sz then
            error s.a (Printf.sprintf "Immediate size (%d) bigger than target size (%d)" imm_sz sz)
        else
            let i = int_of_bytes s (imm_sz/8) in
            if sign_ext then
                if imm_sz = sz then
                    i
                else
                    sign_extension i imm_sz sz
            else
                i

    (** helper to get immediate of _imm_sz_ bits into a _sz_ Const, doing
        _sign_ext_ if true*)
    let get_imm s imm_sz sz sign_ext =
        const_of_Z (get_imm_int s imm_sz sz sign_ext) sz


    (** update and return the current state with the given statements and the new instruction value.
     The context of decoding is also updated *)
    let return s stmts =
      s.b.Cfa.State.ctx <- { Cfa.State.addr_sz = s.addr_sz ; Cfa.State.op_sz = s.operand_sz };
        s.b.Cfa.State.stmts <- stmts;
        s.b.Cfa.State.bytes <- List.rev s.c;
        s.b, Address.add_offset s.a (Z.of_int s.o)

    (************************************************************************************)
    (* segmentation *)
    (************************************************************************************)
	  
    (** builds information from a value as supposed to contained in a segment register *)
    let mask_of_segment_register_content v =
        let lvl   = v land 3         in
        let ti    = (v lsr 2) land 1 in
        let index = (v lsr 3)        in
        { rpl = privilege_level_of_int lvl; ti = if ti = 0 then GDT else LDT; index = Word.of_int (Z.of_int index) 13 }

    (** returns the base address corresponding to the given value (whose format is supposed to be compatible with the content of segment registers *)


    let get_segments a ctx =
        let registers = Hashtbl.create 6 in
        try
            List.iter (fun r -> Hashtbl.add registers r (get_segment_register_mask (ctx#value_of_register r))) [ cs; ds; ss; es; fs; gs ];
            registers
        with _ -> error a "Decoder: overflow in a segment register"

    let copy_segments s a ctx = { gdt = Hashtbl.copy s.gdt; ldt = Hashtbl.copy s.ldt; idt = Hashtbl.copy s.idt; data = ds; reg = get_segments a ctx  }

    let get_base_address s c =
        if !Config.mode = Config.Protected then
            let dt = if c.ti = GDT then s.segments.gdt else s.segments.ldt in
            try
                let e = Hashtbl.find dt c.index in
                if c.rpl <= e.dpl then
                    e.base
                else
                    error s.a "illegal requested privileged level"
            with Not_found ->
                error s.a (Printf.sprintf "illegal requested index %s in %s Description Table" (Word.to_string c.index) (if c.ti = GDT then "Global" else "Local"))
        else
            error s.a "only protected mode supported"


    let add_segment s e sreg =
        let m      = Hashtbl.find s.segments.reg sreg in
        let ds_val = get_base_address s m             in
        if Z.compare ds_val Z.zero = 0 then
            e
        else
            BinOp(Add, e, const_of_Z ds_val s.operand_sz)

    let add_data_segment s e = add_segment s e s.segments.data

    (************************************************************************************)
    (* common utilities *)
    (************************************************************************************)

    (** returns the right Asm.reg value from the given register and context of decoding *)
    let to_reg r sz =
        if Register.size r = sz then
            T r
        else
            P (r, 0, sz-1)

    (** returns the right Asm.reg value from the register corresponding to the given number and context of decoding *)
    let find_reg n sz =
        let r = Hashtbl.find register_tbl n in
        to_reg r sz

    (** returns the right Lval from the register corresponding to the given number and context of decoding *)
    let find_reg_lv n sz =
        Lval ( V ( find_reg n sz ) )

    (** returns the right V from the register corresponding to the given number and context of decoding *)
    let find_reg_v n sz =
        V ( find_reg n sz )

    (** returns the slice from 8 to 15 of the given register index *)

    let get_h_slice n =
      let r = Hashtbl.find register_tbl n in
      P (r, 8, 15)


    (************************************************)
    (* MOD REG R/M *)
    (************************************************)

    (** [mod_nnn_rm v] split from v into the triple (mod, nnn, rm) where mod are its bits 7-6, nnn its bits 5,4,3 and rm its bits 2, 1, 0 *)
    let mod_nnn_rm v =
        let rm 	= v land 7	   in
        let nnn = (v lsr 3) land 7 in
        let md 	= (v lsr 6)	   in
        md, nnn, rm

    (** returns the sub expression used in a displacement *)
    let disp s nb sz =
        get_imm s nb sz true 

    (** returns the expression associated to a sib *)
    let sib s md =
        let c 		       = getchar s                in
        let scale, index, base = mod_nnn_rm (Char.code c) in
        let base' =
            let lv = find_reg_lv base s.addr_sz in
            match md with
            | 0 -> if base = 5 then
                  (* [scaled index] + disp32 *)
                  disp s 32 s.addr_sz
              else
                  lv
            (* [scaled index] + disp8 *)
            | 1 -> BinOp (Add, lv, disp s 8 s.addr_sz)
            (* [scaled index] + disp32 *)
            | 2 -> BinOp (Add, lv, disp s 32 s.addr_sz)
            | _ -> error s.a "Decoder: illegal value in sib"
        in
        let index_lv = find_reg_lv index s.addr_sz in
        if index = 4 then
            base'
        else
            let scaled_index =
                if scale = 0 then
                    index_lv
                else
                    BinOp (Shl, index_lv, const scale s.addr_sz)
            in
            BinOp (Add, base', scaled_index)

    (** returns the statements for a memory operation encoded in _md_ _rm_ *)
    let md_from_mem s md rm sz =
        let rm_lv = find_reg_lv rm s.addr_sz in
        if rm = 4 then
            sib s md
        else
            match md with
            | 0 ->
              begin
                  match rm with
                  | 5 -> disp s s.addr_sz s.addr_sz
                  | _ -> rm_lv
              end
            | 1 -> 
              BinOp (Add, rm_lv, UnOp(SignExt s.addr_sz, disp s 8 sz))

            | 2 ->
              BinOp (Add, rm_lv, disp s s.addr_sz s.addr_sz)
            | _ -> error s.a "Decoder: illegal value in md_from_mem"

    (** returns the statements for a mod/rm with _md_ _rm_ *)
    let exp_of_md s md rm sz mem_sz =
        match md with
        | n when 0 <= n && n <= 2 -> M (add_data_segment s (md_from_mem s md rm sz), mem_sz)
        | 3 ->
            (* special case for ah ch dh bh *)
            if sz = 8 && rm >= 4 then
                V (get_h_slice (rm-4))
            else
                V (find_reg rm sz)
        | _ -> error s.a "Decoder: illegal value for md in mod_reg_rm extraction"

    let operands_from_mod_reg_rm_core s sz ?(mem_sz=sz) dst_sz  =
        let c = getchar s in
        let md, reg, rm = mod_nnn_rm (Char.code c) in
        let reg_v =
            if dst_sz = 8 && reg >= 4 then
                V (get_h_slice (reg-4))
            else
                find_reg_v reg dst_sz in
        let rm' = exp_of_md s md rm sz mem_sz in
	reg_v, rm'
	  
    let operands_from_mod_reg_rm s sz ?(dst_sz = sz) direction =
      let reg_v,rm' =  operands_from_mod_reg_rm_core s sz dst_sz in
      if direction = 0 then
        rm', Lval reg_v
      else
        reg_v, Lval rm'

    let lea s =
        let c = getchar s in
        let md, reg, rm = mod_nnn_rm (Char.code c) in
        if md = 3 then
            error s.a "Illegal mod field in LEA"
        else
            let reg_v = find_reg_v reg s.operand_sz in
            let src = md_from_mem s md rm s.addr_sz in
            let src'=
                if s.addr_sz < s.operand_sz then
                    UnOp(ZeroExt s.addr_sz, src)
                else src
            in
            return s [ Set(reg_v, src') ]

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

    (** produce the statement to set the overflow flag according to the current operation whose operands are op1 and op2 and result is res *)
    let overflow_flag_stmts sz res op1 op op2 =
        (* flag is set if both op1 and op2 have the same nth bit whereas different from the hightest bit of res *)
      let nth = (const (sz-1) sz) in
      let b1        = Const (Word.one sz)          in
      let sign_res  = BinOp(And, BinOp (Shr, res, nth), b1) in
      let sign_op1  = BinOp(And, BinOp (Shr, op1, nth), b1) in
      let sign_op2  = BinOp(And, BinOp (Shr, op2, nth), b1) in
      let cmp_op = 
	match op with
	| Add -> EQ
	| Sub -> NEQ
	| _ -> raise (Invalid_argument "unexpected operation in overflow flag computation") in
      let c1 	      = Cmp (cmp_op, sign_op1, sign_op2)   	      in
      let c2 	      = Cmp (NEQ, sign_res, sign_op1)         in
      Set(V (T fof), (TernOp (BBinOp (LogAnd, c1, c2), Asm.Const (Word.one fof_sz), Asm.Const (Word.zero fof_sz))))
      
    (** produce the statement to set the given flag *)
    let set_flag f = Set (V (T f), Const (Word.one (Register.size f)))

    (** produce the statement to clear the given flag *)
    let clear_flag f = Set (V (T f), Const (Word.zero (Register.size f)))

    (** produce the statement to undefine the given flag *)
    let undef_flag f = Directive (Forget (V (T f)))

    (** produce the statement to set the carry flag according to the current operation whose operands are op1 and op2 and result is res *)
    let carry_flag_stmts sz op1 op op2 =
      (* fcf is set if the sz+1 bit of the result is 1 *)
      let sz' = sz+1 in
      let s 	 = ZeroExt (sz')	  in
      let op1' = UnOp (s, op1)	  in
      let op2' = UnOp (s, op2)	  in
      let res' = BinOp (op, op1', op2') in
      let shifted_res = BinOp (Shr, res', Const (Word.of_int (Z.of_int sz) (sz'))) in
      let one = Const (Word.one sz') in
      let n = Register.size fcf in
      Set (V (T fcf), TernOp( Cmp (EQ, shifted_res, one), Asm.Const (Word.one n), Asm.Const (Word.zero n )))

    let carry_flag_stmts_3 sz op1 op op2 op3 =
      (* fcf is set if the sz+1 bit of the result is 1 *)
      let sz' = sz+1 in
      let s 	 = ZeroExt (sz')	  in
      let op1' = UnOp (s, op1)	  in
      let op2' = UnOp (s, op2)	  in
      let op3' = UnOp (s, op3)	  in
      let res' = BinOp(op, BinOp (op, op1', op2'), op3') in
      let shifted_res = BinOp (Shr, res', Const (Word.of_int (Z.of_int sz) (sz'))) in
      let one = Const (Word.one sz') in
      let n = Register.size fcf in
      Set (V (T fcf), TernOp( Cmp (EQ, shifted_res, one), Asm.Const (Word.one n), Asm.Const (Word.zero n)))

    (** produce the statement to set the sign flag wrt to the given parameter *)
    let sign_flag_stmts sz res =
      let c = Cmp (EQ, const 1 sz, BinOp(Shr, res, const (sz-1) sz)) in
      let n = Register.size fsf in
      Set (V (T fsf), TernOp (c, Asm.Const (Word.one n), Asm.Const (Word.zero n)))

    (** produce the statement to set the zero flag *)
    let zero_flag_stmts sz res =
      let c = Cmp (EQ, res, Const (Word.zero sz)) in
      let n = Register.size fzf in
        Set (V (T fzf), TernOp (c, Asm.Const (Word.one n), Asm.Const (Word.zero n)))

    (** produce the statement to set the adjust flag wrt to the given parameters.
     faf is set if there is an overflow on the 4th bit *)
    let adjust_flag_stmts sz op1 op op2 =
      let word_0f = const 0xf sz in
      let word_4 = const 4 8 in
      let one = const 1 sz in
      let op1' = BinOp (And, op1, word_0f)	  in
      let op2' = BinOp (And, op2, word_0f)	  in
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

    (**************************************************************************************)
    (* State generation of binary logical/arithmetic operations *)
    (**************************************************************************************)

    (** produces the list of states for for ADD, SUB, ADC, SBB depending on
	the value of the operator and the boolean value (=true for carry or borrow) *)
    let add_sub s op use_carry dst src sz =
        let name 	= Register.fresh_name ()	    in
        let res_reg	= Register.make ~name:name ~size:sz in
        let res = V (T res_reg) in
        let res_cf_stmts = if use_carry then
                let carry_ext = UnOp (ZeroExt sz, Lval (V (T fcf))) in
                [ Set(res, BinOp(op, BinOp(op, Lval dst, src), carry_ext)) ; (* dst-src-cf *)
                  carry_flag_stmts_3 sz (Lval dst) op src (Lval (V (T fcf)))]
            else
                [ Set(res, BinOp(op, Lval dst, src)) ;
                  carry_flag_stmts sz (Lval dst) op src ; ] in
        return s
            (res_cf_stmts @ [
                 adjust_flag_stmts_from_res sz (Lval dst) src (Lval res) ;
                 overflow_flag_stmts sz (Lval res) (Lval dst) op src ;
                 zero_flag_stmts sz (Lval res) ;
                 sign_flag_stmts sz (Lval res) ;
                 parity_flag_stmts sz (Lval res) ;
                 Set(dst, Lval res) ;
                 Directive (Remove res_reg)
             ])


    (** produces the state corresponding to an add or a sub with an immediate operand *)
    let add_sub_immediate s op b r sz =
        let r'  = V (to_reg r sz)                                       in
        (* TODO : check if should sign extend *)
        let w   = get_imm s sz s.operand_sz false in
        add_sub s op b r' w sz


    let cmp_stmts e1 e2 sz =
        let tmp         = Register.make (Register.fresh_name ()) sz in
        let res         = Lval (V (T tmp))                          in
        let flag_stmts =
            [
                carry_flag_stmts sz e1 Sub e2; overflow_flag_stmts sz res e1 Sub e2; zero_flag_stmts sz res;
                sign_flag_stmts sz res           ; parity_flag_stmts sz res     ; adjust_flag_stmts sz e1 Sub e2
            ]
        in
        let set = Set (V (T tmp), BinOp (Sub, e1, e2)) in
        (set::(flag_stmts)@[Directive (Remove tmp)])

    (** returns the states for OR, XOR, AND depending on the the given operator *)
    let or_xor_and s op dst src sz =
        let res   = Set (dst, BinOp(op, Lval dst, src)) in
        let res'  = Lval dst			        in
        let flag_stmts =
            [
                clear_flag fcf; clear_flag fof; zero_flag_stmts sz res';
                sign_flag_stmts sz res';
                parity_flag_stmts sz res'; undef_flag faf
            ]
        in
        return s (res::flag_stmts)

    let or_xor_and_eax s op sz imm_sz =
        let eax = find_reg_v 0 sz in
        let imm = get_imm s imm_sz sz false in
            or_xor_and s op eax imm sz

    let or_xor_and_mrm s op sz direction =
        let dst, src = operands_from_mod_reg_rm s sz direction in
        or_xor_and s op dst src sz

    let test_stmts dst src sz =
        let name 	= Register.fresh_name ()	    in
        let v  	 	= Register.make ~name:name ~size:sz in
        let tmp  	= V (T v)		  	    in
        let tmp_calc   = Set (tmp, BinOp(And, Lval dst, src)) in
	L.debug (fun p -> p "%s" (Asm.string_of_stmt tmp_calc true));
	let tmp' = Lval tmp in
        let flag_stmts =
            [
                clear_flag fcf; clear_flag fof; zero_flag_stmts sz tmp';
                sign_flag_stmts sz tmp';
                parity_flag_stmts sz tmp'; undef_flag faf
            ]
        in
        ([tmp_calc] @ flag_stmts @ [ Directive (Remove v) ])

    let inc_dec reg op s sz =
        let dst 	= reg                               in
        let name        = Register.fresh_name ()            in
        let v           = Register.make ~name:name ~size:sz in
        let tmp         = V (T v)			    in
        let op1         = Lval tmp			    in
        let op2         = const 1 sz                        in
        let res         = Lval dst			    in
        let flags_stmts =
            [
                overflow_flag_stmts sz res op1 op op2   ; zero_flag_stmts sz res;
                parity_flag_stmts sz res; adjust_flag_stmts sz op1 op op2;
                sign_flag_stmts sz res
            ]
        in
        let stmts =
            [ Set(tmp, Lval dst); Set (dst, BinOp (op, Lval dst, op2)) ] @
            flags_stmts @ [Directive (Remove v)]
        in
        return s stmts

    (*********************************************************************************************)
    (* Prefix management *)
    (*********************************************************************************************)
    type prefix_opt =
        Jcc_i
      | Esc
      | Str

    let is_register_set stmts r =
        let is_set stmt =
            match stmt with
            | Set (V (T r'), _) | Set (V (P(r', _, _)), _) -> Register.compare r r' = 0
            | _ 						 -> false
        in
        List.exists is_set stmts



    (******************************************************************************************************)
    (* Generation of state for string manipulation                                                        *)
    (******************************************************************************************************)
    (** common inc/dec depending on value of df in instructions SCAS/STOS/CMPS/MOVS *)
    let inc_dec_wrt_df regs i =
        let inc_dec op r sz =
            let c = const (i / 8) sz in
            Set (r, BinOp (op, Lval r, c))
        in
        let istmts, estmts =
            List.fold_left (fun (istmts, estmts) r ->
                let r' = V (T r)         in
                let sz = Register.size r in
                (inc_dec Add r' sz)::istmts, (inc_dec Sub r' sz)::estmts) ([], []) regs
        in
        [ If ( Cmp (EQ, Lval (V (T fdf)), Const (Word.zero fdf_sz)), istmts, estmts) ]

    (** state generation for MOVS *)
    let taint_cmps_movs s i =
      Directive (Taint (Some (BinOp (Or, Lval (M (Lval (V (to_reg edi s.addr_sz)), i)), Lval (M (Lval (V (to_reg esi s.addr_sz)), i)))), V (T ecx)))
	
    let movs s i =
        let edi'  = V (to_reg edi s.addr_sz)            in
        let esi'  = V (to_reg esi s.addr_sz)            in
        let medi' = M (add_segment s (Lval edi') ds, i) in
        let mesi' = M (add_segment s (Lval esi') es, i) in
        return s ((Set (medi', Lval mesi'))::(taint_cmps_movs s i)::(inc_dec_wrt_df [edi ; esi] i))

    (** state generation for CMPS *)
    let cmps s i =
        let edi'  = V (to_reg edi s.addr_sz)            in
        let esi'  = V (to_reg esi s.addr_sz)            in
        let medi' = M (add_segment s (Lval edi') ds, i) in
        let mesi' = M (add_segment s (Lval esi') es, i) in
        return s ((cmp_stmts (Lval medi') (Lval mesi') i) @ ((taint_cmps_movs s i)::(inc_dec_wrt_df [edi ; esi] i)))

    (** state generation for LODS *)
    let lods s i =
        let eax'  = V (to_reg eax i)                    in
        let esi'  = V (to_reg esi s.addr_sz)            in
        let mesi' = M (add_segment s (Lval esi') es, i) in
	let taint_stmt = Directive (Taint (Some (BinOp (Or, Lval (V (to_reg eax i)), Lval (M (Lval (V (to_reg esi s.addr_sz)), 8)))), V (T ecx))) in
        return s ((Set (eax', Lval mesi'))::taint_stmt::(inc_dec_wrt_df [esi] i))

    (** state generation for SCAS *)
    let scas s i =
        let eax' = V (to_reg eax i)                    in
        let edi' = V (to_reg edi s.addr_sz)            in
        let mem  = M (add_segment s (Lval edi') es, i) in
	let taint_stmt =
	  Directive (Taint (Some (BinOp (Or, Lval (V (to_reg eax i)), Lval (M (Lval (V (to_reg edi s.addr_sz)), i)))), V (T ecx))) in
	let typ = Types.T (TypedC.Int (Newspeak.Unsigned, i)) in
	let type_stmt = Directive (Type (mem, typ)) in 
        return s ((cmp_stmts (Lval eax') (Lval mem) i) @ [type_stmt ; taint_stmt] @ (inc_dec_wrt_df [edi] i) )


    (** state generation for STOS *)
    let stos s i =
        let eax'  = V (to_reg eax i)                     in
        let edi'  = V (to_reg edi s.addr_sz)             in
        let medi' = M (add_segment s (Lval edi') ds, i)  in
        let stmts = Set (medi', Lval eax')               in
	let taint_stmt = Directive (Taint (Some ((BinOp (Or, Lval (V (to_reg eax i)), Lval (M (Lval (V (to_reg edi s.addr_sz)), i))))), V (T ecx))) in
        return s (stmts::taint_stmt::(inc_dec_wrt_df [edi] i))

    (** state generation for INS *)
    let taint_ins_outs s i =
      Directive (Taint (Some (BinOp (Or, Lval (M (Lval (V (to_reg edi s.addr_sz)), i)), Lval (M (Lval (V (to_reg esi s.addr_sz)), i)))), V (T ecx)))
	
    let ins s i =
        let edi' = V (to_reg edi s.addr_sz)     in
        let edx' = V (to_reg edx i)             in
        let m    = add_segment s (Lval edi') es in
        return s ((Set (M (m, i), Lval edx'))::(taint_ins_outs s i)::(inc_dec_wrt_df [edi] i))

    (** state generation for OUTS *)
    let outs s i =
        let edi' = V (to_reg edi s.addr_sz)     in
        let edx'  = V (to_reg edx i)             in
        let m     = add_segment s (Lval edi') es in
        return s ((Set (edx', Lval (M (m, i))))::(taint_ins_outs s i)::(inc_dec_wrt_df [edi] i))

    (*************************)
    (* State generation for loading far pointers *)
    (*************************)
    let load_far_ptr s sreg =
        let sreg' 	     = V (T sreg)						     in
        let _mod, reg, _rm = mod_nnn_rm (Char.code (getchar s))			     in
        let reg'           = find_reg reg s.operand_sz			 	     in
        let src 	     = get_imm s s.operand_sz s.operand_sz false in
        let src' 	     = add_segment s src s.segments.data			     in
        let off 	     = BinOp (Add, src', const (s.operand_sz /8) s.addr_sz) in
        return s [ Set (V reg', Lval (M (src', s.operand_sz))) ; Set (sreg', Lval (M (off, 16)))]

    (****************************************************)
    (* State generation for loop, call and jump instructions *)
    (****************************************************)
    (** returns the asm condition of jmp statements from an expression *)
    let exp_of_cond v s =
        let eq f  = Cmp (EQ, Lval (V (T f)), const 1 1)  in
        let neq f = Cmp (NEQ, Lval (V (T f)), const 1 1) in
        match v with
        | 0  -> eq fof
        | 1  -> neq fof
        | 2  -> eq fcf
        | 3  -> neq fcf
        | 4  -> eq fzf
        | 5  -> neq fzf
        | 6  -> BBinOp (LogOr, eq fcf, eq fzf)
        | 7  -> BBinOp (LogAnd, neq fcf, neq fzf)
        | 8  -> eq fsf
        | 9  -> neq fsf
        | 10 -> eq fpf
        | 11 -> neq fpf
        | 12 -> (* sf <> of *) Cmp (NEQ, Lval (V (T fsf)), Lval (V (T fof)))
        | 13 -> (* not (sf <> of) = sf = of *) Cmp (EQ, Lval (V (T fsf)), Lval (V (T fof)))
        | 14 -> (* sf <> of || zf == 1 *) BBinOp (LogOr, Cmp (NEQ, Lval (V (T fsf)), Lval (V (T fof))), eq fzf)
        | 15 -> (* GT : zf == 0 && sf == of *) BBinOp (LogAnd, Cmp (EQ, Lval (V (T fsf)), Lval (V (T fof))), neq fzf)
        | _  -> error s.a "Opcode.exp_of_cond: illegal value"



    (** checks that the target is within the bounds of the code segment *)
    let check_jmp (s: state) target =
        let a = s.a in
        let csv = Hashtbl.find s.segments.reg cs						     in
        let seg : tbl_entry  = Hashtbl.find (if csv.ti = GDT then s.segments.gdt else s.segments.ldt) csv.index in
        (* compute limit according to granularity *)
        let limit = if (Z.compare seg.gran Z.zero) == 0 then seg.limit else (Z.shift_left seg.limit 12) in
        let target_int   = Address.to_int target							     in
        let linear_target = (Z.add seg.base target_int) in
        if Z.compare linear_target limit < 0 then
            ()
        else
            error a (Printf.sprintf "Decoder: jump target (%s) out of limits of the code segment (%s) (GP exception in protected mode)" (Z.to_string linear_target) (Z.to_string limit))

    (** [return_jcc_stmts s e] returns the statements for conditional jumps: e is the condition and o the offset to add to the instruction pointer *)
    let return_jcc_stmts s cond_exp imm_sz =
        let o  = get_imm_int s imm_sz s.addr_sz true in
        let ip = Address.add_offset s.a (Z.of_int s.o) in
        let a' = Address.add_offset ip o in
        check_jmp s a';
        check_jmp s ip;
        return s [ If (cond_exp, [ Jmp (A a') ], [Jmp (A ip)]) ]

    (** jump statements on condition *)
    let jcc s cond imm_sz =
        let cond_exp = exp_of_cond cond s in
        return_jcc_stmts s cond_exp imm_sz


    (** jump if eCX is zero *)
    let jecxz s =
        let ecx' = to_reg ecx s.addr_sz				   in
        let e    = Cmp (EQ, Lval (V ecx'), Const (Word.zero s.addr_sz)) in
        return_jcc_stmts s e 8

    (** common behavior between relative jump and relative call *)
    let relative s off_sz sz =
        let delta = get_imm_int s off_sz sz true in
        let a' = Address.add_offset s.a (Z.add (Z.of_int s.o) delta) in
        check_jmp s a';
        a'

    (** unconditional jump by adding an offset to the current ip *)
    let relative_jmp s off_sz =
        let a' = relative s off_sz s.operand_sz in
        return s [ Jmp (A a') ]

    (** common statement to move (a chunk of) esp by a relative offset *)
    let set_esp op esp' n =
        Set (V esp', BinOp (op, Lval (V esp'), const (n / 8) !Config.stack_width))


    let call s t =
        let cesp = M (Lval (V (T esp)), !Config.stack_width)   in
        (* call destination *)
        let ip' = Data.Address.add_offset s.a (Z.of_int s.o) in
        let ip   = Const (Data.Address.to_word ip' s.operand_sz) in
        let stmts =
            [
                set_esp Sub (T esp) !Config.stack_width;
                Set (cesp, ip);
                Call t
            ]
        in
        return s stmts

    (** call with target as an offset from the current ip *)
    let relative_call s off_sz =
      let a = relative s off_sz s.operand_sz in
        call s (A a)

    (** statements of jump with absolute address as target *)
    let direct_jmp s =
        let sz = Register.size cs            in
        let v  = int_of_bytes s sz           in
        let v' = get_segment_register_mask v in
        (* check properties on the requested segment loading: type of segment + privilege level *)
        begin
            try
                let dt = if v'.ti = GDT then s.segments.gdt else s.segments.ldt in
                let e  = Hashtbl.find dt v'.index                               in
                if e.dpl = v'.rpl then
                    if e.typ = Code_e || e.typ = Code_ea || e.typ = Code_ea
                       || e.typ = Code_er || e.typ = Code_era || e.typ = Code_ec || e.typ = Code_eca ||
                       e.typ = Code_erc || e.typ = Code_erca then
                        ()
                    else
                        error s.a "decoder: tried a far jump into non code segment"
                else error s.a "Illegal segment loading (privilege error)"
            with _ -> error s.a "Illegal segment loading request (illegal index in the description table)"
        end;
        Hashtbl.replace s.segments.reg cs v';
        let a  = int_of_bytes s (s.operand_sz / 8) in
        let o  = Address.of_int Address.Global a s.operand_sz        in
        let a' = Address.add_offset o v                              in
        check_jmp s a';
        (* returns the statements : the first one enables to update the interpreter with the new value of cs *)
        return s [ Set (V (T cs), const_of_Z v (Register.size cs)) ; Jmp (A a') ]

    (* statements for LOOP/LOOPE/LOOPNE *)
    let loop s c =
        let ecx' = V (if Register.size ecx = s.addr_sz then T ecx else P (ecx, 0, s.addr_sz-1)) in
        let dec_stmt  = Set (ecx', BinOp(Sub, Lval ecx', Const (Word.one s.addr_sz))) in
        let a' = relative s 8 s.operand_sz in
        let fzf_cond cst = Cmp (EQ, Lval (V (T fzf)), Const (cst fzf_sz)) in
        let ecx_cond = Cmp (NEQ, Lval ecx', Const (Word.zero s.addr_sz)) in
        let cond =
            match c with
            | '\xe0' -> BBinOp (LogAnd, fzf_cond Word.zero, ecx_cond)
            | '\xe1' -> BBinOp (LogAnd, fzf_cond Word.one, ecx_cond)
            | '\xe2' -> ecx_cond
            | _      -> error s.a "Unexpected use of Decoder.loop"
        in
        return s [ dec_stmt ; If (cond, [Jmp (A (a'))], [ Jmp (A (Address.add_offset s.a (Z.of_int s.o)))]) ]

    (*******************)
    (* push/pop        *)
    (*******************)
    let is_segment lv =
        match lv with
        | V (T r) | V (P(r, _, _)) ->
          Register.compare r cs = 0 || Register.compare r ds = 0
          || Register.compare r ss = 0 || Register.compare r es = 0
          || Register.compare r fs = 0 || Register.compare r gs = 0
        | _ -> false

    let is_esp lv =
        match lv with
        | V (T r) | V (P(r, _, _)) -> Register.compare r esp = 0
        | _                        -> false

    (** builds a left value from esp which is consistent with the stack width *)
    let esp_lval () = if !Config.stack_width = Register.size esp then T esp else P(esp, 0, !Config.stack_width-1)

    (** common value used for the decoding of push and pop *)
    let size_push_pop lv sz = if is_segment lv then !Config.stack_width else sz

    (** returns true whenever the left value contains the stack register *)
    let with_stack_pointer a lv =
        let rec has e =
            match e with
            | UnOp (_, e') -> has e'
            | BinOp (_, e1, e2) -> (has e1) || (has e2)
            | Lval lv -> in_lv lv
            | _ -> false
        and in_lv lv =
            match lv with
            | M (e, _) -> has e
            | V (T r) | V (P (r, _, _)) -> if Register.compare r cs = 0 then error a "Illegal POP CS"; Register.is_stack_pointer r
        in
        in_lv lv

    (* replace all occurence of prev_reg by new_reg into lv *)
    let replace_reg lv prev_reg new_reg =
      let rec replace_lv lv =
	match lv with
	 | M (e, n) -> M (replace_exp e, n)
         | V (T r) when Register.compare r prev_reg = 0 -> V (T new_reg)
	 | V (P (r, l, u)) when Register.compare r prev_reg = 0 -> V (P (new_reg, l, u)) 
	 | _ -> lv  
      and replace_exp e =
	match e with
	| Lval lv -> Lval (replace_lv lv)
	| UnOp(op, e) -> UnOp (op, replace_exp e)
	| BinOp (op, e1, e2) -> BinOp (op, replace_exp e1, replace_exp e2)
	| _ -> e
      in
      replace_lv lv
      
	  
	     
    (** statements generation for pop instructions *)
    let pop_stmts s lv =
        let esp'  = esp_lval () in
        List.fold_left (fun stmts lv ->
            let n = size_push_pop lv s.addr_sz in
            let incr = set_esp Add esp' n in
            if with_stack_pointer s.a lv then
                [ incr ; Set (lv, Lval (M (BinOp (Sub, Lval (V esp'), const (n/8) s.operand_sz), s.operand_sz))) ] @ stmts

            else
                [ Set (lv, Lval (M (Lval (V esp'), s.operand_sz))) ; incr ] @ stmts
        ) [] lv

    (** state generation for the pop instructions *)
    let pop s lv = return s (pop_stmts s lv)

    let popf s sz =
        let name        = Register.fresh_name ()            in
        let v           = Register.make ~name:name ~size:sz in
        let tmp         = V (T v)			    in
            let stmt = set_eflags v in
            let popst = pop_stmts s [tmp] in
            return s (popst @ stmt @ [Directive (Remove v)])

    (** generation of statements for the push instructions *)
    let push_stmts (s: state) v =
        let esp' = esp_lval () in
        let t    = Register.make (Register.fresh_name ()) (Register.size esp) in
        (* in case esp is in the list, save its value before the first push (this is this value that has to be pushed for esp) *)
        (* this is the purpose of the pre and post statements *)
        let pre, post=
          if List.exists (with_stack_pointer s.a) v then
              [ Set (V (T t), Lval (V esp')) ], [ Directive (Remove t) ]
            else
                [], []
        in
   
        let stmts =
            List.fold_left (
                fun stmts lv ->
                    let n = size_push_pop lv s.addr_sz in
                    let st =
                        if with_stack_pointer s.a lv then
                            (* save the esp value to its value before the first push (see PUSHA specifications) *)
                            Set (M (Lval (V esp'), s.operand_sz), Lval (replace_reg lv esp t))
                        else
                            Set (M (Lval (V esp'), s.operand_sz), Lval lv);
                    in
                    [ set_esp Sub esp' n ; st ] @ stmts

            ) [] v
        in
        (pre @ stmts @ post)

    (** state generation for the push instructions *)
    let push s v = return s (push_stmts s v)

    (** returns the state for the push of an immediate operands. _sz_ in bits *)
    let push_immediate s sz =
        let c     = get_imm s sz !Config.stack_width true in
        let esp'  = esp_lval ()						       in
        let stmts = [ set_esp Sub esp' !Config.stack_width ; Set (M (Lval (V esp'), !Config.stack_width), c) ]
        in
        return s stmts

    let pushf s sz =
        let name        = Register.fresh_name ()            in
        let v           = Register.make ~name:name ~size:sz in
        let tmp         = V (T v)			    in
        let e = get_eflags () in
        let e' =
            if sz = 32 then
                (* if sz = 32 should AND EFLAGS with 00FCFFFFH) *)
                BinOp(And, e, const 0x00FCFFFF 32)
            else e
        in
        let stmt = [Set(tmp, e')] in
        return s (stmt @ (push_stmts s [tmp]) @ [Directive (Remove v)])

    (** returns the state for the mov from immediate operand to register. The size in byte of the immediate is given as parameter *)
    let mov_immediate s sz =
        let dst, _ = operands_from_mod_reg_rm s sz 0 in
        let imm = get_imm s sz sz false in
        return s [ Set (dst, imm) ]

    (** returns the the state for the mov from/to eax *)
    let mov_with_eax s n from =
        let imm = int_of_bytes s (n/8) in
        let leax = V (to_reg eax n) in
        let lmem = M (add_segment s (const_of_Z imm s.addr_sz) s.segments.data, n) in
        let dst, src =
            if from then lmem, Lval leax
            else leax, Lval lmem
        in
        return s [Set (dst, src)]

    (** [cmovcc s cond] returns the statements for cond. mov : cond is the condition *)
    let cmovcc s cond =
        let dst, src  = operands_from_mod_reg_rm s s.operand_sz 1 in
        let cond_stmt = exp_of_cond cond s in
        return s [ Set(dst, TernOp (cond_stmt, src , (Lval dst) )) ]

    (*******************************)
    (* multiplication and division *)
    (*******************************)

    (* Generic multiplication statements for implicit destination registers.
       Multiply EAX/AX/AL with src with destination EDX:EAX/DX:AX/AX.
       op is either Mul or Imul for unsigned / signed multiplication *)
    let mul_stmts op src sz =
        let eax_r = (to_reg eax sz) in let eax_lv = Lval( V (eax_r)) in
        let edx_r = (to_reg edx sz) in
        let tmp   = Register.make ~name:(Register.fresh_name()) ~size:(sz*2) in
        let mul_s =
            if sz = 8 (* dest = AX *) then begin
                [ Set(V(to_reg eax 16), BinOp(op, eax_lv, src));
                  Set(V(T tmp), Lval(V(to_reg eax 16)))] (* for flags *)
            end else begin
                (* dest is split over (E)DX:(E)AX *)
                [ Set(V(T tmp), BinOp(op, eax_lv, src));
                  Set (V(eax_r), Lval (V (P (tmp, 0, sz-1))));
                  Set (V(edx_r), Lval (V (P (tmp, sz, sz*2-1))));
                ]
            end in
        let clr_f = [clear_flag fcf; clear_flag fof] in
        let set_f = [set_flag fcf; set_flag fof] in 
        let flags_stmts =
            if op = Mul then begin
                (* The OF and CF flags are set to 0 if the upper half of the result
                   is 0; otherwise, they are set to 1.  *)
                [ If(Cmp(EQ, Const (Word.zero sz), Lval (V( P(tmp, sz, sz*2-1)))),
                    clr_f, set_f) ]
            end else begin (* IMul *) 
                (* The OF and CF flags are set to 0 if the full size result (tmp) equals
                   the src size result; otherwise, they are set to 1.  *)
                if sz = 8  then begin (* AL == AX *)
                    [  If(Cmp(EQ, Lval (V(to_reg eax 16)), UnOp(SignExt 16, Lval(V(to_reg eax 8)))),
                        clr_f, set_f) ]
                end else begin (* SignExt((E)AX) == (E)DX:(E)AX *)
                    [ If(Cmp(EQ, Lval(V(T tmp)), UnOp(SignExt (sz*2), Lval(V(eax_r)))),
                        clr_f, set_f) ]
                end
            end in
        mul_s @ [ undef_flag fsf;  undef_flag fzf; undef_flag faf; undef_flag fpf; ] @ flags_stmts @ [ Directive (Remove tmp) ]

    (* Signed multiplication with explicit destination register *)
    let imul_stmts s (dst:Asm.lval) (src1:Asm.exp) (src2:Asm.exp) =
        let tmp   = Register.make ~name:(Register.fresh_name()) ~size:(s.operand_sz*2) in
        let imul_s = [ Set(V(T tmp), BinOp(IMul, src1, src2));
                       Set(dst, Lval(V(P(tmp, 0, s.operand_sz-1)))) ] in
        let flags_stmts =
            [   undef_flag fsf;  undef_flag fzf; undef_flag faf; undef_flag fpf;
                (* The OF and CF flags are set to 0 if the full size result (tmp) equals
                   the normal size result; otherwise, they are set to 1.  *)
                If(Cmp(EQ, Lval(V(T tmp)), UnOp(SignExt (s.operand_sz*2), Lval dst)),
                    [clear_flag fcf; clear_flag fof],
                    [set_flag fcf; set_flag fof])
            ] in
        return s (imul_s @ flags_stmts @ [ Directive (Remove tmp) ])

    let div_stmts (reg : Asm.exp) sz signed =
        (* Useful boundaries for flags *)
        let min_int_z = (Z.of_int (1 lsl (sz-1))) in
        let min_int_const = (Const (Word.of_int min_int_z (sz*2))) in
        let max_int_z = (Z.sub min_int_z Z.one) in
        let max_int_const = (Const (Word.of_int max_int_z (sz*2))) in

	let remainder_r = if sz = 8 then (P (eax, 8, 15)) else (to_reg edx sz) in
        let divisor = if sz = 8
          then Lval (V (to_reg eax 16))
          else let eax_ext = UnOp(ZeroExt (sz*2), Lval (V (to_reg eax sz))) in
               let edx_ext = UnOp(ZeroExt (sz*2), Lval (V (to_reg edx sz))) in
               BinOp(Or, BinOp(Shl, edx_ext, const sz (2*sz)), eax_ext) in
        let quotient = to_reg eax sz in

        let tmp   = Register.make ~name:(Register.fresh_name()) ~size:(sz*2) in
        let tmp_div   = Register.make ~name:(Register.fresh_name()) ~size:(sz*2) in
        let op_div,op_mod = if signed then Div,Mod else IDiv,IMod in

        [ Assert (BBinOp(LogOr,
                         Cmp(GT, Lval( V (T tmp_div)), max_int_const),
                         Cmp(LT, Lval( V (T tmp_div)), min_int_const)),
                  "Divide error");
          Set (V (T tmp), divisor);
          Set (V (T tmp_div), BinOp(op_div, Lval (V (T tmp)), reg));
          (* compute remainder *)
          Set (V remainder_r, BinOp(op_mod, Lval(V(T tmp)), reg));
          Set (V quotient, Lval (V (P (tmp_div, 0, sz-1))));
          Directive (Remove tmp);
          Directive (Remove tmp_div) ]


    (*****************************************************************************************)
    (* decoding of opcodes of groups 1 to 8 *)
    (*****************************************************************************************)

    let core_grp s sz =
        let md, nnn, rm = mod_nnn_rm (Char.code (getchar s)) in
        let dst 	= exp_of_md s md rm sz sz	     in
        nnn, dst

    let grp1 s reg_sz imm_sz =
        let nnn, dst = core_grp s reg_sz in
        let imm = get_imm s imm_sz reg_sz true in
        (* operation is encoded in bits 5,4,3 *)
        match nnn with
        | 0 -> add_sub s Add false dst imm reg_sz
        | 1 -> or_xor_and s Or dst imm reg_sz
        | 2 -> add_sub s Add true dst imm reg_sz
        | 3 -> add_sub s Sub true dst imm reg_sz
        | 4 -> or_xor_and s And dst imm reg_sz
        | 5 -> add_sub s Sub false dst imm reg_sz
        | 6 -> or_xor_and s Xor dst imm reg_sz
        | 7 -> return s (cmp_stmts (Lval dst) imm reg_sz)
        | _ -> error s.a "Illegal nnn value in grp1"

    (* SHL *)
    let shift_l_stmt dst sz n =
        let sz' = const sz 8 in
        let one8 = Const (Word.one 8) in
        let one_sz = Const (Word.one sz) in
        let word_1f = Const (Word.of_int (Z.of_int 0x1f) 8) in
        let n_masked = BinOp(And, n, word_1f) in
        let ldst = Lval dst in
        let cf_stmt =
            let c = Cmp (LT, sz', n_masked) in
            If (c,
                [undef_flag fcf],
                (* CF is the last bit having been "evicted out" *)
                [Set (V (T fcf), BinOp (And, one_sz, (BinOp(Shr, ldst, BinOp(Sub, sz', n_masked)))))])
        in
        let of_stmt =
            let is_one = Cmp (EQ, n_masked, one8) in
            let op =
                (* last bit having been "evicted out"  xor CF*)
                Set (V (T fof),
                     BinOp(Xor, Lval (V (T fcf)),
                           BinOp (And, one_sz,
                                  (BinOp(Shr, ldst,
                                         BinOp(Sub, sz', n_masked))))))
            in
            If (is_one,    (* OF is set if n == 1 only *)
                [op] ,
                [undef_flag fof])
        in
        let lv = Lval dst in
        let ops =
          [
	    cf_stmt; 
            Set (dst, BinOp (Shl, ldst, n_masked));
            of_stmt; undef_flag faf;
            (sign_flag_stmts sz lv) ; (zero_flag_stmts sz lv) ; (parity_flag_stmts sz lv)
            ]
        in
        (* If shifted by zero, do nothing, else do the rest *)
        [If(Cmp(EQ, n_masked, Const (Word.zero 8)), [], ops)]

    (* SHR *)
    let shift_r_stmt dst sz n arith =
        let sz' = const sz 8 in
        let one8 = Const (Word.one 8) in
        let one_sz = Const (Word.one sz) in
        let word_1f = Const (Word.of_int (Z.of_int 0x1f) 8) in
        let n_masked = BinOp(And, n, word_1f) in
        let ldst = Lval dst in
        let dst_sz_min_one = const (sz-1) sz in
        let dst_msb = BinOp(And, one_sz, BinOp(Shr, ldst, dst_sz_min_one)) in
        let cf_stmt =
            let c = Cmp (LT, sz', n_masked) in
            If (c,
                [undef_flag fcf],
                (* CF is the last bit having been "evicted out" *)
                [Set (V (T fcf), BinOp (And, one_sz, (BinOp(Shr, ldst, BinOp(Sub,n_masked, one8)))))])
        in
        let of_stmt =
            let is_one = Cmp (EQ, n_masked, one8) in
            let op =
                if arith then
                    (clear_flag fof)
                else
                    (* MSB of original dest *)
                    (Set (V (T fof), dst_msb))
            in
            If (is_one,    (* OF is set if n == 1 only *)
                [op] ,
                [undef_flag fof])
        in
        let ops =
          if arith then
	    begin
	      let ffff = const (-1) sz in
	      let sign_mask = TernOp(Cmp(LEQ, n_masked, sz'),
				    BinOp(Shl, ffff, BinOp(Sub, sz', n_masked)),
				    ffff)  in
                [
                    (* Compute sign extend mask if needed *)
                  cf_stmt ; of_stmt ;
		  If (Cmp (EQ, dst_msb, one_sz),
                        [Set (dst, BinOp (Or, BinOp (Shr, ldst, n_masked), sign_mask))], (* TODO :extend *)
                        [Set (dst, BinOp (Shr, ldst, n_masked))] (* no extend *)
                       );
                    undef_flag faf;
                ]
	    end
            else
                [
                  cf_stmt ; of_stmt ; 
		  Set (dst, BinOp (Shr, ldst, n_masked));
                  undef_flag faf;
                ]
        in
        (* If shifted by zero, do nothing, else do the rest *)
        let res = Lval dst in
        [If(Cmp(EQ, n_masked, Const (Word.zero 8)), [], ops @ [(sign_flag_stmts sz res) ; (zero_flag_stmts sz res) ; (parity_flag_stmts sz res)] )]

    (* SHLD / TODO : merge with SHL ? *)
    let shift_ld_stmt dst src sz n =
        let sz' = const sz 8 in
        let one8 = Const (Word.one 8) in
        let one = Const (Word.one sz) in
        let word_1f = Const (Word.of_int (Z.of_int 0x1f) 8) in
        let n_masked = BinOp(And, n, word_1f) in
        let ldst = Lval dst in
        let dst_sz_min_one = const (sz-1) sz in
        let dst_msb = BinOp(And, one, BinOp(Shr, ldst, dst_sz_min_one)) in
        let cf_stmt = Set (V (T fcf), BinOp (And, one, (BinOp(Shr, ldst, BinOp(Sub, sz', n_masked))))) in
        let of_stmt =
            let is_one = Cmp (EQ, n_masked, one8) in
            If (is_one,    (* OF is computed only if n == 1 *)
                [Set ((V (T fof)), (* OF is set if signed changed. We saved sign in fof *)
                    BinOp(Xor,  Lval (V (T fof)), dst_msb));],
                [undef_flag fof])
        in
        let lv = Lval dst in
        let ops =
            [
                (* save sign *)
                Set ((V (T fof)), dst_msb);
                cf_stmt;
                (* dst = (dst << n) | (src >> (sz-n)) *)
                Set (dst, (BinOp(Or,
                            (BinOp(Shl, ldst, n_masked)),
                            (BinOp(Shr, src, BinOp(Sub, sz', n_masked))))));
                (* previous cf is used in of_stmt *)
                of_stmt; undef_flag faf;
                (sign_flag_stmts sz lv) ; (zero_flag_stmts sz lv) ; (parity_flag_stmts sz lv)
            ]
        in
        (* If shifted by zero, do nothing, else do the rest *)
        [If(Cmp(EQ, n_masked, Const (Word.zero 8)), [], 
            (* if shifted by more than opsize, everything is undef *)
            [ If(Cmp(GT, n_masked, sz'),
                [ undef_flag fcf; undef_flag fof; undef_flag fsf;
                  undef_flag faf; undef_flag fzf; undef_flag fpf; Directive(Forget dst)],
                ops)
           ])
       ]


    (* SHRD *)
    let shift_rd_stmt dst src sz n =
        let sz' = const sz 8 in
        let one8 = Const (Word.one 8) in
        let one = Const (Word.one sz) in
        let word_1f = Const (Word.of_int (Z.of_int 0x1f) 8) in
        let n_masked = BinOp(And, n, word_1f) in
        let ldst = Lval dst in
        let dst_sz_min_one = const (sz-1) sz in
        let dst_msb = BinOp(And, one, BinOp(Shr, ldst, dst_sz_min_one)) in
        let cf_stmt =
            let c = Cmp (LT, sz', n_masked) in
            If (c,
                [undef_flag fcf],
                (* CF is the last bit having been "evicted out" *)
                [Set (V (T fcf), BinOp (And, one, (BinOp(Shr, ldst, BinOp(Sub, n_masked, one8)))))])
        in
        let of_stmt =
            let is_one = Cmp (EQ, n_masked, one8) in
            If (is_one,    (* OF is computed only if n == 1 *)
                [Set ((V (T fof)), (* OF is set if signed changed. We saved sign in fof *)
                    BinOp(Xor,  Lval (V (T fof)), dst_msb));],
                [clear_flag fof])
        in
        let ops =
                [
                    (* save sign *)
                    Set ((V (T fof)), dst_msb);
                    cf_stmt;
                    (* dst = (dst >> n) | (src << (sz-n)) *)
                    Set (dst, (BinOp(Or,
                                (BinOp(Shr, ldst, n_masked)),
                                (BinOp(Shl, src, BinOp(Sub, sz', n_masked))))));
                    of_stmt ; undef_flag faf;
                ]
        in
        (* If shifted by zero, do nothing, else do the rest *)
        let res = Lval dst in
        [If(Cmp(EQ, n_masked, Const (Word.zero 8)), [], 
            (* if shifted by more than opsize, everything is undef *)
            (* TODO : forget dst *)
            [If(Cmp(GT, n_masked, sz'), [undef_flag fcf; undef_flag fof; undef_flag fsf; undef_flag faf; undef_flag fzf;],
               ops @ [(sign_flag_stmts sz res) ; (zero_flag_stmts sz res) ; (parity_flag_stmts sz res)])])]


    let rotate_l_stmt dst sz count =
      let one = Const (Word.one sz) in
      let zero = Const (Word.zero sz) in
      let sz_exp = const sz sz in
      let szm1_exp = const (sz-1) sz in
      let word_1f = Const (Word.of_int (Z.of_int 0x1f) sz) in
      let count_ext = UnOp(ZeroExt sz, count) in
      let count_masked = BinOp(And, count_ext, word_1f) in
      let count_mod = BinOp(Mod, count_masked, sz_exp) in
      (* spec : tempCOUNT ← (COUNT & COUNTMASK) MOD SIZE *)
      let inv_count_mod = BinOp (Sub, sz_exp, count_mod) in
      let low = BinOp (Shr, Lval dst, inv_count_mod) in
      let high = BinOp (Shl, Lval dst, count_mod) in
      let res = BinOp (Or, high, low) in
      let msb = BinOp(Shr, (Lval dst), szm1_exp) in
      let lsb = BinOp(And, (Lval dst), one) in
      let cf_stmt = Set (V (T fcf), lsb) in
      let of_stmt = If (Cmp (EQ, count_masked, one),
			[Set (V (T fof), BinOp(Xor, lsb, msb))],
			[undef_flag fof]) in
      (* beware of that : of_stmt has to be analysed *after* having set cf *)
      let stmts =  [  Set (dst, res) ; cf_stmt ; of_stmt ;] in
      [ If (Cmp(EQ, count_masked, zero), [], stmts)]
	
    let rotate_r_stmt dst sz count =
      let one = Const (Word.one sz) in
      let zero = Const (Word.zero sz) in
      let sz_exp = const sz sz in
      let szm1_exp = const (sz-1) sz in
      let szm2_exp = const (sz-2) sz in
      let word_1f = Const (Word.of_int (Z.of_int 0x1f) sz) in
      let count_ext = UnOp(ZeroExt sz, count) in
      let count_masked = BinOp(And, count_ext, word_1f) in
      let count_mod = BinOp(Mod, count_masked, sz_exp) in
      let inv_count_mod = BinOp (Sub, sz_exp, count_mod) in
      let low = BinOp (Shr, Lval dst, count_mod)  in
      let high = BinOp (Shl, Lval dst, inv_count_mod) in
      let res = BinOp (Or, high, low) in
      let msb = BinOp(Shr, (Lval dst), szm1_exp) in
      let smsb = BinOp(Shr, (Lval dst), szm2_exp) in
      let cf_stmt = Set (V (T fcf), msb) in 
      let of_stmt = If (Cmp (EQ, count_masked, one),
			[Set (V (T fof), BinOp(Xor, msb, smsb))],
			[undef_flag fof]) in
      (* beware of that : of_stmt has to be analysed *after* having set cf *)
      let stmts =  [Set (dst, res) ; cf_stmt ; of_stmt ] in
      [ If (Cmp(EQ, count_masked, zero), [], stmts)]

    let rotate_l_carry_stmt dst sz count = (* rcr *)
      let zero = Const (Word.zero 8) in
      let one8 = Const (Word.one 8) in
      let onesz = Const (Word.one sz) in
      let word_1f = Const (Word.of_int (Z.of_int 0x1f) 8) in
      (*      let sz8 = Const (Word.of_int (Z.of_int sz) 8) in*)
      (* add 1 to operand size to take in account the carry *)
      let sz8p1 = Const (Word.of_int (Z.of_int (sz+1)) 8) in
      let count_masked = BinOp(And, count, word_1f) in
      let count_mod = BinOp(Mod, count_masked , sz8p1) in
      let inv_count_mod = BinOp(Sub, sz8p1, count_mod) in
      let inv_count_mod_m1 = BinOp(Sub, inv_count_mod, one8) in
      (* count_mod == 0 will be cut later on, so we can compute count_mod-1 *)
      let count_mod_m1 = BinOp(Sub, count_mod, one8) in
      (* sz bit temporary register to hold original carry *)
      let old_cf_reg = Register.make ~name:(Register.fresh_name ()) ~size:sz in
      let old_cf = V (T old_cf_reg) in
      let old_cf_lsb = V (P (old_cf_reg, 0, 0)) in 
      (* compute the rcl *)
      let high = BinOp (Shl, Lval dst, count_mod) in
      let low = BinOp (Shr, Lval dst,  inv_count_mod) in
      let shifted_cf = BinOp(Shl, Lval old_cf, count_mod_m1) in
      let res = BinOp(Or, BinOp(Or, high, low), shifted_cf) in
      let msb = BinOp(Shr, (Lval dst), (const (sz-1) sz)) in
      let new_cf_val = TernOp(Cmp(EQ, BinOp(And, BinOp(Shr, Lval dst, inv_count_mod_m1), onesz), onesz),
                              const 1 1, const 0 1) in
      let cf_stmt = Set (V (T fcf), new_cf_val) in
      (* of flag is affected only by single-bit rotate ; otherwise it is undefined *)
      let of_stmt = If (Cmp (EQ, count_masked, one8),
			[Set (V (T fof), TernOp(
                          Cmp(EQ, BinOp(Xor, UnOp(ZeroExt sz, (Lval (V (T fcf)))), msb), const 1 sz),
                          const 1 1,
                          const 0 1))],
			[undef_flag fof]) in
      (* beware of that : of_stmt has to be analysed *after* having set cf *)
      let stmts =  [
        Set(old_cf, Const (Word.zero sz)) ;
        Set(old_cf_lsb, Lval (V (T fcf))) ;
        cf_stmt ; Set (dst, res) ; of_stmt ;
        Directive (Remove old_cf_reg )] in
      [ If (Cmp(EQ, count_mod, zero), [], stmts)]


    let rotate_r_carry_stmt dst sz count = (* rcr *)
      let zero = Const (Word.zero 8) in
      let one8 = Const (Word.one 8) in
      let onesz = Const (Word.one sz) in
      let word_1f = Const (Word.of_int (Z.of_int 0x1f) 8) in
      (*      let sz8 = Const (Word.of_int (Z.of_int sz) 8) in*)
      (* add 1 to operand size to take in account the carry *)
      let sz8m1 = Const (Word.of_int (Z.of_int (sz-1)) 8) in
      let sz8p1 = Const (Word.of_int (Z.of_int (sz+1)) 8) in
      let count_masked = BinOp(And, count, word_1f) in
      let count_mod = BinOp(Mod, count_masked , sz8p1) in
      let inv_count_mod = BinOp(Sub, sz8p1, count_mod) in
      let inv_count_mod_m1 = BinOp(Sub, inv_count_mod, one8) in
      (* count_mod == 0 will be cut later on, so we can compute count_mod-1 *)
      let count_mod_m1 = BinOp(Sub, count_mod, one8) in
      (* sz bit temporary register to hold original carry *)
      let old_cf_reg = Register.make ~name:(Register.fresh_name ()) ~size:sz in
      let old_cf = V (T old_cf_reg) in
      let old_cf_lsb = V (P (old_cf_reg, 0, 0)) in 
      (* compute the rcl *)
      let high = BinOp (Shl, Lval dst, inv_count_mod) in
      let low = BinOp (Shr, Lval dst,  count_mod) in
      let shifted_cf = BinOp(Shl, Lval old_cf, inv_count_mod_m1) in
      let src = BinOp(Or, BinOp(Or, high, low), shifted_cf) in
      let new_cf_val = TernOp(Cmp(EQ, BinOp(And, BinOp(Shr, Lval dst, count_mod_m1), onesz), onesz),
                              const 1 1, const 0 1) in
      let cf_stmt = Set (V (T fcf), new_cf_val) in
      (* of flag is affected only by single-bit rotate ; otherwise it is undefined *)
      let of_stmt = If (Cmp (EQ, count_masked, one8),
			[Set (V (T fof), BinOp(Xor, Lval old_cf, BinOp(Shr, Lval dst, sz8m1)))],
			[undef_flag fof]) in
      (* beware of that : of_stmt has to be analysed *after* having set cf *)
      let stmts =  [
	Set(old_cf, Const (Word.zero sz)) ;
	Set(old_cf_lsb, Lval (V (T fcf))) ;
	cf_stmt ; of_stmt ; Set (dst, src) ; 
	Directive (Remove old_cf_reg )] in
      [ If (Cmp(EQ, count_mod, zero), [], stmts)]

    let neg sz reg =
      let name = Register.fresh_name ()	    in
      let tmp_reg = Register.make ~name:name ~size:sz in
      let tmp_regv = V (T tmp_reg) in
      let zero = Const (Word.zero sz) in
      [ Set ( V (T fcf), TernOp( Cmp(EQ, Lval reg, const 0 sz),
				 const 0 1, const 1 1) ) ;
	Set (tmp_regv, Lval reg) ;
	Set (reg, BinOp (Sub, zero, Lval reg)) ;
	sign_flag_stmts sz (Lval reg) ;
	zero_flag_stmts sz (Lval reg) ;
	parity_flag_stmts sz (Lval reg) ;
	overflow_flag_stmts sz (Lval reg) zero Sub (Lval tmp_regv);
	adjust_flag_stmts_from_res sz zero (Lval tmp_regv) (Lval reg);
	Directive(Remove tmp_reg) ;
      ]
	
    let grp2 s sz e =
        let nnn, dst = core_grp s sz in
        let n =
            match e with
            | Some e' -> e'
            | None -> get_imm s 8 8 false
        in
        match nnn with
	| 0 -> return s (rotate_l_stmt dst sz n) (* ROL *)
	| 1 -> return s (rotate_r_stmt dst sz n) (* ROR *)
	| 2 -> return s (rotate_l_carry_stmt dst sz n) (* RCL *)
	| 3 -> return s (rotate_r_carry_stmt dst sz n) (* RCR *)
        | 4
        | 6 -> return s (shift_l_stmt dst sz n) (* SHL/SAL *)
        | 5 -> return s (shift_r_stmt dst sz n false) (* SHR *)
       	| 7 -> return s (shift_r_stmt dst sz n true) (* SAR *)
        | _ -> error s.a "Illegal opcode in grp 2"

    let grp3 s sz =
        let nnn, reg = core_grp s sz in
        let stmts =
            match nnn with
            | 0 -> (* TEST *) let imm = get_imm s sz sz false in test_stmts reg imm sz
            | 2 -> (* NOT *) [ Set (reg, UnOp (Not, Lval reg)) ]
            | 3 -> (* NEG *) neg sz reg
            | 4 -> (* MUL *) mul_stmts Mul (Lval reg) sz
            | 5 -> (* IMUL *) mul_stmts IMul (Lval reg) sz
            | 6 -> (* DIV *) div_stmts (Lval reg) sz true
            | 7 -> (* IDIV *) div_stmts (Lval reg) sz false
            | _ -> error s.a "Unknown operation in grp 3"
        in
        return s stmts

    let grp4 s =
        let nnn, dst = core_grp s 8 in
        match nnn with
        | 0 -> inc_dec dst Add s 8
        | 1 -> inc_dec dst Sub s 8
        | _ -> error s.a "Illegal opcode in grp 4"

    let grp5 s =
        let nnn, dst = core_grp s s.operand_sz in
        match nnn with
        | 0 -> inc_dec dst Add s s.operand_sz
        | 1 -> inc_dec dst Sub s s.operand_sz
        | 2 -> call s (R (Lval dst))

        | 4 -> return s [ Jmp (R (Lval dst)) ]
        | 6 -> push s [dst]
        | _ -> error s.a "Illegal opcode in grp 5"

    let grp6 s =
        let nnn, _dst = core_grp s s.operand_sz in
        match nnn with
        | _ -> error s.a "Unknown opcode in grp 6"

    let grp7 s =
        let nnn, _dst = core_grp s s.operand_sz in
        match nnn with
        | _ -> error s.a "Unknown opcode in grp 7"

    let core_bt s fct dst src =
        let is_register =
            match dst with
            | V _ -> true
            | M _ -> false
        in
        let nth  =
            if is_register then BinOp (Mod, src, const s.operand_sz s.operand_sz)
            else src
        in
        let nbit  = BinOp (And, UnOp (SignExt s.operand_sz, BinOp (Shr, Lval dst, nth)), Const (Word.one s.operand_sz)) in
        let stmt  = Set (V (T fcf), nbit) in
        let stmts = fct nth nbit in
        return s ((stmt::stmts) @ [ undef_flag fof; undef_flag fsf; undef_flag fzf; undef_flag faf; undef_flag fpf])

    let bts_stmt dst nbit op_sz = Set (dst, BinOp (Or, Lval dst, BinOp (Shl, Const (Data.Word.one op_sz), nbit)))
    let btr_stmt dst nbit op_sz = Set (dst, BinOp (And, Lval dst, UnOp (Not, BinOp (Shl, Const (Data.Word.one op_sz), nbit))))
    let bt s dst src = core_bt s (fun _nth _nbit -> []) dst src
    let bts s dst src = core_bt s (fun nth _nbit -> [bts_stmt dst nth s.operand_sz]) dst src
    let btr s dst src = core_bt s (fun nth _nbit -> [btr_stmt dst nth s.operand_sz]) dst src
    let btc s dst src = core_bt s (fun _nth nbit -> [If (Cmp (EQ, nbit, Const (Word.one s.operand_sz)), [btr_stmt dst _nth s.operand_sz], [bts_stmt dst _nth s.operand_sz])]) dst src
    let bsr s dst src =
      let sz = s.operand_sz in
      let zero = Const (Word.zero sz) in
      let one =  Const (Word.one sz) in
      let rec compose_bsr src i =
        let idx = const i sz in
        if i = 0 then idx
        else TernOp (Cmp (EQ, (BinOp (And, one, BinOp(Shr, src, idx))), one),
                     idx,
                     compose_bsr src (i-1)) in
      return s [
        undef_flag fcf ; undef_flag fpf ; undef_flag fsf ; undef_flag fof ; undef_flag faf ;
        If(Cmp(EQ, src, zero),
           [ Set(V (T fzf), Const (Word.one fzf_sz)) ;
             Directive(Forget dst) ; ],
           [ Set(V (T fzf), Const (Word.zero fzf_sz)) ;
             Set(dst, compose_bsr src (s.operand_sz-1)) ; ] )
      ]

    let bsf s dst src =
      let sz = s.operand_sz in
      let zero = Const (Word.zero sz) in
      let one =  Const (Word.one sz) in
      let rec compose_bsf src i =
        let idx = const i sz in
        if i = s.operand_sz-1 then idx
        else TernOp (Cmp (EQ, (BinOp (And, one, BinOp(Shr, src, idx))), one),
                     idx,
                     compose_bsf src (i+1)) in
      return s [
        undef_flag fcf ; undef_flag fpf ; undef_flag fsf ; undef_flag fof ; undef_flag faf ; 
        If(Cmp(EQ, src, zero),
           [ Set(V (T fzf), Const (Word.one fzf_sz)) ;
             Directive(Forget dst) ; ],
           [ Set(V (T fzf), Const (Word.zero fzf_sz)) ;
             Set(dst, compose_bsf src 0) ; ] )
      ]

    let grp8 s =
        let nnn, dst = core_grp s s.operand_sz                                                           in
        let imm = get_imm s 8 s.operand_sz false in
        match nnn with
        | 4 -> (* BT *) bt s dst imm
        | 5 -> (* BTS *) bts s dst imm
        | 6 -> (* BTR *) btr s dst imm
        | 7 -> (* BTC *) btc s dst imm
        | _ -> error s.a "Illegal opcode in grp 8"


    (*******************)
    (* BCD *)
    (*******************)
    let al  = V (P (eax, 0, 7))
    let ah  = V (P (eax, 8, 15))
    let ax  = V (P (eax, 0, 15))
    let fal = BinOp (And, Lval al, const 0xF 8)
    let fal_gt_9 = Cmp (GT, fal, const 9 8)
    let faf_eq_1 = Cmp (EQ, Lval (V (T faf)), Const (Word.one 1))

    let core_aaa_aas s op =
        let stmts =
            [
              If (BBinOp (LogOr, fal_gt_9, faf_eq_1),
		  [ Set (ax, BinOp (op, Lval ax, const 0x106 16));
                    set_flag faf;
                    set_flag fcf;
                  ],
		  [ clear_flag faf;
                    clear_flag fcf; ]) ;
	      Set (al, fal);
              undef_flag fof;
              undef_flag fsf;
              undef_flag fpf;
              undef_flag fzf
            ]
        in
        return s stmts

    let aaa s = core_aaa_aas s Add
    let aas s = core_aaa_aas s Sub

    let core_daa_das s op =
        let old_al = Register.make (Register.fresh_name()) 8				       in
        let old_cf = Register.make (Register.fresh_name()) 1				       in
        let al_op_6 = BinOp (op, Lval al, const 6 8) in
	let carry_or_borrow =  if op = Asm.Add then
	    BBinOp(LogAnd,
		   Cmp(EQ, BinOp(Shr,Lval (V (T old_al)), const 7 8), const 1 8),
		   Cmp(EQ, BinOp(Shr,Lval al, const 7 8), const 0 8))
	  else
	    BBinOp(LogAnd,
		   Cmp(EQ, BinOp(Shr,Lval (V (T old_al)), const 7 8), const 0 8),
		   Cmp(EQ, BinOp(Shr,Lval al, const 7 8), const 1 8)) in
        let if1 = If (BBinOp (LogOr, fal_gt_9, faf_eq_1),
                      [ Set(al, al_op_6);
			Set(V (T fcf), BinOp(Or, Lval (V (T old_cf)),
					     TernOp(carry_or_borrow,
						    const 1 1,
						    const 0 1))) ;
			set_flag faf],
                      [clear_flag faf])
        in
	let maybe_clear_cf = if op = Asm.Add then [clear_flag fcf] else [] in
        let if2 = If (BBinOp (LogOr, Cmp (GT, Lval (V (T old_al)), const 0x99 8),
			      Cmp(EQ, Lval (V (T old_cf)), Const (Word.one 1))),
                      [ Set (al, BinOp(op, Lval al, const 0x60 8)) ;
			set_flag fcf ],
                      maybe_clear_cf)
        in

        let stmts =
            [
                Set (V (T old_al), Lval al);
                Set (V (T old_cf), Lval (V (T fcf)));
                clear_flag fcf;
                if1;
                if2;
                sign_flag_stmts 8 (Lval al);
                zero_flag_stmts 8 (Lval al);
                parity_flag_stmts 8 (Lval al);
                undef_flag fof;
                Directive (Remove old_al);
                Directive (Remove old_cf)
            ]
        in
        return s stmts

    let daa s = core_daa_das s Add
    let das s = core_daa_das s Sub

    let aam s =
      let base = const_of_Z (int_of_byte s) 8 in
      let stmts = [
        Set(ah, BinOp(Div, Lval al, base));
        Set(al, BinOp(Mod, Lval al, base));
        zero_flag_stmts 8 (Lval al);
        sign_flag_stmts 8 (Lval al);
        parity_flag_stmts 8 (Lval al);
        undef_flag fof;
        undef_flag faf;
        undef_flag fcf; ] in

        return s stmts

    let aad s =
      let base = const_of_Z (int_of_byte s) 8 in
      let tmp  = Register.make (Register.fresh_name ()) 16 in
      let stmts = [
        Set(V (T tmp), BinOp(Add, UnOp(ZeroExt 16, Lval al), BinOp(Mul, Lval ah, base)));
	Set(al, Lval (V (P (tmp, 0, 7))));
        Set(ah, const 0 8);
        zero_flag_stmts 8 (Lval al);
        sign_flag_stmts 8 (Lval al);
        parity_flag_stmts 8 (Lval al);
        undef_flag fof;
        undef_flag faf;
        undef_flag fcf;
	Directive(Remove tmp) ] in
        return s stmts

    (********)
    (* misc *)
    (*****)

    (** CWD / CDQ **)
    (* sign extend AX to DX:AX (16 bits) or *)
    (* sign extend EAX to EDX:EAX (32 bits) *)
    let cwd_cdq s =
        let d_edx = V (to_reg edx s.operand_sz) in
        let tmp   = Register.make ~name:(Register.fresh_name()) ~size:(s.operand_sz*2) in
        let sign_ext = Set (V (T tmp), UnOp (SignExt (s.operand_sz*2), Lval (V (to_reg eax s.operand_sz)))) in
        return s [sign_ext; Set (d_edx, Lval (V (P (tmp, s.operand_sz, (s.operand_sz*2-1))))); Directive (Remove tmp)]

    (** set byte on condition *)
    let setcc s cond =
        let e = exp_of_cond cond s in
        let md, _, rm = mod_nnn_rm (Char.code (getchar s)) in
        let dst = exp_of_md s md rm 8 8 in
        return s [If (e, [Set (dst, Const (Word.one 8))], [Set (dst, Const (Word.zero 8))])]

    let xchg s arg1 arg2 sz =
        let tmp   = Register.make ~name:(Register.fresh_name()) ~size:sz in
        let stmts = [ Set(V (T tmp), Lval arg1);
		      Set(arg1, Lval arg2) ;
                      Set(arg2, Lval (V (T tmp)))  ;
		      Directive (Remove tmp) ]
        in
        return s stmts

    let xchg_mrm s sz =
      let dst,src = operands_from_mod_reg_rm_core s sz sz in
      xchg s src dst sz

    let xchg_with_eax s v =
        let eax = to_reg eax s.operand_sz in
        let v'  = find_reg v s.operand_sz in
        xchg s (V eax) (V v') s.operand_sz

    let cmpxchg s rm reg sz =
      let eax = to_reg eax sz in
      let stmts = [
        If (Cmp(EQ, Lval (V eax), Lval rm),
            [ set_flag fzf;
              Set(rm, reg);  ],
            [ clear_flag fzf;
              Set(V eax, Lval rm); ]
        )
      ] in
      return s stmts

    let cmpxchg8b_mrm s  =
      let sz = s.operand_sz in
      let _reg,rm = operands_from_mod_reg_rm_core s sz ~mem_sz:(sz*2) sz in
      let tmp64   = Register.make ~name:(Register.fresh_name()) ~size:(2*sz) in
      let stmts = [
	Set( V (T tmp64), BinOp(Or,
				BinOp(Shl, UnOp(ZeroExt (2*sz), Lval (V (T edx))), const sz (2*sz)),
				UnOp(ZeroExt (2*sz), Lval (V (T eax))))) ;
        If (Cmp(EQ, Lval (V (T tmp64)), Lval rm),
            [ set_flag fzf;
	      Set( V (T tmp64), BinOp(Or,
				      BinOp(Shl, UnOp(ZeroExt (2*sz), Lval (V (T ecx))), const sz (2*sz)),
				      UnOp(ZeroExt (2*sz), Lval (V (T ebx))))) ;
              Set(rm, Lval (V (T tmp64)));  ],
            [ clear_flag fzf;
	      Set( V (T tmp64), Lval rm) ;
              Set(V (T eax), Lval (V (P (tmp64,0,31))));
              Set(V (T edx), Lval (V (P (tmp64,32,63))));
	    ]) ;
        Directive (Remove tmp64)
      ] in
      return s stmts

    let xadd_mrm s sz =
      let arg1,arg2 = operands_from_mod_reg_rm_core s sz sz in
      let tmp   = Register.make ~name:(Register.fresh_name()) ~size:sz in
      let stmts = [ Set(V (T tmp), BinOp(Add, Lval arg1, Lval arg2));
		    Set(arg1, Lval arg2) ;
                    Set(arg2, Lval (V (T tmp)));
		    Directive (Remove tmp) ] in
        return s stmts


    let xlat s =
      let al = V (to_reg eax 8) in
      let al_ext = UnOp(ZeroExt s.operand_sz, Lval al) in
      let reg_ebx = Lval (V (to_reg ebx s.operand_sz)) in
      let ofs = BinOp(Add, reg_ebx, al_ext) in
      let mem = M ((add_segment s ofs  s.segments.data), 8) in
      return s [ Set(al, Lval mem) ]

    let to_segment_reg a n =
        match n with
        | 0 -> es
        | 1 -> cs
        | 2 -> ss
        | 3 -> ds
        | 4 -> fs
        | 5 -> gs
        | _ -> error a "Invalid conversion to segment register"

    let arpl (s: state) =
        let _mod, reg, rm = mod_nnn_rm (Char.code (getchar s))  in
        let dst           = V (P (Hashtbl.find register_tbl rm, 0, 1)) in
        let src           = V (P (to_segment_reg s.a reg, 0, 1))    in
        let stmts = [
            If (Cmp(GT, Lval dst, Lval src),
                [set_flag fzf; Set (dst, Lval src)],
                [clear_flag fzf]
               )
        ]
        in
        return s stmts
	  
    (** check whether an opcode is defined in a given state of the decoder *)
    let check_context s c =
        if s.rep then
            match c with
            | c when '\x6C' <= c && c <= '\x6F' (* INS and OUTS *) || '\xA4' <= c && c <= '\xA5' (* MOVS *) -> c
            | c when '\xAE' <= c && c <= '\xAF' -> (* CMPS *) s.repe <- true; c
            | c when '\xA6' <= c && c <= '\xA7' -> (* SCAS *) s.repe <-true; c
            | _ -> error s.a (Printf.sprintf "Decoder: undefined behavior of REP with opcode %x" (Char.code c))
        else
        if s.repne then
            match c with
            | c when '\xA6' <= c && c <= '\xA7' || '\xAE' <= c && c <= '\xAF' -> c
            | _ -> error s.a (Printf.sprintf "Decoder: undefined behavior of REPNE/REPNZ with opcode %x" (Char.code c))
        else
            c

    let set_flag f sz = [ Set (V (T f), Const (Word.one sz)) ]
    let clear_flag f sz = [ Set (V (T f), Const (Word.zero sz)) ]

    (** directive for automatic unrolling in rep instructions *)
    let unroll_scas (cmp: cmp) s i: stmt =
      let edi' = V (to_reg edi s.addr_sz) in
      let mem  = add_segment s (Lval edi') es in
      Directive (Unroll_until (mem, cmp, Lval (V (to_reg eax i)), 10000, i))
      
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
            | '\x06' -> (* PUSH es *) let es' = to_reg es s.operand_sz in push s [V es']
            | '\x07' -> (* POP es *) let es' = to_reg es s.operand_sz in pop s [V es']
            | '\x08' -> (* OR *) or_xor_and_mrm s Or 8 0
            | '\x09' -> (* OR *) or_xor_and_mrm s Or s.operand_sz 0
            | '\x0A' -> (* OR *) or_xor_and_mrm s Or 8 1
            | '\x0B' -> (* OR *) or_xor_and_mrm s Or s.operand_sz 1
            | '\x0C' -> (* OR imm8 *) or_xor_and_eax s Or 8 8
            | '\x0D' -> (* OR imm *) or_xor_and_eax s Or s.operand_sz s.operand_sz


            | '\x0E' -> (* PUSH cs *) let cs' = to_reg cs s.operand_sz in push s [V cs']
            | '\x0F' -> (* 2-byte escape *) decode_snd_opcode s

            | '\x10' -> (* ADC *) add_sub_mrm s Add true 8 0
            | '\x11' -> (* ADC *) add_sub_mrm s Add true s.operand_sz 0
            | '\x12' -> (* ADC *) add_sub_mrm s Add true 8 1
            | '\x13' -> (* ADC *) add_sub_mrm s Add true s.operand_sz 1

            | '\x14' -> (* ADC AL with immediate *) add_sub_immediate s Add true eax 8
            | '\x15' -> (* ADC eAX with immediate *) add_sub_immediate s Add true eax s.operand_sz
            | '\x16' -> (* PUSH ss *) let ss' = to_reg ss s.operand_sz in push s [V ss']
            | '\x17' -> (* POP ss *) let ss' = to_reg ss s.operand_sz in pop s [V ss']

            | '\x18' -> (* SBB *) add_sub_mrm s Sub true 8 0
            | '\x19' -> (* SBB *) add_sub_mrm s Sub true s.operand_sz 0
            | '\x1A' -> (* SBB *) add_sub_mrm s Sub true 8 1
            | '\x1B' -> (* SBB *) add_sub_mrm s Sub true s.operand_sz 1
            | '\x1C' -> (* SBB AL with immediate *) add_sub_immediate s Sub true eax 8
            | '\x1D' -> (* SBB eAX with immediate *) add_sub_immediate s Sub true eax s.operand_sz
            | '\x1E' -> (* PUSH ds *) let ds' = to_reg ds s.operand_sz in push s [V ds']
            | '\x1F' -> (* POP ds *) let ds' = to_reg ds s.operand_sz in pop s [V ds']

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
            | '\x66' -> (* operand size switch *) s.operand_sz <- if s.operand_sz = 16 then 32 else 16; decode s
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

            | '\x90' 			      -> (* NOP *) return s [Nop]
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
              return s ( (Set (sp, Lval bp))::(pop_stmts s [bp]))
            | '\xca' -> (* RET FAR *) return s ([Return ; set_esp Add (T esp) s.addr_sz; ] @ (pop_stmts s [V (T cs)]))
            | '\xcb' -> (* RET FAR and pop a word *) return s ([Return ; set_esp Add (T esp) s.addr_sz ; ] @ (pop_stmts s [V (T cs)] @ (* pop imm16 *) [set_esp Add (T esp) 16]))
            | '\xcc' -> (* INT 3 *) error s.a "INT 3 decoded. Interpreter halts"
            | '\xcd' -> (* INT *) let c = getchar s in error s.a (Printf.sprintf "INT %d decoded. Interpreter halts" (Char.code c))
            | '\xce' -> (* INTO *) error s.a "INTO decoded. Interpreter halts"
            | '\xcf' -> (* IRET *) error s.a "IRET instruction decoded. Interpreter halts"

            | '\xd0' -> (* grp2 shift with one on byte size *) grp2 s 8 (Some (Const (Word.one 8)))
            | '\xd1' -> (* grp2 shift with one on word or double size *) grp2 s s.operand_sz (Some (Const (Word.one 8)))
            | '\xd2' -> (* grp2 shift with CL and byte size *) grp2 s 8 (Some (Lval (V (to_reg ecx 8))))
            | '\xd3' -> (* grp2 shift with CL *) grp2 s s.operand_sz (Some (Lval (V (to_reg ecx 8))))
            | '\xd4' -> (* AAM *) aam s
            | '\xd5' -> (* AAD *) aad s
            | '\xd7' -> (* XLAT *) xlat s
            | c when '\xd8' <= c && c <= '\xdf' -> (* ESC (escape to coprocessor instruction set *) error s.a "ESC to coprocessor instruction set. Interpreter halts"

            | c when '\xe0' <= c && c <= '\xe2' -> (* LOOPNE/LOOPE/LOOP *) loop s c
            | '\xe3' -> (* JCXZ *) jecxz s

            | '\xe8' -> (* relative call *) relative_call s s.operand_sz
            | '\xe9' -> (* JMP to near relative address (offset has word or double word size) *) relative_jmp s s.operand_sz
            | '\xea' -> (* JMP to near absolute address *) direct_jmp s
            | '\xeb' -> (* JMP to near relative address (offset has byte size) *) relative_jmp s 8


            | '\xf0' -> (* LOCK *) error s.a "LOCK instruction found. Interpreter halts"
            | '\xf1' -> (* undefined *) error s.a "Undefined opcode 0xf1"
            | '\xf2' -> (* REPNE *) s.repne <- true; rep s Word.one
            | '\xf3' -> (* REP/REPE *) s.repe <- true; rep s Word.zero
            | '\xf4' -> (* HLT *) error s.a "Decoder stopped: HLT reached"
            | '\xf5' -> (* CMC *) let fcf' = V (T fcf) in return s [ Set (fcf', UnOp (Not, Lval fcf')) ]
            | '\xf6' -> (* shift to grp3 with byte size *) grp3 s 8
            | '\xf7' -> (* shift to grp3 with word or double word size *) grp3 s s.operand_sz
            | '\xf8' -> (* CLC *) return s (clear_flag fcf fcf_sz)
            | '\xf9' -> (* STC *) return s (set_flag fcf fcf_sz)
            | '\xfa' -> (* CLI *) L.decoder (fun p -> p "entering privilege mode (CLI instruction)"); return s (clear_flag fif fif_sz)
            | '\xfb' -> (* STI *) L.decoder (fun p -> p "entering privilege mode (STI instruction)"); return s (set_flag fif fif_sz)
            | '\xfc' -> (* CLD *) return s (clear_flag fdf fdf_sz)
            | '\xfd' -> (* STD *) return s (set_flag fdf fdf_sz)
            | '\xfe' -> (* INC/DEC grp4 *) grp4 s
            | '\xff' -> (* indirect grp5 *) grp5 s
            | c ->  error s.a (Printf.sprintf "Unknown opcode 0x%x" (Char.code c))

        and rep s c =
	    (* rep prefix *)
	  
            let ecx_cond  = Cmp (NEQ, Lval (V (to_reg ecx s.addr_sz)), Const (Word.zero s.addr_sz)) in
            let v, ip = decode s in
            (* TODO: remove this hack *)
            begin
              match List.hd v.Cfa.State.stmts with
              | Return -> L.decoder (fun p -> p "simplified rep ret into ret")
              | _ ->
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

        and decode_snd_opcode s =
            match getchar s with
            | '\x00' -> grp6 s
            | '\x01' -> grp7 s
            (* CMOVcc *)
            | c when '\x40' <= c && c <= '\x4f' -> let cond = (Char.code c) - 0x40 in cmovcc s cond

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

            | c 	   -> error s.a (Printf.sprintf "unknown second opcode 0x%x\n" (Char.code c))
        in
        decode s;;

    (** converts a signature function to typing directives for stdcall with respect to the stdcall calling convention *)
    let forget_reserved_registers_stdcall () =
      [ Directive (Forget (V (T ecx))) ; Directive (Forget (V (T edx))) ]
  

    let forget_reserved_registers_cdecl = forget_reserved_registers_stdcall
      
    let type_directives_cdecl (typing_rule: TypedC.ftyp): (Asm.stmt list * Asm.stmt list * int) =
        let epilogue =
            try
                [ Directive (Type (V (T eax), Types.typ_of_npk (snd typing_rule))) ]
            with _ -> []
        in
        let off = !Config.stack_width / 8 in
        let sz, prologue =
	  match fst typing_rule with
	  | None -> 0, []
	  | Some args ->
	     List.fold_left (fun (sz, stmts) (typ, _name) ->
            let lv = M (BinOp (Add, Lval (V (T esp)), Const (Word.of_int (Z.of_int sz) !Config.stack_width)), !Config.stack_width) in 
            sz+off, (Directive (Type (lv, Types.typ_of_npk typ)))::stmts
        ) (off, []) args
        in
        prologue, epilogue@(forget_reserved_registers_cdecl ()), sz

   
    let taint_directives_stdcall taint_ret taint_args =
        let taint_arg taint =
            match taint with
            | Config.No_taint -> []
            | Config.Buf_taint -> [Directive (Taint (None, M (Lval (V (T eax)), !Config.operand_sz)))]
            | Config.Addr_taint -> [Directive (Taint (None, V (T eax)))]
        in
        let taint_ret' =
            match taint_ret with
            | None -> []
            | Some t -> taint_arg t
        in
        List.fold_left (fun l arg -> (taint_arg arg)@l) [] taint_args, taint_ret'
    let type_directives_stdcall typing_rule =
        let prologue, epilogue, sz =
            type_directives_cdecl typing_rule in
        (* clean stack + forget volatile registers *)
        let sz' = sz / 8 in
        let clean_stack = Asm.Set (V (T esp), BinOp(Add, Lval (V (T esp)), Const (Word.of_int (Z.of_int sz') (Register.size esp)))) in
        prologue, (clean_stack::(forget_reserved_registers_stdcall ()))@epilogue

    let default_stub_stdcall () = [ Directive (Forget (V (T eax))) ]

    let default_stub_cdecl = default_stub_stdcall

    let taint_directives_cdecl = taint_directives_stdcall


    let get_stub name =
        match !Config.call_conv with
        | Config.STDCALL ->
          begin
              try
                  Hashtbl.find Imports.stdcall_stubs name
              with Not_found -> default_stub_stdcall ()
          end
        | Config.CDECL ->
          begin
              try
                  Hashtbl.find Imports.cdecl_stubs name
              with Not_found -> default_stub_cdecl ()
          end 
        | _ -> L.abort (fun p -> p "calling convention not managed for the while")   

    let replace_types type_directive =
        Hashtbl.iter (fun name typing_rule ->
            try
                let a, fundec = Imports.search_by_name name in
                let prologue, epilogue = type_directive typing_rule in 
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
        Hashtbl.iter (fun a (libname, fname) ->
            let a' = Data.Address.of_int Data.Address.Global a !Config.address_sz in
            let fundec =  {
                Imports.libname = libname;
                Imports.name = fname;
                Imports.prologue = [];
                Imports.stub = [];
                Imports.epilogue = [];
            }
            in
            Hashtbl.add Imports.tbl a' fundec) Config.import_tbl;
        (* adds typing information to prologue and epilogue *)
         
    begin	
        match !Config.call_conv with
        | Config.STDCALL -> replace_types type_directives_stdcall
        | Config.CDECL -> replace_types (fun r -> let e, p, _ = type_directives_cdecl r in e, p)
        | _ -> L.debug (fun p -> p "Calling convention not managed. Typing and tainting directives ignored")
    end;
    (* adds tainting information to prologue and epilogue *)
    Hashtbl.iter (fun (_libname, funame) (callconv, taint_ret, taint_args) ->
        try
            match callconv with
            | Config.STDCALL ->
              replace_taint taint_directives_stdcall funame taint_ret taint_args

            | Config.CDECL ->
              replace_taint taint_directives_cdecl funame taint_ret taint_args

            | _ -> raise (Failure "calling convention not supported")
        with 
          Not_found ->
          L.analysis (fun p -> p"Typing information for function without import address ignored"); ()
        | Failure msg -> L.abort (fun p -> p "%s" msg)

    ) Config.tainting_rules

	
      
     (** initialization of the decoder *)
    let init () =
      init_imports();
      let ldt = Hashtbl.create 5  in
      let gdt = Hashtbl.create 19 in
      let idt = Hashtbl.create 15 in
        (* builds the gdt *)
      Hashtbl.iter (fun o v -> Hashtbl.replace gdt (Word.of_int o 64) (tbl_entry_of_int v)) Config.gdt;
        let reg = Hashtbl.create 6 in
        List.iter (fun (r, v) -> Hashtbl.add reg r (get_segment_register_mask v)) [cs, !Config.cs; ds, !Config.ds; ss, !Config.ss; es, !Config.es; fs, !Config.fs; gs, !Config.gs];
        { gdt = gdt; ldt = ldt; idt = idt; data = ds; reg = reg;}
	  
    (** launch the decoder *)
    let parse text g is v a ctx =
        let s' = {
            g 	       = g;
            a 	       = a;
            o 	       = 0;
            c          = [];
            addr_sz    = !Config.address_sz;
            operand_sz = !Config.operand_sz;
            segments   = copy_segments is a ctx;
            rep_prefix = None;
            buf        = text;
            b 	       = v;
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
        | _ 			  -> (*end of buffer *) None
end
(* end Decoder *)

