(***************************************************************************************)
(* Decoder functor *)
(***************************************************************************************)

module Make(Domain: Domain.T) =
struct

    (** control flow automaton *)
    module Cfa = Cfa.Make(Domain)

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
            | _ -> Log.error "Invalid decription table selection"
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
        g: Z.t;}

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
            g = g; }

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

    (** complete internal state of the decoder *)
    (** only the segment field is exported out of the functor (see parse signature) for further reloading *)
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
        Log.error (Printf.sprintf "at %s: %s" (Address.to_string a) msg)


    (***********************************************************************)
    (* State helpers *)
    (***********************************************************************)

    (** extract from the string code the current byte to decode *)
    (** the offset field of the decoder state is increased *)
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
            error s.a "Immediate size bigger than target size"
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

    (** update and return the current state with the given statements and the new instruction value *)
    (** the context of decoding is also updated *)
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

    exception Disp32

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
                  | 5 -> raise Disp32
                  | _ -> rm_lv
              end
            | 1 -> 
              BinOp (Add, rm_lv, UnOp(SignExt s.addr_sz, disp s 8 sz))

            | 2 ->
              BinOp (Add, rm_lv, disp s 32 sz)
            | _ -> error s.a "Decoder: illegal value in md_from_mem"

    (** returns the statements for a mod/rm with _md_ _rm_ *)
    let exp_of_md s md rm sz =
        match md with
        | n when 0 <= n && n <= 2 -> M (add_data_segment s (md_from_mem s md rm sz), sz)
        | 3 ->
            (* special case for ah ch dh bh *)
            if sz = 8 && rm >= 4 then
                V (get_h_slice (rm-4))
            else
                V (find_reg rm sz)
        | _ -> error s.a "Decoder: illegal value for md in mod_reg_rm extraction"

    let operands_from_mod_reg_rm s sz ?(dst_sz = sz) direction =
        let c = getchar s in
        let md, reg, rm = mod_nnn_rm (Char.code c) in
        let reg_v =
            if dst_sz = 8 && reg >= 4 then
                V (get_h_slice (reg-4))
            else
                find_reg_v reg dst_sz in
        try
            let rm' = exp_of_md s md rm sz in
            if direction = 0 then
                rm', Lval reg_v
            else
                reg_v, Lval rm'
        with
        | Disp32 ->
          if direction = 0 then
              find_reg_v rm sz, add_data_segment s (disp s 32 sz)
          else
              error s.a "Decoder: illegal direction for displacement only addressing mode"

    let lea s =
        let c = getchar s in
        let md, reg, rm = mod_nnn_rm (Char.code c) in
        if md = 3 then
            error s.a "Illegal mod field in LEA"
        else
            let reg_v = find_reg_v reg s.operand_sz in
            let src =
                try
                    md_from_mem s md rm s.addr_sz
                with Disp32 -> disp s 32 s.addr_sz
            in
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


    (** produce common statements to set the overflow flag and the adjust flag *)
    let overflow flag n nth res sz op1 op2 =
        (* flag is set if both op1 and op2 have the same nth bit whereas different from the hightest bit of res *)
        let b1        = Const (Word.one sz)          in
        let sign_res  = BinOp(And, BinOp (Shr, res, nth), b1) in
        let sign_op1  = BinOp(And, BinOp (Shr, op1, nth), b1) in
        let sign_op2  = BinOp(And, BinOp (Shr, op2, nth), b1) in
        let c1 	      = Cmp (EQ, sign_op1, sign_op2)   	      in
        let c2 	      = Cmp (NEQ, sign_res, sign_op1)         in
        let one_stmt  = Set (V (T flag), Const (Word.one n))  in
        let zero_stmt = Set (V (T flag), Const (Word.zero n)) in
        If (BBinOp (LogAnd, c1, c2), [ one_stmt ], [ zero_stmt ])

    (** produce the statement to set the overflow flag according to the current operation whose operands are op1 and op2 and result is res *)
    let overflow_flag_stmts sz res op1 op2 = overflow fof fof_sz (const (sz-1) sz) res 1 op1 op2

    (** produce the statement to set the given flag *)
    let set_flag f = Set (V (T f), Const (Word.one (Register.size f)))

    (** produce the statement to clear the given flag *)
    let clear_flag f = Set (V (T f), Const (Word.zero (Register.size f)))

    (** produce the statement to undefine the given flag *)
    let undef_flag f = Directive (Forget f)

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
      If ( Cmp (EQ, shifted_res, one), [ set_flag fcf ], [ clear_flag fcf ] )

    (** produce the statement to set the sign flag wrt to the given parameter *)
    let sign_flag_stmts sz res =
        let c = Cmp (EQ, const 1 sz, BinOp(Shr, res, const (sz-1) sz)) in
        If (c, [ set_flag fsf ], [ clear_flag fsf ] )

    (** produce the statement to set the zero flag *)
    let zero_flag_stmts sz res =
        let c = Cmp (EQ, res, Const (Word.zero sz)) in
        If (c, [ set_flag fzf ], [ clear_flag fzf ])

    (** produce the statement to set the adjust flag wrt to the given parameters *)
    (** faf is set if there is an overflow on the bit 4 *)
    let adjust_flag_stmts res sz op1 op2 = overflow faf faf_sz (const 4 sz) res (sz-4) op1 op2

    (** produce the statement to set the parity flag wrt to the given parameters *)
    let parity_flag_stmts sz res =
        (* fpf is set if res contains an even number of 1 in the least significant byte *)
        (* we sum every bits and check whether this sum is even or odd *)
        (* using the modulo of the divison by 2 *)
        let nth i =
            let one = const 1 sz in
            let i' = const i sz in
            BinOp (And, UnOp(SignExt sz, BinOp(Shr, res, i')), one)
        in
        let e = ref (nth 0) in
        for i = 1 to 7 do
            e := BinOp(Add, !e, nth i)
        done;
        let if_stmt   = set_flag fpf			                    in
        let else_stmt = clear_flag fpf in
        let c 	      = Cmp (EQ, BinOp(Mod, !e, const 2 sz), Const (Word.zero sz)) in
        If(c, [ if_stmt ], [ else_stmt ])

    (** builds a value equivalent to the EFLAGS register from the state *)
    let get_eflags () =
      let eflags0 = Lval (V (T fcf)) in
      (*  bit 1 : reserved *)
      let eflags2 = UnOp (ZeroExt 32, BinOp(Shl,  Lval (V (T fpf)), const 2 32)) in
      (*  bit 3 : reserved *)
      let eflags4 = UnOp (ZeroExt 32, BinOp(Shl, Lval (V (T faf)), const 4 32)) in
      (*  bit 5 : reserved *)
      let eflags6 = UnOp(ZeroExt 32, BinOp(Shl, Lval (V (T fzf)), const 6 32)) in
      let eflags7 = UnOp(ZeroExt 32, BinOp(Shl, Lval (V (T fsf)), const 7 32)) in
      let eflags8 = UnOp(ZeroExt 32, BinOp(Shl, Lval (V (T _ftf)), const 8 32)) in
      let eflags9 = UnOp(ZeroExt 32, BinOp(Shl, Lval (V (T fif)), const 9 32)) in
      let eflags10 = UnOp(ZeroExt 32, BinOp(Shl, Lval (V (T fdf)), const 10 32)) in
      let eflags11 = UnOp(ZeroExt 32, BinOp(Shl, Lval (V (T fof)), const 11 32)) in
      let eflags12_13 = UnOp(ZeroExt 32, BinOp(Shl, Lval (V (T _fiopl)), const 12 32)) in
      let eflags14 = UnOp(ZeroExt 32, BinOp(Shl, Lval (V (T _fnt)), const 14 32)) in
      (*  bit 15 : reserved *)
      let eflags16 = UnOp(ZeroExt 32, BinOp(Shl, Lval (V (T _frf)), const 16 32)) in
      let eflags17 = UnOp (ZeroExt 32, BinOp(Shl, Lval (V (T _fvm)), const 17 32)) in
      let eflags18 = UnOp (ZeroExt 32, BinOp(Shl, Lval (V (T _fac)), const 18 32)) in
      let eflags19 = UnOp (ZeroExt 32, BinOp(Shl, Lval (V (T _fvif)), const 19 32)) in
      let eflags20 = UnOp (ZeroExt 32, BinOp(Shl, Lval (V (T _fvip)), const 20 32)) in
      let eflags21 = UnOp (ZeroExt 32, BinOp(Shl, Lval (V (T _fid)), const 21 32)) in
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
    let set_eflags eflags sz =
        let one = Const (Word.one sz) in
        let set_f flg value = Set (V (T flg), value) in
            (* XXX check perms and validity *)
            [set_f fcf  (BinOp(And, eflags, one));
             set_f fpf  (BinOp(And, (BinOp (Shr, eflags, const 2 32)), one));
             set_f faf  (BinOp(And, (BinOp (Shr, eflags, const 4 32)), one));
             set_f fzf  (BinOp(And, (BinOp (Shr, eflags, const 6 32)), one));
             set_f fsf  (BinOp(And, (BinOp (Shr, eflags, const 7 32)), one));
             set_f _ftf (BinOp(And, (BinOp (Shr, eflags, const 8 32)), one));
             set_f fif  (BinOp(And, (BinOp (Shr, eflags, const 9 32)), one));
             set_f fdf  (BinOp(And, (BinOp (Shr, eflags, const 10 32)), one));
             set_f fof  (BinOp(And, (BinOp (Shr, eflags, const 11 32)), one));
             set_f _fiopl (BinOp(And, (BinOp (Shr, eflags, const 12 32)),  const 3 32));
             set_f _fnt   (BinOp(And, (BinOp (Shr, eflags, const 14 32)), one));
             set_f _frf   (BinOp(And, (BinOp (Shr, eflags, const 16 32)), one));
             set_f _fvm   (BinOp(And, (BinOp (Shr, eflags, const 17 32)), one));
             set_f _fac   (BinOp(And, (BinOp (Shr, eflags, const 18 32)), one));
             set_f _fvif  (BinOp(And, (BinOp (Shr, eflags, const 19 32)), one));
             set_f _fvip  (BinOp(And, (BinOp (Shr, eflags, const 20 32)), one));
             set_f _fid   (BinOp(And, (BinOp (Shr, eflags, const 21 32)), one));
             ]

    (**************************************************************************************)
    (* State generation of binary logical/arithmetic operations *)
    (**************************************************************************************)

    (** produces the list of statements for the flag settings involved in the ADD, ADC, SUB, SBB, ADD_i, SUB_i instructions *)
    let add_sub_flag_stmts istmts sz dst op op2 =
        let name 	= Register.fresh_name ()	    in
        let v  	 	= Register.make ~name:name ~size:sz in
        let tmp  	= V (T v)		  	    in
        let op1  	= Lval tmp		  	    in
        let res  	= Lval dst		  	    in
        let flags_stmts =
            [
                carry_flag_stmts sz op1 op op2; overflow_flag_stmts sz res op1 op2; zero_flag_stmts sz res;
                sign_flag_stmts sz res            ; parity_flag_stmts sz res       ; adjust_flag_stmts res sz op1 op2
            ]
        in
        (Set (tmp, Lval dst)):: istmts @ flags_stmts @ [ Directive (Remove v) ]



    (** produces the list of statements for ADD, SUB, ADC, SBB depending of the value of the operator and the boolean value (=true for carry or borrow) *)
    let add_sub_stmts op b dst src sz =
        let e =
            if b then BinOp (op, Lval dst, UnOp (SignExt sz, Lval (V (T fcf))))
            else Lval dst
        in
        let res = [Set (dst, BinOp(op, e, src))] in
        add_sub_flag_stmts res sz dst op src

    (** produces the list of states for for ADD, SUB, ADC, SBB depending of the value of the operator and the boolean value (=true for carry or borrow) *)
    let add_sub s op b dst src sz = return s (add_sub_stmts op b dst src sz)


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
                carry_flag_stmts sz e1 Sub e2; overflow_flag_stmts sz res e1 e2; zero_flag_stmts sz res;
                sign_flag_stmts sz res           ; parity_flag_stmts sz res     ; adjust_flag_stmts res sz e1 e2
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
        let res'  = Lval dst			        in
        let flag_stmts =
            [
                clear_flag fcf; clear_flag fof; zero_flag_stmts sz res';
                sign_flag_stmts sz res';
                parity_flag_stmts sz res'; undef_flag faf
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
                overflow_flag_stmts sz res op1 op2   ; zero_flag_stmts sz res;
                parity_flag_stmts sz res; adjust_flag_stmts res sz op1 op2;
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
      Directive (Taint (BinOp (Or, Lval (M (Lval (V (to_reg edi s.addr_sz)), i)), Lval (M (Lval (V (to_reg esi s.addr_sz)), i))), ecx))
	
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
	let taint_stmt = Directive (Taint (BinOp (Or, Lval (V (to_reg eax i)), Lval (M (Lval (V (to_reg esi s.addr_sz)), 8))), ecx)) in
        return s ((Set (eax', Lval mesi'))::taint_stmt::(inc_dec_wrt_df [esi] i))

    (** state generation for SCAS *)
    let scas s i =
        let eax' = V (to_reg eax i)                    in
        let edi' = V (to_reg edi s.addr_sz)            in
        let mem  = M (add_segment s (Lval edi') es, i) in
	let taint_stmt = Directive (Taint (BinOp (Or, Lval (V (to_reg eax i)), Lval (M (Lval (V (to_reg edi s.addr_sz)), i))), ecx)) in 
        return s ((cmp_stmts (Lval eax') (Lval mem) i) @ [taint_stmt] @ (inc_dec_wrt_df [edi] i) )


    (** state generation for STOS *)
    let stos s i =
        let eax'  = V (to_reg eax i)                     in
        let edi'  = V (to_reg edi s.addr_sz)             in
        let medi' = M (add_segment s (Lval edi') ds, i)  in
        let stmts = Set (medi', Lval eax')               in
	let taint_stmt = Directive (Taint (BinOp (Or, Lval (V (to_reg eax i)), Lval (M (Lval (V (to_reg edi s.addr_sz)), i))), ecx)) in
        return s (stmts::taint_stmt::(inc_dec_wrt_df [edi] i))

    (** state generation for INS *)
    let taint_ins_outs s i =
      Directive (Taint (BinOp (Or, Lval (M (Lval (V (to_reg edi s.addr_sz)), i)), Lval (M (Lval (V (to_reg esi s.addr_sz)), i))), ecx))
	
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
        let s   = Hashtbl.find (if csv.ti = GDT then s.segments.gdt else s.segments.ldt) csv.index in
        let i   = Address.to_int target							     in
        if Z.compare (Z.add s.base i) s.limit >= 0 then
            ()
        else
            error a "Decoder: jump target out of limits of the code segments (GP exception in protected mode)"

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
        let o  = int_of_bytes s 1                                                           in
        let a' = Address.add_offset s.a o                                                   in
        check_jmp s a';
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
            let stmt = set_eflags (Lval tmp) sz in
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
                        if is_esp lv then
                            (* save the esp value to its value before the first push (see PUSHA specifications) *)
                            Set (M (Lval (V esp'), s.operand_sz), Lval (V (T t)))
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
        let c     = get_imm s sz !Config.stack_width false in
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
            if sz = 16 then
                (* if sz = 16 should AND EFLAGS with 00FCFFFFH) *)
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
        let dst, src  = operands_from_mod_reg_rm s s.operand_sz 0 in
        let cond_stmt = exp_of_cond cond s in
        return s [ If (cond_stmt, [ Set(dst, src) ], []) ]

    (*******************************)
    (* multiplication and division *)
    (*******************************)

    let mul_stmts dst sz =
        let eax_v = (find_reg_v 0 sz) in
        let mul_s = [ Set(eax_v, (BinOp(Mul, (Lval eax_v), dst))) ] in
        let flags_stmts = [ undef_flag fsf;  undef_flag fzf; undef_flag faf; undef_flag fpf;
            (* The OF and CF flags are set to 0 if the upper half of the result
               is 0; otherwise, they are set to 1.  *)
            If(Cmp(EQ, Const (Word.zero sz), Lval (V( P(eax, sz/2, sz-1)))),
                [clear_flag fcf; clear_flag fof],
                [set_flag fcf; set_flag fof])
            ] in
        mul_s @ flags_stmts

    let idiv_stmts (reg : Asm.exp)  sz =
        let eax_r = (to_reg eax sz) in let eax_lv = Lval( V (eax_r)) in
        let edx_r = (to_reg edx sz) in let edx_lv = Lval( V (edx_r)) in
        let tmp   = Register.make ~name:(Register.fresh_name()) ~size:(sz*2) in
        let tmp_div   = Register.make ~name:(Register.fresh_name()) ~size:(sz*2) in
        let set_tmp = Set (V (T tmp), BinOp(Or, BinOp(Shl, edx_lv, Const (Word.of_int (Z.of_int sz) sz)), eax_lv)) in
        [set_tmp; Set (V(T tmp_div), BinOp(Div, Lval (V (T tmp)), reg)); 
         (* TODO : assert *)
         (* compute remainder *)
         Set (V(edx_r), BinOp(Sub, Lval(V(T tmp)), Lval(V(T tmp_div))));
         Set (V(eax_r), Lval (V (P (tmp_div, 0, sz-1))));
         Directive (Remove tmp); Directive (Remove tmp_div)]


    (*****************************************************************************************)
    (* decoding of opcodes of groups 1 to 8 *)
    (*****************************************************************************************)


    let core_grp s sz =
        let md, nnn, rm = mod_nnn_rm (Char.code (getchar s)) in
        let dst 	= exp_of_md s md rm sz		     in
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

    let shift_l_stmt dst sz n =
        let sz' = const sz sz in
        let one = Const (Word.one sz) in
        let ldst = Lval dst in
        let cf_stmt =
            let c = Cmp (LT, sz', n) in
            If (c,
                [undef_flag fcf],
                (* CF is the last bit having been "evicted out" *)
                [Set (V (T fcf), BinOp (And, one, (BinOp(Shr, ldst, BinOp(Sub, sz', n)))))])
        in
        let of_stmt =
          let is_one = Cmp (EQ, n, one) in
          let op =
            (* last bit having been "evicted out"  xor CF*)
            Set (V (T fof),
                 BinOp(Xor, Lval (V (T fcf)),
                       BinOp (And, one,
                              (BinOp(Shr, ldst,
				     BinOp(Sub, sz', n))))))
          in
          If (is_one,    (* OF is set if n == 1 only *)
              [op] ,
              [undef_flag fof])
        in
	let lv = Lval dst in
        let ops =
                [
                 Set (dst, BinOp (Shl, ldst, n));
                 (* previous cf is used in of_stmt *)
                 of_stmt; cf_stmt; undef_flag faf;
                 (sign_flag_stmts sz lv) ; (zero_flag_stmts sz lv) ; (parity_flag_stmts sz lv)
		]
        in
        (* If shifted by zero, do nothing, else do the rest *)
        [If(Cmp(EQ, n, Const (Word.zero sz)), [], ops)]

    let core_rotate dst src op sz count =
      let cf_stmt = Set (V (T fcf), BinOp(op, Lval dst, Const (Word.of_int (Z.of_int (sz-1)) sz))) in
      (* of flag is affected only by single-bit rotate ; otherwise it is undefined *)
      let of_stmt = If (Cmp (EQ, count, Const (Word.one sz)), [Set (V (T fof), Lval (V (T fcf)))], [undef_flag fof]) in
      (* beware of that : of_stmt has to be analysed *after* having set cf *)
      let stmts =  [Set (dst, src) ; cf_stmt ; of_stmt ] in
      [ If (Cmp(EQ, count, Const (Word.zero sz)), [], stmts)]
	
    let rotate_l_stmt dst sz count =
      let high = BinOp (Shr, Lval dst, BinOp (Sub, Const (Word.of_int (Z.of_int (sz-1)) sz), count)) in
      let low = BinOp (Shl, Lval dst, count) in
      let src = BinOp (Add, high, low) in
      core_rotate dst src Shl sz count

    let rotate_r_stmt dst sz count =
      let high = BinOp (Shl, Lval dst, count) in
      let low = BinOp (Shr, Lval dst, BinOp(Sub, Const (Word.of_int (Z.of_int (sz-1)) sz), count)) in
      let src = BinOp(Add, high, low) in
      core_rotate dst src Shr sz count
		  
    let shift_r_stmt dst sz n arith =
        let sz' = const sz sz in
        let one = Const (Word.one sz) in
        let ldst = Lval dst in
        let dst_sz_min_one = const (sz-1) sz in
        let dst_msb = BinOp(And, Const (Word.one sz), BinOp(Shr, ldst, dst_sz_min_one)) in
        let cf_stmt =
            let c = Cmp (LT, sz', n) in
            If (c,
                [undef_flag fcf],
                (* CF is the last bit having been "evicted out" *)
                [Set (V (T fcf), BinOp (And, one, (BinOp(Shr, ldst, BinOp(Sub,n, one)))))])
        in
        let of_stmt =
                let is_one = Cmp (EQ, n, one) in
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
                [
                (* Compute sign extend mask if needed *)
                 If (Cmp (EQ, dst_msb, one),
                    [Set (dst, BinOp(Or, BinOp (Shr, ldst, n), one))], (* TODO :extend *)
                    [Set (dst, BinOp (Shr, ldst, n))] (* no extend *)
                    );
                 cf_stmt ; of_stmt ; undef_flag faf;
                ]
            else
                [
                 Set (dst, BinOp (Shr, ldst, n));
                 cf_stmt ; of_stmt ; undef_flag faf;
                ]
        in
        (* If shifted by zero, do nothing, else do the rest *)
	let res = Lval dst in
        [If(Cmp(EQ, n, Const (Word.zero sz)), [], ops @ [(sign_flag_stmts sz res) ; (zero_flag_stmts sz res) ; (parity_flag_stmts sz res)] )]

    let grp2 s sz e =
        let nnn, dst = core_grp s sz in
        let n =
            match e with
            | Some e' -> e'
            | None -> get_imm s 8 sz false
        in
        match nnn with
	| 0 -> return s (rotate_l_stmt dst sz n) (* ROL *)
	| 1 -> return s (rotate_r_stmt dst sz n) (* ROR *)
        | 4 -> return s (shift_l_stmt dst sz n) (* SHL/SAL *)
        | 5 -> return s (shift_r_stmt dst sz n false) (* SHR *)
       	| 7 -> return s (shift_r_stmt dst sz n true) (* SAR *)
        | _ -> error s.a "Illegal opcode in grp 2"

    let grp3 s sz =
        let nnn, reg = core_grp s sz in
        let stmts =
            match nnn with
            | 0 -> (* TEST *) let imm = get_imm s sz sz false in test_stmts reg imm sz
            | 2 -> (* NOT *) [ Set (reg, UnOp (Not, Lval reg)) ]
            | 3 -> (* NEG *) [ Set (reg, BinOp (Sub, Const (Word.zero sz), Lval reg)) ]
            | 4 -> (* MUL *) mul_stmts (Lval reg) sz
            | 7 -> (* IDIV *) idiv_stmts (Lval reg) sz
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

    let bts_stmt dst nbit = Set (dst, BinOp (Or, Lval dst, BinOp (Shl, Const (Data.Word.one 1), nbit)))
    let btr_stmt dst nbit = Set (dst, BinOp (And, Lval dst, UnOp (Not, BinOp (Shl, Const (Data.Word.one 1), nbit))))
    let bt s dst src = core_bt s (fun _nth _nbit -> []) dst src
    let bts s dst src = core_bt s (fun nth _nbit -> [bts_stmt dst nth]) dst src
    let btr s dst src = core_bt s (fun nth _nbit -> [btr_stmt dst nth]) dst src
    let btc s dst src = core_bt s (fun _nth nbit -> [If (Cmp (EQ, nbit, Const (Word.one 1)), [btr_stmt dst nbit], [bts_stmt dst nbit])]) dst src

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
    let fal = BinOp (And, Lval al, const 0xF 8)
    let fal_gt_9 = Cmp (GT, fal, const 9 8)
    let faf_eq_1 = Cmp (EQ, Lval (V (T faf)), Const (Word.one 1))

    let core_aaa_aas s op =
        let al_op_6 = BinOp (op, Lval al, const 6 8) in
        let ah      = V (P (eax, 24, 31))                                     in
        let set     = Set (al, fal)	                                      in
        let istmts =
            [
                Set (al, al_op_6);
                Set (ah, BinOp(op, Lval ah, Const (Word.one 8)));
                set_flag faf;
                set_flag fcf;
                set
            ]
        in
        let estmts =
            [
                clear_flag faf;
                clear_flag fcf;
                set
            ]
        in
        let c  = BBinOp (LogOr, fal_gt_9, faf_eq_1) in
        let stmts =
            [
                If (c, istmts, estmts);
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
        let carry  = If(BBinOp (LogOr, Cmp (EQ, Lval (V (T old_cf)), Const (Word.one 1)), BBinOp (LogOr, fal_gt_9, faf_eq_1)), [set_flag fcf],[clear_flag fcf]) in

        let if1 = If (BBinOp (LogOr, fal_gt_9, faf_eq_1),
                      [ Set(al, al_op_6); carry; set_flag faf],
                      [clear_flag faf])
        in
        let if2 = If (BBinOp (LogOr, Cmp (GT, Lval (V (T old_al)), const 0x99 8), Cmp(EQ, Lval (V (T old_cf)), Const (Word.one 1))),
                      [Set (al, BinOp(op, Lval al, const 0x60 8))],
                      [clear_flag fcf])
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
        let dst = exp_of_md s md rm 8 in
        return s [If (e, [Set (dst, Const (Word.one 8))], [Set (dst, Const (Word.zero 8))])]

    let xchg s v1 v2 sz =
        let tmp   = Register.make ~name:(Register.fresh_name()) ~size:sz in
        let stmts = [ Set(V (T tmp), Lval (V v1)); Set(V v1, Lval (V v2)) ;
                      Set(V v2, Lval (V (T tmp)))  ; Directive (Remove tmp) ]
        in
        return s stmts

    let xchg_with_eax s v =
        let eax = to_reg eax s.operand_sz in
        let v'  = find_reg v s.operand_sz in
        xchg s eax v' s.operand_sz

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

    (** decoding of one instruction *)
    let decode s =
        let add_sub_mrm s op b sz direction =
            let dst, src = operands_from_mod_reg_rm s sz direction in
            add_sub s op b dst src sz
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
            | '\x6A' -> (* PUSH byte *) push_immediate s 8

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
            | '\x86' -> (* XCHG byte registers *) let _, reg, rm = mod_nnn_rm (Char.code (getchar s)) in xchg s (find_reg rm 8) (find_reg reg 8) 8
            | '\x87' -> (* XCHG word or double-word registers *) let _, reg, rm = mod_nnn_rm (Char.code (getchar s)) in xchg s (find_reg rm s.operand_sz) (find_reg reg s.operand_sz) s.operand_sz
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
            | '\xa0' -> (* MOV EAX *) mov_with_eax s 8 true
            | '\xa1' -> (* MOV EAX *) mov_with_eax s s.operand_sz true
            | '\xa2' -> (* MOV EAX *) mov_with_eax s 8 false
            | '\xa3' -> (* MOV EAX *) mov_with_eax s s.operand_sz false
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
              let n = (Char.code c) - 0xb0          in
              let r = V (P (Hashtbl.find register_tbl n, 24, 32)) in
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
            | '\xd1' -> (* grp2 shift with one on word or double size *) grp2 s s.operand_sz (Some (Const (Word.one s.operand_sz)))
            | '\xd2' -> (* grp2 shift with CL and byte size *) grp2 s 8 (Some (Lval (V (to_reg ecx 8))))
            | '\xd3' -> (* grp2 shift with CL *) grp2 s s.operand_sz (Some (Lval (V (to_reg ecx 8))))

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
            | '\xf3' -> (* REP/REPE *) s.repne <- false; rep s Word.zero
            | '\xf4' -> (* HLT *) error s.a "Decoder stopped: HLT reached"
            | '\xf5' -> (* CMC *) let fcf' = V (T fcf) in return s [ Set (fcf', UnOp (Not, Lval fcf')) ]
            | '\xf6' -> (* shift to grp3 with byte size *) grp3 s 8
            | '\xf7' -> (* shift to grp3 with word or double word size *) grp3 s s.operand_sz
            | '\xf8' -> (* CLC *) return s (clear_flag fcf fcf_sz)
            | '\xf9' -> (* STC *) return s (set_flag fcf fcf_sz)
            | '\xfa' -> (* CLI *) Log.from_decoder "entering privilege mode (CLI instruction)"; return s (clear_flag fif fif_sz)
            | '\xfb' -> (* STI *) Log.from_decoder "entering privilege mode (STI instruction)"; return s (set_flag fif fif_sz)
            | '\xfc' -> (* CLD *) return s (clear_flag fdf fdf_sz)
            | '\xfd' -> (* STD *) return s (set_flag fdf fdf_sz)
            | '\xfe' -> (* INC/DEC grp4 *) grp4 s
            | '\xff' -> (* indirect grp5 *) grp5 s
            | c ->  error s.a (Printf.sprintf "Unknown opcode 0x%x" (Char.code c))

        (** rep prefix *)
        and rep s c =
            let ecx_cond  = Cmp (NEQ, Lval (V (to_reg ecx s.addr_sz)), Const (Word.zero s.addr_sz)) in
            (* thanks to check_context at the beginning of decode we know that next opcode is SCAS/LODS/STOS/CMPS *)
            (* otherwise decoder halts *)
            let v, ip = decode s in
            let a'  = Data.Address.add_offset s.a (Z.of_int s.o) in
            let zf_stmts =
                if s.repe || s.repne then
                    [ If (Cmp (EQ, Lval (V (T fzf)), Const (c fzf_sz)), [Jmp (A a')], [Jmp (A v.Cfa.State.ip) ]) ]
                else
                    [ Jmp (A v.Cfa.State.ip) ]
            in
            let ecx' = V (to_reg ecx s.addr_sz) in
            let ecx_stmt = Set (ecx', BinOp (Sub, Lval ecx', Const (Word.one s.addr_sz))) in    
            let blk = 
	      [
		If (ecx_cond,
		    v.Cfa.State.stmts @ (ecx_stmt :: zf_stmts),
		    [ Jmp (A a')])
	      ] in
            v.Cfa.State.stmts <- blk;
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
            | '\xa8' -> push s [V (T gs)]
            | '\xa9' -> pop s [V (T gs)]
            | '\xab' -> let reg, rm = operands_from_mod_reg_rm s s.operand_sz 0 in bts s reg rm

            | '\xb2' -> load_far_ptr s ss
            | '\xb3' -> let reg, rm = operands_from_mod_reg_rm s s.operand_sz 0 in btr s reg rm
            | '\xb4' -> load_far_ptr s fs
            | '\xb5' -> load_far_ptr s gs

            | '\xb6' -> let reg, rm = operands_from_mod_reg_rm s 8 ~dst_sz:s.operand_sz 1 in
              return s [ Set (reg, UnOp(ZeroExt s.operand_sz, rm)) ]
            | '\xb7' ->
              let reg, rm = operands_from_mod_reg_rm s 16 1 in
              return s [ Set (reg, UnOp(ZeroExt s.operand_sz, rm)) ]

            | '\xba' -> grp8 s
            | '\xbb' -> let reg, rm = operands_from_mod_reg_rm s s.operand_sz 0 in btc s reg rm

            | '\xbe' -> let reg, rm = operands_from_mod_reg_rm s 8  ~dst_sz:s.operand_sz 1 in
              return s [ Set (reg, UnOp(SignExt s.operand_sz, rm)) ];
            | '\xbf' -> let reg, rm = operands_from_mod_reg_rm s !Config.operand_sz 1 in return s [ Set (reg, UnOp(SignExt s.operand_sz, rm)) ]
            | c 	   -> error s.a (Printf.sprintf "unknown second opcode 0x%x\n" (Char.code c))
        in
        decode s;;

     (** initialization of the decoder *)
    let init () =
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
        | _ 			    -> (*end of buffer *) None
end
(* end Decoder *)

