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
      let _fif   = Register.make ~name:"if" ~size:1;; 
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
	  | _ -> raise (Exceptions.Error "Invalid decription table selection")
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
      type tbl_entry = { base: Z.t; limit: Z.t; a: Z.t; typ: segment_descriptor_type; dpl: privilege_level; p: Z.t; u: Z.t; x: Z.t; d: Z.t; g: Z.t;}

      (** return a high level representation of a GDT/LDT entry *)
      let tbl_entry_of_int v =
	let ffff  = Z.of_int 0xffff					   in
	let ff 	  = Z.of_int 0xff					   in
	let f 	  = Z.of_int 0x0f					   in
	let limit = Z.logand v ffff    					   in
	let v' 	  = Z.shift_right v 16	                                   in
	let base  = Z.logand v ffff 					   in
	let v' 	  = Z.shift_right v' 16	 			           in
	let base  = Z.add base (Z.shift_left (Z.logand v' ff) 16)	   in
	let v' 	  = Z.shift_right v' 8				   	   in
	let a 	  = Z.logand v' Z.one				   	   in
	let v' 	  = Z.shift_right v' 1  				   in
	let typ   = segment_descriptor_of_int (Z.to_int (Z.logand v' f))   in
	let v' 	  = Z.shift_right v' 4				 	   in	
	let dpl   = Z.logand v' (Z.of_int 3)				   in
	let v' 	  = Z.shift_right v' 2				 	   in
	let p 	  = Z.logand v' Z.one				 	   in
	let v' 	  = Z.shift_right v' 1        			 	   in 
	let limit = Z.add limit (Z.shift_left (Z.logand v' f) 16)	   in	
	let v' 	  = Z.shift_right v' 4				 	   in
	let u 	  = Z.logand v' Z.one				 	   in
	let v' 	  = Z.shift_right v' 1  			 	   in
	let x 	  = Z.logand v' Z.one				 	   in
	let v' 	  = Z.shift_right v' 1   		                   in
	let d 	  = Z.logand v' Z.one				 	   in
	let v' 	  = Z.shift_right v' 1  		    		   in
	let g 	  = Z.logand v' Z.one				 	   in
	let base  = Z.add base (Z.shift_left (Z.shift_right v' 1) 24)      in
	{ limit = limit; base = base; a = a; typ = typ; dpl = privilege_level_of_int (Z.to_int dpl); p = p; u = u; x = x; d = d; g = g; }

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

      

      (***********************************************************************)
      (* Char transformations *)
      (***********************************************************************)

      (** extract from the string code the current byte to decode *)
      (** the offset field of the decoder state is increased *)
      let getchar s =
	let c = String.get s.buf s.o in
	s.o <- s.o + 1;
	c


      (** int conversion of a byte in the string code *)
      let int_of_byte s = Z.of_int (Char.code (getchar s))
				    
      (** [int_of_bytes s sz] is an integer conversion of sz bytes of the string code s.buf *)  
      let int_of_bytes s sz =
	let n = ref Z.zero in
	for i = 0 to sz-1 do
	  n := Z.add (!n) (Z.shift_left (int_of_byte s) (8*i));
	done;
	!n;;

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
      let get_base_address s c =
	if !Config.mode = Config.Protected then
	  let dt = if c.ti = GDT then s.segments.gdt else s.segments.ldt in 
	  try
	      let e = Hashtbl.find dt c.index in
	      if c.rpl <= e.dpl then
		e.base
	      else
		raise (Exceptions.Error "illegal requested privileged level")
	  with Not_found ->
	    raise (Exceptions.Error (Printf.sprintf "illegal requested index %s in %s Description Table" (Word.to_string c.index) (if c.ti = GDT then "Global" else "Local")))
	else
	  raise (Exceptions.Error "only protected mode supported")

      (** initialization of the segmentation *)
      let init () =
	let ldt = Hashtbl.create 5  in
	let gdt = Hashtbl.create 19 in
	let idt = Hashtbl.create 15 in
	(* builds the gdt *)
	Hashtbl.iter (fun o v -> Hashtbl.replace gdt (Word.of_int o 64) (tbl_entry_of_int v)) Config.gdt;
	let reg = Hashtbl.create 6 in
	List.iter (fun (r, v) -> Hashtbl.add reg r (get_segment_register_mask v)) [cs, !Config.cs; ds, !Config.ds; ss, !Config.ss; es, !Config.es; fs, !Config.fs; gs, !Config.gs];
	{ gdt = gdt; ldt = ldt; idt = idt; data = ds; reg = reg;}

      let get_segments ctx =
	let registers = Hashtbl.create 6 in
	try
	  List.iter (fun r -> Hashtbl.add registers r (get_segment_register_mask (ctx#value_of_register r))) [ cs; ds; ss; es; fs; gs ];
	  registers
	with _ -> raise (Exceptions.Error "Decoder: overflow in a segment register") 
	  
      let copy_segments s ctx = { gdt = Hashtbl.copy s.gdt; ldt = Hashtbl.copy s.ldt; idt = Hashtbl.copy s.idt; data = ds; reg = get_segments ctx  }
	


      (************************************************************************************)
      (* common utilities *)
      (************************************************************************************)
	
      (** returns the right Asm.reg value from the given register and context of decoding *)
      let to_reg r sz =
	if Register.size r = sz then
	  T r
	else
	  P (r, 0, sz-1)

      (** returns the right Asm.reg value from the register corresponding to the given numeber and context of decoding *)
      let find_reg n sz =
	let r = Hashtbl.find register_tbl n in
	to_reg r sz

      (** add a new state with the given statements *)
      (** an edge between the current state and this new state is added *)
      let create s stmts label =
	let ctx = { Cfa.State.addr_sz = s.addr_sz ; Cfa.State.op_sz = s.operand_sz }                        in
	let v   = Cfa.add_state s.g (Address.add_offset s.a (Z.of_int s.o)) s.b.Cfa.State.v stmts ctx false in
	let label' =
	  match label with
	  | None   -> None
	  | Some f -> Some (f s)
	in
	Cfa.add_edge s.g s.b v label';
	[v]

      (************************************************)
      (* MOD REG R/M *)
      (************************************************)
      (** [mod_nnn_rm v] decompose from v the triple (mod, nnn, rm) where mod are its bits 7-6, nn its bits 5,4,3 and rm its bits 2, 1, 0 *)
      let mod_nnn_rm v =
	let rm 	= v land 7	   in
	let nnn = (v lsr 3) land 7 in
	let md 	= (v lsr 6)	   in
	md, nnn, rm	 

      (** returns the sub expression used in a displacement *)
      let disp s nb =
	let n = int_of_bytes s (nb/Config.size_of_byte) in
	Const (Word.of_int n nb)

      (** returns the expression associated to a sib *)
      let sib s reg md =
	let c 		       = getchar s                                        in
	let scale, index, base = mod_nnn_rm (Char.code c)                         in
	if index = 4 then raise (Exceptions.Error "Decoder: Illegal index value in sib (0x04)");
	let index' 	       = find_reg index s.operand_sz                      in
	let e 		       = UnOp (Shl scale, Lval (V index'))                in
	match base with
	| 5 when md = 0 -> e
	| _ 	        -> BinOp (Add, e, Lval (V reg))

      exception Disp32

      let add_segment s e sreg =
	let m      = Hashtbl.find s.segments.reg sreg in 
	let ds_val = get_base_address s m             in
	BinOp(Add, e, Const (Word.of_int ds_val s.operand_sz))
	
      let operands_from_mod_reg_rm s v =

	let add_data_segment e = add_segment s e s.segments.data                            in	 
	let c 		       = getchar s  						    in
	let md, reg, rm        = mod_nnn_rm (Char.code c)				    in
	let direction 	       = (v lsr 1) land 1   					    in
	let sz                 = if v land 1 = 0 then Config.size_of_byte else s.operand_sz in
	let rm' 	       = find_reg rm sz 					    in
	let reg                = find_reg reg sz                                            in
	try
	  let reg' =
	    match md with
	    | 0 ->
	       begin
		 match rm with
		 | 4 -> M ( add_data_segment (sib s reg md), sz)
		 | 5 -> raise Disp32
		 | _ -> M (add_data_segment (Lval (V reg)), sz)
	       end						    
	    | 1 ->
	       let e =
		 if rm = 4 then sib s reg md
		 else Lval (V reg)
	       in
	       let e' = BinOp (Add, e, disp s 8) in
	       M (add_data_segment e', sz)
	     	 
	    | 2 ->
	       let e =
		 if rm = 4 then sib s reg md
		 else Lval (V reg)
	       in
	       let e' = BinOp (Add, e, disp s 32) in
	       M (add_data_segment e', sz)
		 
	    | 3 -> flush stdout; V reg
	    | _ -> raise (Exceptions.Error "Decoder: illegal value for md in mod_reg_rm extraction")
			     
	  in
	  if direction = 0 then
	    (V rm'), Lval (M (Lval reg', sz))
	  else
	    reg', Lval (V rm')
	with
	  Disp32 -> 
	  if direction = 0 then
	    V rm', add_data_segment (disp s 32)
	  else
	    raise (Exceptions.Error "Decoder: illegal direction for displacement only addressing mode")
		      
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

				 
      (** produce common statements to set the overflow flag and the adjust flag *) 
      let overflow flag n nth res op1 op2 =
	(* flag is set if both op1 and op2 have the same nth bit whereas different from the hightest bit of res *)
	let b1        = Const (Word.of_int Z.one 1)                  in
	let shn       = Shr nth                                      in
	let sign_res  = BinOp(And, UnOp (shn, res), b1)              in
	let sign_op1  = BinOp(And, UnOp (shn, op1), b1)	             in
	let sign_op2  = BinOp(And, UnOp (shn, op2), b1)	             in
	let c1 	      = Cmp (EQ, sign_op1, sign_op2)   	       	     in
	let c2 	      = BUnOp (LogNot, Cmp (EQ, sign_res, sign_op1)) in
	let one_stmt  = Set (V (T flag), Const (Word.one n))	     in
	let zero_stmt = Set (V (T flag), Const (Word.zero n))	     in
	If (BBinOp (LogAnd, c1, c2), [ one_stmt ], [ zero_stmt ])

      (** produce the statement to set the overflow flag according to the current operation whose operands are op1 and op2 and result is res *)
      let overflow_flag_stmts res op1 op2 = overflow fof fof_sz (!Config.operand_sz-1) res op1 op2

      (** produce the statement to clear the overflow flag *)
      let clear_overflow_flag_stmts () = Set (V (T fof), Const (Word.zero fof_sz)) 

      (** produce the statement to set the carry flag according to the current operation whose operands are op1 and op2 and result is res *)
      let carry_flag_stmts sz res op1 op op2 = 
      (* fcf is set if the sz+1 bit of the result is 1 *)
	let s 	 = SignExt (sz+1)	  in
	let op1' = UnOp (s, op1)	  in
	let op2' = UnOp (s, op2)	  in
	let res' = BinOp (op, op1', op2') in
	If ( Cmp (EQ, res, res'), [ Set (V (T faf), Const (Word.zero faf_sz)) ], [ Set (V (T faf), Const (Word.one faf_sz)) ] )

      (** produce the statement to unset the carry flag *)
      let clear_carry_flag_stmts () = Set (V (T fcf), Const (Word.zero fcf_sz))

      (** produce the statement to undefine the adjust flag *)
      let undefine_adjust_flag_stmts () = Directive (Undef faf)

      (** produce the statement to set the sign flag *)					    
      let sign_flag_stmts res =
	let c = Cmp (EQ, Const (Word.one fsf_sz), UnOp(Shr 31, res)) in
	If (c, [ Set (V (T fsf), Const (Word.one fsf_sz)) ], [ Set (V (T fsf), Const (Word.zero fsf_sz))] ) 
	     
      (** produce the statement to set the zero flag *)	
      let zero_flag_stmts sz res =
	let c = Cmp (EQ, res, Const (Word.zero sz)) in
	If (c, [ Set (V (T fzf), Const (Word.one fzf_sz))], [Set (V (T fzf), Const (Word.zero fzf_sz))])

      (** produce the statement to set the adjust flag *)
      (** faf is set if there is an overflow on the bit 3 *)
      let adjust_flag_stmts res op1 op2 = overflow faf faf_sz 3 res op1 op2
					      
      (** produce the statement to set the parity flag *)					      
      let parity_flag_stmts sz res =
	(* fpf is set if res contains an even number of 1 in the least significant byte *)
	(* we sum every bits and check whether this sum is even or odd *)
	(* using the modulo of the divison by 2 *)
	let nth i =
	  let one = Const (Word.one (sz-i)) in
	  BinOp (And, UnOp(Shr i, res), one)
	in
	let e = ref (nth 0) in
	for i = 1 to 7 do
	  e := BinOp(Add, !e, nth i)
	done;
	let if_stmt   = Set (V (T fpf), Const (Word.one fpf_sz))			                    in
	let else_stmt = Set (V (T fpf), Const (Word.zero fpf_sz))			                    in
	let c 	      = Cmp (EQ, BinOp(Mod, !e, Const (Word.of_int (Z.of_int 2) sz)), Const (Word.zero sz)) in
	If(c, [ if_stmt ], [ else_stmt ]) 

					 
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
	    carry_flag_stmts sz res op1 op op2; overflow_flag_stmts res op1 op2; zero_flag_stmts sz res;
	    sign_flag_stmts res               ; parity_flag_stmts sz res       ; adjust_flag_stmts res op1 op2
	  ]
	in
	(Set (tmp, Lval dst)):: istmts @ flags_stmts @ [ Directive (Remove v) ]

     
     
      (** produces the list of statements for ADD, SUB, ADC, SBB depending of the value of the operator and the boolean value (=true for carry or borrow) *)							 
      let add_sub_stmts op b dst src sz =
	let e =
	  if b then BinOp (op, Lval dst, UnOp (SignExt sz, Lval (V (T fcf))))
	  else Lval dst
	in
	let res   = Set (dst, BinOp(op, e, src)) in
	add_sub_flag_stmts [res] sz dst op src 

	(** produces the list of states for for ADD, SUB, ADC, SBB depending of the value of the operator and the boolean value (=true for carry or borrow) *)
	let add_sub s op b dst src sz label = create s (add_sub_stmts op b dst src sz) label

	
      (** produces the state corresponding to an add or a sub with an immediate operand *)
      let add_sub_immediate s op b r sz label =
	let r'  = V (to_reg r sz)                                       in
	let sz' = sz / Config.size_of_byte                              in
	let w   = Const (Word.of_int (int_of_bytes s sz') s.operand_sz) in
	add_sub s op b r' w sz label
     
		     
      (** creates the states for OR, XOR, AND depending on the the given operator *)
      let or_xor_and s op dst src label =
	let res   = Set (dst, BinOp(op, Lval dst, src)) in
	let res'  = Lval dst			        in
	let flag_stmts =
	  [
	    clear_carry_flag_stmts (); clear_overflow_flag_stmts ()       ; zero_flag_stmts s.operand_sz res';
	    sign_flag_stmts res'     ; parity_flag_stmts s.operand_sz res'; undefine_adjust_flag_stmts ()
	  ]
	in
	create s (res::flag_stmts) label
		       
      (** [const c s] builds the asm constant c from the given context *)
      let const s c = Const (Word.of_int (Z.of_int c) s.operand_sz)
			    
      let inc_dec reg op s label =
	let dst 	= V reg                                       in
	let name        = Register.fresh_name ()                      in
	let v           = Register.make ~name:name ~size:s.operand_sz in
	let tmp         = V (T v)				      in
	let op1         = Lval tmp			              in
	let op2         = const s 1                                   in
	let res         = Lval dst			              in
	let flags_stmts =
	  [
	    overflow_flag_stmts res op1 op2   ; zero_flag_stmts s.operand_sz res;
	    parity_flag_stmts s.operand_sz res; adjust_flag_stmts res op1 op2;
	    sign_flag_stmts res
	  ]
	in
	let stmts = 
	  [ Set(tmp, Lval dst); Set (dst, BinOp (op, Lval dst, op2)) ] @ 
	    flags_stmts @ [Directive (Remove v)]
	in
	create s stmts label

      (*****************************************************************************************)
      (* decoding of opcodes of group 1 to 5 *)
      (*****************************************************************************************)

      let sign_extension_of_byte b nb =
	if Z.compare (Z.logand b (Z.of_int Config.size_of_byte)) Z.zero = 0 then
	  b
	else
	  let ff = ref "0xff" in
	  for _i = 1 to nb-1 do
	    ff := !ff ^ "ff"
	  done;
	  Z.add (Z.shift_left (Z.of_string !ff) Config.size_of_byte) b

      let core_grp s i reg_sz =
	let v 	= (Char.code (getchar s)) in
	let dst =
	  match v lsr 6 with
	  | 3 -> V (find_reg (v land 7) reg_sz)
	  | _ -> Log.error (Printf.sprintf "Decoder: unexpected mod field in group %d" i)
	in
	dst, (v lsr 3) land 7
	       
      let grp1 s reg_sz imm_sz label =
	let dst, nnn = core_grp s 1 reg_sz in
	let i = int_of_bytes s (imm_sz / Config.size_of_byte) in
	let i' =
	  if reg_sz = imm_sz then i
	  else sign_extension_of_byte i ((reg_sz / Config.size_of_byte)-1)
	in
	let c   = Const (Word.of_int i' reg_sz) in
	(* operation is encoded in bits 5,4,3 *)
	   match nnn with
	   | 0 -> add_sub s Add false dst c reg_sz label
	   | 1 -> or_xor_and s Or dst c label 
	   | 2 -> add_sub s Add true dst c reg_sz label
	   | 3 -> add_sub s Sub true dst c reg_sz label
	   | 4 -> or_xor_and s And dst c label 
	   | 5 -> add_sub s Sub false dst c reg_sz label
	   | 6 -> or_xor_and s Xor dst c label
	   | 7 -> (* cmp: like the x86 spec it is implemented as a Sub *) add_sub s Sub false dst c reg_sz label
	   | _ -> Log.error "Illegal nnn value in grp1"

      let grp3 s sz label =
	let dst, nnn = core_grp s 3 sz in
	match nnn with
	| 2 -> (* NOT *) create s [ Set (dst, UnOp (Not, Lval dst)) ] label
	| _ -> Log.error "Unknown operation in grp 3"
    
			   
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
	let c = Const (Word.of_int (Z.of_int (i / Config.size_of_byte)) i) in 
	let inc_dec op r =
	  Set (r, BinOp (op, Lval r, c))
	in
	  let istmts, estmts =
	    List.fold_left (fun (istmts, estmts) r -> (inc_dec Add r)::istmts, (inc_dec Sub r)::estmts) ([], []) regs
	  in
	  [ If ( Cmp (EQ, Lval (V (T fdf)), Const (Word.zero 1)), istmts, estmts ) ]

      (** state generation for MOVS *)			 
      let movs s i label =
	let edi'  = V (to_reg edi i)                    in
	let esi'  = V (to_reg esi i)                    in
	let medi' = M (add_segment s (Lval edi') es, i) in
	let mesi' = M (add_segment s (Lval esi') es, i) in
	create s ((Set (medi', Lval mesi'))::(inc_dec_wrt_df [edi' ; esi'] i)) label

	(** state generation for CMPS *)
	let cmps s i label = 
	  let edi'  = V (to_reg edi i)                    in
	  let esi'  = V (to_reg esi i)                    in
	  let medi' = M (add_segment s (Lval edi') es, i) in
	  let mesi' = M (add_segment s (Lval esi') es, i) in
	  create s ((add_sub_stmts Sub false medi' (Lval mesi') i) @ (inc_dec_wrt_df [edi' ; esi'] i)) label

	(** state generation for LODS *)
	let lods s i label =
	  let eax'  = V (to_reg eax i)                    in
	  let esi'  = V (to_reg esi i)                    in
	  let mesi' = M (add_segment s (Lval esi') es, i) in
	  create s ((Set (eax', Lval mesi'))::(inc_dec_wrt_df [esi'] i)) label

	(** state generation for SCAS *)
	let scas s i label =
	  let eax' = V (to_reg eax i)                    in
	  let edi' = V (to_reg edi i)                    in
	  let mem  = M (add_segment s (Lval edi') es, i) in
	  create s ((add_sub_stmts Sub false eax' (Lval mem) i) @ (inc_dec_wrt_df [edi'] i)) label


	(** state generation for STOS *)
	let stos s i label =
	  let eax'  = V (to_reg eax i)                    in
	  let edi'  = V (to_reg edi i)                    in
	  let medi' = M (add_segment s (Lval edi') es, i) in
	  create s ((Set (medi', Lval eax'))::(inc_dec_wrt_df [edi'] i)) label
		 
	(****************************************************)
	(* State generation for loop, call and jump instructions *)
	(****************************************************)
	(** returns the asm condition of jmp statements from an expression *)
	let exp_of_cond v s =
	  let const c  = const s c in
	  let eq f  = Cmp (EQ, Lval (V (T f)), const 1)  in
	  let neq f = Cmp (NEQ, Lval (V (T f)), const 1) in
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
	  | 15 -> (* (not (sf <> zf || zf == 1) = sf == zf && zf <> 1 *) BBinOp (LogAnd, Cmp (EQ, Lval (V (T fsf)), Lval (V (T fof))), neq fzf)
	  | _  -> raise (Exceptions.Error "Opcode.exp_of_cond: illegal value")

			

	(** checks that the target is within the bounds of the code segment *)
	let check_jmp s target =
	  let csv = Hashtbl.find s.segments.reg cs						     in
	  let s   = Hashtbl.find (if csv.ti = GDT then s.segments.gdt else s.segments.ldt) csv.index in
	  let i   = Address.to_int target							     in
	  if Z.compare s.base i < 0 && Z.compare i s.limit < 0 then
	    ()
	  else
	    raise (Log.error "Decoder: jump target out of limits of the code segments (GP exception in protected mode)")

	(** [create_jcc_stmts s e] creates the statements for conditional jumps: e is the condition and o the offset to add to the instruction pointer *)
	let create_jcc_stmts s e n label =
	  let o  = sign_extension_of_byte (int_of_bytes s 1) (n-1) in
	  let a' = Address.add_offset s.a o					            in
	  check_jmp s a';
	  let na = Address.add_offset s.a Z.one					            in
	  check_jmp s na;
	  create s [ If (e, [Jmp (Some (A a'))], [ Jmp (Some (A na)) ] ) ] label

	(** jump statements on condition *)
	 let jcc s v n label =
	   let e = exp_of_cond v s in
	   create_jcc_stmts s e n label

	 (** jump if eCX is zero *)
	 let jecxz s label =
	   let ecx' = to_reg ecx s.addr_sz				   in
	   let e    = Cmp (EQ, Lval (V ecx'), Const (Word.zero s.addr_sz)) in
	   create_jcc_stmts s e s.addr_sz label

	 (** common behavior between relative jump and relative call *)
	 let relative s i sz =
	   let o  = int_of_bytes s i in
	   let o' =
	     if i = 1 then sign_extension_of_byte o (( sz / Config.size_of_byte)-1)
	     else o
	   in
	   let a' = Address.add_offset s.a o' in
	   check_jmp s a';
	   a'
	
	 (** unconditional jump by adding an offset to the current ip *)
	 let relative_jmp s i label =
	   let a' = relative s i s.operand_sz in
	   create s [ Jmp (Some (A a')) ] label

	 (** common statement to move (a chunk of) esp by a relative offset *)
	 let set_esp op esp' n =
	   Set (V esp', BinOp (op, Lval (V esp'), Const (Word.of_int (Z.of_int (n / Config.size_of_byte)) !Config.stack_width)) )

	 (** call with target as an offset from the current ip *)
	 let relative_call s i label =
	   let a    = relative s i s.operand_sz                   in
	   let cesp = M (Lval (V (T esp)), !Config.stack_width)   in
	   let ip   = Const (Data.Address.to_word a s.operand_sz) in
	   let stmts =
	     [
	       Set (cesp, ip);
	       set_esp Sub (T esp) !Config.stack_width;
	       Call (A a)
	     ]
	   in
	   create s stmts label
	   
	 (** statements of jump with absolute address as target *)
	 let direct_jmp s label =
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
		   Log.error "decoder: tried a far jump into non code segment"
	       else Log.error "Illegal segment loading (privilege error)"
	     with _ -> Log.error "Illegal segment loading requested (illegal index in the description table)"
	   end;
	   Hashtbl.replace s.segments.reg cs v';
	   let a  = int_of_bytes s (s.operand_sz / Config.size_of_byte) in
	   let o  = Address.of_int Address.Global a s.operand_sz        in
	   let a' = Address.add_offset o v                              in
	   check_jmp s a';
	    (* creates the statements : the first one enables to update the interpreter with the new value of cs *)
	   create s [ Set (V (T cs), Const (Word.of_int v (Register.size cs))) ; Jmp (Some (A a')) ] label
		  
	 

		  
      (****************************************************************************************)
      (* Parsing *)
      (****************************************************************************************)
      let is_segment r = 
	match r with
	  T r | P(r, _, _) ->
		 Register.compare r cs = 0 || Register.compare r ds = 0
		 || Register.compare r ss = 0 || Register.compare r es = 0
		 || Register.compare r fs = 0 || Register.compare r gs = 0
	
      let is_esp r = 
	match r with 
	  T r | P(r, _, _) -> Register.compare r esp = 0

     
      (** builds a left value from esp that is consistent with the stack width *)
      let esp_lval () = if !Config.stack_width = Register.size esp then T esp else P(esp, 0, !Config.stack_width-1)

      (** common value used for the decoding of push and pop *)
      let size_push_pop v sz = if is_segment v then !Config.stack_width else sz

      (** state generation for pop instructions *)
      let pop s v label =
	let esp'  = esp_lval () in
	let stmts = List.fold_left (fun stmts v -> 
			let n = size_push_pop v s.operand_sz in
			[ Set (V v,
			       Lval (M (Lval (V esp'), n))) ; set_esp Add esp' n ] @ stmts
		      ) [] v 
	in
	create s stmts label

      (** generation of states for the push instructions *)
      let push s v label =
	(* TODO: factorize with POP *)
	let esp' = esp_lval () in
	let t    = Register.make (Register.fresh_name ()) (Register.size esp) in
	(* in case esp is in the list, save its value before the first push (this is this value that has to be pushed for esp) *)
	(* this is the purpose of the pre and post statements *)
	let pre, post =
	  if List.exists (fun v -> match v with T r | P (r, _, _) -> Register.is_stack_pointer r) v then
	    [ Set (V (T t), Lval (V esp')) ], [ Directive (Remove t) ]
	  else
	    [], []
	in
	let stmts =
	  List.fold_left (
	      fun stmts v ->
	      let n = size_push_pop v s.operand_sz in 
	      let s =
		if is_esp v then
		  (* save the esp value to its value before the first push (see PUSHA specifications) *)
		  Set (M (Lval (V esp'), n), Lval (V (T t)))
		else
		  Set (M (Lval (V esp'), n), Lval (V v));
	      in
	      [ s ; set_esp Sub esp' n ] @ stmts
	    ) [] v
	in
	create s (pre @ stmts @ post) label

      (** creates the state for the push of an immediate operands. Its size is given by the parameter *)
      let push_immediate s n label =
	let c     = Const (Word.of_int (int_of_bytes s n) !Config.stack_width) in
	let esp'  = esp_lval ()						       in
	let stmts = [ Set (M (Lval (V esp'), !Config.stack_width), c) ; set_esp Sub esp' !Config.stack_width ]			 
	in
	create s stmts label

      (********)
      (* misc *)
      (*****)
      let xchg s v label = 
	let tmp   = Register.make ~name:(Register.fresh_name()) ~size:s.operand_sz in
	let r     = find_reg v s.operand_sz					   in
	let eax   = to_reg eax s.operand_sz					   in 
	let stmts = [ Set(V (T tmp), Lval (V eax)); Set(V eax, Lval (V r)) ; 
		      Set(V r, Lval (V (T tmp)))  ; Directive (Remove tmp) ]
	in
	create s stmts label

      (** check whether an opcode is defined in a given state of the decoder *)
      let check_context s c =
	if s.rep then
	  match c with
	  | c when '\x6C' <= c && c <= '\x6F' (* INS and OUTS *) || '\xA4' <= c && c <= '\xA5' (* MOVS *) -> c
	  | c when '\xAE' <= c && c <= '\xAF' -> (* CMPS *) s.repe <- true; c
	  | c when '\xA6' <= c && c <= '\xA7' -> (* SCAS *) s.repe <-true; c
	  | _ -> Log.error (Printf.sprintf "Decoder: undefined behavior of REP with opcode %x" (Char.code c))
	else
	  if s.repne then
	    match c with
	    | c when '\xA6' <= c && c <= '\xA7' || '\xAE' <= c && c <= '\xAF' -> c
	    | _ -> Log.error (Printf.sprintf "Decoder: undefined behavior of REPNE/REPNZ with opcode %x" (Char.code c))
	  else
	    c
	  
      (** decoding of one instruction *)
      let decode s =
	let to_size s v =
	  if v land 1 = 1 then s.operand_sz
	  else Config.size_of_byte
	in
	let add_sub s op b c label =
	  let v        = Char.code c		      in
	  let dst, src = operands_from_mod_reg_rm s v in
	  let sz       = to_size s v		      in
	  add_sub s op b dst src sz label
	in
	let or_xor_and s op c label =
	  let v        = Char.code c                  in
	  let dst, src = operands_from_mod_reg_rm s v in
	  or_xor_and s op dst src label
	in
	let rec decode s label =
	  match check_context s (getchar s) with
	  | c when '\x00' <= c && c <= '\x03'  -> add_sub s Sub false c label
	  | '\x04' 			       -> add_sub_immediate s Add false eax Config.size_of_byte label
	  | '\x05' 			       -> add_sub_immediate s Add false eax s.operand_sz label
	  | '\x06' 			       -> let es' = to_reg es s.operand_sz in push s [es'] label
	  | '\x07' 			       -> let es' = to_reg es s.operand_sz in pop s [es'] label
	  | c when '\x08' <= c &&  c <= '\x0D' -> or_xor_and s Or c label
	  | '\x0E' 			       -> let cs' = to_reg cs s.operand_sz in push s [cs'] label
	  | '\x0F' 			       -> decode_snd_opcode s label
									       
	  | c when '\x10' <= c && c <= '\x13' -> add_sub s Add true c label
	  | '\x14' 			      -> add_sub_immediate s Add true eax Config.size_of_byte label
	  | '\x15' 			      -> add_sub_immediate s Add true eax s.operand_sz label
	  | '\x16' 			      -> let ss' = to_reg ss s.operand_sz in push s [ss'] label
	  | '\x17' 			      -> let ss' = to_reg ss s.operand_sz in pop s [ss'] label
	  | c when '\x18' <= c && c <='\x1B'  -> add_sub s Sub true c label
	  | '\x1C' 			      -> add_sub_immediate s Sub true eax Config.size_of_byte label
	  | '\x1D' 			      -> add_sub_immediate s Sub true eax s.operand_sz label
	  | '\x1E' 			      -> let ds' = to_reg ds s.operand_sz in push s [ds'] label
	  | '\x1F' 			      -> let ds' = to_reg ds s.operand_sz in pop s [ds'] label
										       
	  | c when '\x20' <= c && c <= '\x25' -> or_xor_and s And c label
	  | '\x26' 			      -> s.segments.data <- es; decode s label
	  | c when '\x28' <= c && c <= '\x2B' -> add_sub s Sub false c label
	  | '\x2C' 			      -> add_sub_immediate s Sub false eax Config.size_of_byte label
	  | '\x2D' 			      -> add_sub_immediate s Sub false eax s.operand_sz label
	  | '\x2E' 			      -> s.segments.data <- cs; (* will be set back to default value if the instruction is a jcc *) decode s label
								       
	  | c when '\x30' <= c &&  c <= '\x35' -> or_xor_and s Xor c label
	  | '\x36' 			       -> s.segments.data <- ss; decode s label
	  | c when '\x38' <= c && c <= '\x3B'  -> (* cmp *) add_sub s Sub false c label
	  | '\x3C' 			       -> add_sub_immediate s Sub false eax Config.size_of_byte label
	  | '\x3D' 			       -> add_sub_immediate s Sub false eax s.operand_sz label
	  | '\x3E' 			       -> s.segments.data <- ds (* will be set back to default value if the instruction is a jcc *); decode s label
									
	  | c when '\x40' <= c && c <= '\x47' -> let r = find_reg ((Char.code c) - (Char.code '\x40')) s.operand_sz in inc_dec r Add s label
	  | c when '\x48' <= c && c <= '\x4f' -> let r = find_reg ((Char.code c) - (Char.code '\x48')) s.operand_sz in inc_dec r Sub s label
															       
	  | c when '\x50' <= c && c <= '\x57' -> let r = find_reg ((Char.code c) - (Char.code '\x50')) s.operand_sz in push s [r] label
	  | c when '\x58' <= c && c <= '\x5F' -> let r = find_reg ((Char.code c) - (Char.code '\x58')) s.operand_sz in pop s [r] label
															   
	  | '\x60' -> let l = List.map (fun v -> find_reg v s.operand_sz) [0 ; 1 ; 2 ; 3 ; 5 ; 6 ; 7] in push s l label
	  | '\x61' -> let l = List.map (fun v -> find_reg v s.operand_sz) [7 ; 6 ; 3 ; 2 ; 1 ; 0] in pop s l label
	  | '\x64' -> s.segments.data <- fs; decode s label
	  | '\x65' -> s.segments.data <- ss; decode s label
	  | '\x66' -> s.operand_sz <- if s.operand_sz = 16 then 32 else 16; decode s label
	  | '\x67' -> s.addr_sz <- if s.addr_sz = 16 then 32 else 16; decode s label
	  | '\x68' -> push_immediate s 1 label
	  | '\x6A' -> push_immediate s (s.operand_sz / Config.size_of_byte) label
				     
	  | c when '\x6C' <= c && c <= '\x6F' -> Log.error "INS/OUTS instruction not precisely handled in that model"
								   
	  | c when '\x70' <= c && c <= '\x7F' -> let v = (Char.code c) - (Char.code '\x70') in jcc s v 1 label
												   
	  | '\x80' -> grp1 s Config.size_of_byte Config.size_of_byte label
	  | '\x81' -> grp1 s s.operand_sz s.operand_sz label
	  | '\x82' -> raise (Exceptions.Error "Undefined opcode 0x82")
	  | '\x83' -> grp1 s s.operand_sz Config.size_of_byte label
			   
	  | c when '\x88' <= c && c <= '\x8b' -> let dst, src = operands_from_mod_reg_rm s (Char.code c) in create s [ Set (dst, src) ] label
														
	  | '\x90' 			      -> create s [Nop] label
	  | c when '\x91' <= c && c <= '\x97' -> xchg s ((Char.code c) - (Char.code '\x90')) label
						      
						      
	  | '\xa4' -> movs s Config.size_of_byte label
	  | '\xa5' -> movs s s.addr_sz label
	  | '\xa6' -> cmps s Config.size_of_byte label
	  | '\xa7' -> cmps s s.addr_sz label
	  | '\xaa' -> stos s Config.size_of_byte label
	  | '\xab' -> stos s s.addr_sz label
	  | '\xac' -> lods s Config.size_of_byte label
	  | '\xad' -> lods s s.addr_sz label
	  | '\xae' -> scas s Config.size_of_byte label
	  | '\xaf' -> scas s s.addr_sz label

	  | '\xc3' -> create s [ Return; set_esp Add (T esp) !Config.stack_width; ] label
			     
	  | '\xe3' 			      -> jecxz s label

	  | '\xe9' 			      -> relative_jmp s (s.operand_sz / Config.size_of_byte) label
	  | '\xea' 			      -> direct_jmp s label
	  | '\xeb' 			      -> relative_jmp s 1 label
	  | '\xe8' 			      -> relative_call s (s.operand_sz / Config.size_of_byte) label
				    

	  | '\xf0' -> Log.error "LOCK instruction found. Interpreter halts"
	  | '\xf1' -> Log.error "Undefined opcode 0xf1"
	  | '\xf2' -> (* REP/REPE *) s.rep <- true; rep s Word.zero
	  | '\xf3' -> (* REPNE *) s.repne <- true; rep s Word.one
	  | '\xf4' -> raise (Exceptions.Error "Decoder stopped: HLT reached")
	  | '\xf5' -> let fcf' = V (T fcf) in create s [ Set (fcf', UnOp (Not, Lval fcf')
	  | '\xf6' -> grp3 s Config.size_of_byte label
	  | '\xf7' -> grp3 s s.operand_sz label
	  | '\xf8' -> let fcf' = V (T fcf) in create s [ Set (fcf', Const (Word.zero fcf_sz)) ]
	  | '\xf9' -> let fcf' = V (T fcf) in create s [ Set (fcf', Const (Word.one fcf_sz)) ]
	  | '\xfa' -> Log.error "CLI decoded. Interruptions not handled for the while"
	  | '\xfb' -> Log.error "STI decoded. Interruptions not handled for the while"
	  | '\xfc' -> let fdf' = V (T fdf) in create s [ Set (fdf', Const (Word.zero fdf_sz)) ]
	  | '\xfd' -> let fdf' = V (T fdf) in create s [ Set (fdf', Const (Word.one fdf_sz)) ]
						     
	  | c ->  raise (Exceptions.Error (Printf.sprintf "Unknown opcode 0x%x\n" (Char.code c)))

	(** rep prefix *)
	and rep s c =
	  (* create a state with an empty set of statements for the exit from the loop body -> body *)
	  let make_label neg s =
	    let ecx_cond  = Cmp (EQ, Lval (V (to_reg ecx s.addr_sz)), Const (c s.addr_sz)) in
	    let eq_c_cond = Cmp (EQ, Lval (V (T fzf)), Const (c fzf_sz))                   in
	    let e =
	      if s.repe || s.repne then
		BBinOp(LogOr, ecx_cond, eq_c_cond)
	      else ecx_cond
	    in
	    if neg then BUnOp (LogNot, e)
	    else e
	    in
	   (* thanks to check_context at the beginning of decode we know that next opcode is SCAS/LODS/etc. *)
	   (* otherwise decoder halts *)
	   let body = List.hd (decode s (Some (make_label false))) in
	   (* add an edge body -> s.b for the loop *)
	   Cfa.add_edge s.g body s.b None;
	   (* TODO: optimize : label is built twice (one for the if true branch and once for the false branch *)
	   body::(create s [] (Some (make_label true)))	    
	  
	and decode_snd_opcode s label =
	  match getchar s with
	  | c when '\x80' <= c && c <= '\x8f' -> let v = (Char.code c) - (Char.code '\x80') in jcc s v (s.operand_sz / Config.size_of_byte) label
	  | c 				      -> raise (Exceptions.Error (Printf.sprintf "unknown second opcode 0x%x\n" (Char.code c)))
	in
	  decode s None
					      
      (** launch the decoder *)
      let parse text g is v a ctx =
	  let s' = {
	    g 	       = g;
	    a 	       = a;
	    o 	       = 0;
	    addr_sz    = !Config.address_sz;
	    operand_sz = !Config.operand_sz; 
	    segments   = copy_segments is ctx;
	    rep_prefix = None;
	    buf        = text;
	    b 	       = v;
	    rep        = false;
	    repe       = false;
	    repne      = false
	    }
	  in
	  try
	    decode s', s'.segments
	  with
	  | Exceptions.Error _ as e -> raise e
	  | _ 			    -> (*end of buffer *) [], is
  end
    (* end Decoder *)

