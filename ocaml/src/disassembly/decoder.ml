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
	{ gdt = gdt; ldt = ldt; idt = idt; data = ds; reg = reg; }

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
      let create s stmts =
	let ctx = { Cfa.State.addr_sz = s.addr_sz ; Cfa.State.op_sz = s.operand_sz } in
	let v   = Cfa.add_state s.g (Address.add_offset s.a (Z.of_int s.o)) s.b.Cfa.State.v stmts ctx false in
	Cfa.add_edge s.g s.b v None;
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
		  
      let operands_from_mod_reg_rm s v =

	let add_data_segment e =
	  let m      = Hashtbl.find s.segments.reg s.segments.data in 
	  let ds_val = get_base_address s m                        in
	  BinOp(Add, e, Const (Word.of_int ds_val s.operand_sz))
	in
	let c 		= getchar s  						     in
	let md, reg, rm = mod_nnn_rm (Char.code c)				     in
	let direction 	= (v lsr 1) land 1   					     in
	let sz          = if v land 1 = 0 then Config.size_of_byte else s.operand_sz in
	let rm' 	= find_reg rm sz 					     in
	let reg         = find_reg reg sz                                            in
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
	let b1        = Const (Word.of_int Z.one 1)               in
	let shn       = Shr nth                                   in
	let sign_res  = BinOp(And, UnOp (shn, res), b1)           in
	let sign_op1  = BinOp(And, UnOp (shn, op1), b1)	          in
	let sign_op2  = BinOp(And, UnOp (shn, op2), b1)	          in
	let c1 	      = Cmp (EQ, sign_op1, sign_op2)   	       	  in
	let c2 	      = BUnOp (Not, Cmp (EQ, sign_res, sign_op1)) in
	let one_stmt  = Set (V (T flag), Const (Word.one n))	  in
	let zero_stmt = Set (V (T flag), Const (Word.zero n))	  in
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
      let undefine_adjust_flag_stmts () = Directive (Forget faf)

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
      let add_sub s op b dst src sz =
	let e =
	  if b then BinOp (op, Lval dst, UnOp (SignExt sz, Lval (V (T fcf))))
	  else Lval dst
	in
	let res   = Set (dst, BinOp(op, e, src))	   in
	let stmts = add_sub_flag_stmts [res] sz dst op src in
	create s stmts
	
      (** produces the state corresponding to an add or a sub with an immediate operand *)
      let add_sub_immediate s op b r sz =
	let r'  = V (to_reg r sz)                                       in
	let sz' = sz / Config.size_of_byte                              in
	let w   = Const (Word.of_int (int_of_bytes s sz') s.operand_sz) in
	add_sub s op b r' w sz
     
		     
      (** creates the states for OR, XOR, AND depending on the the given operator *)
      let or_xor_and s op dst src =
	let res   = Set (dst, BinOp(op, Lval dst, src)) in
	let res'  = Lval dst			        in
	let flag_stmts =
	  [
	    clear_carry_flag_stmts (); clear_overflow_flag_stmts ()       ; zero_flag_stmts s.operand_sz res';
	    sign_flag_stmts res'     ; parity_flag_stmts s.operand_sz res'; undefine_adjust_flag_stmts ()
	  ]
	in
	create s (res::flag_stmts)
		       
      (** [const c s] builds the asm constant c from the given context *)
      let const s c = Const (Word.of_int (Z.of_int c) s.operand_sz)
			    
      let inc_dec reg op s =
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
	create s stmts

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
	
      let grp1 s reg_sz imm_sz =
	let v 	= (Char.code (getchar s)) in
	let dst =
	  match v lsr 6 with
	  | 3 -> V (find_reg (v land 7) reg_sz)
	  | _ -> raise (Exceptions.Error "Decoder: unexpected mod field in group 1")
	in
	let i = int_of_bytes s (imm_sz / Config.size_of_byte) in
	let i' =
	  if reg_sz = imm_sz then i
	  else sign_extension_of_byte i ((reg_sz / Config.size_of_byte)-1)
	in
	let c   = Const (Word.of_int i' reg_sz) in
	(* operation is encoded in bits 5,4,3 *)
	   match ((v lsr 3) land 7) with
	   | 0 -> add_sub s Add false dst c reg_sz
	   | 1 -> or_xor_and s Or dst c 
	   | 2 -> add_sub s Add true dst c reg_sz
	   | 3 -> add_sub s Sub true dst c reg_sz
	   | 4 -> or_xor_and s And dst c
	   | 5 -> add_sub s Sub false dst c reg_sz
	   | 6 -> or_xor_and s Xor dst c
	   | 7 -> (* cmp: like the x86 spec it is implemented as a Sub *) add_sub s Sub false dst c reg_sz
	   | _ -> raise (Exceptions.Error "Illegal nnn value in grp1")

   
    
			   
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
		    
      let make_rep s str_stmt regs i =
	(* BE CAREFUL: be sure to return the vertices sorted by a topological order  *)
	let len      = Register.size ecx					     in
	let lv       = V(if s.addr_sz <> len then P(ecx, 0, s.addr_sz-1) else T ecx) in
	let ecx_decr = Set(lv, BinOp(Sub, Lval lv, Const (Word.one len)))	     in
	let test     = BUnOp (Not, Cmp (EQ, Lval lv, Const (Word.zero len)))         in (* lv <> 0 *)
	let test'    = 
	  if is_register_set str_stmt fzf then
	    let c = if s.rep_prefix = Some true then Const (Word.zero len) else Const (Word.one len)
	    in
	    BBinOp (LogOr, test, Cmp (EQ, Lval (V (T fzf)), c)) 
	  else test
	in
	let esi_stmt = 
	  if is_register_set str_stmt esi then 
	    let len = Register.size esi							  		      in
	    let lv  = V (if s.addr_sz <> len then P(esi, 0, s.addr_sz-1) else T esi)		  	      in
	    let e   = BinOp(Add, Lval lv, BinOp(Mul, Const (Word.of_int (Z.of_int 2) len), Lval (V (T fdf)))) in
	    [ Set(lv, BinOp(Add, Lval lv, e)) ]
	  else []
	in
	let edi_stmt =
	  (* TODO factorize with esi_stmt *)
	  if is_register_set str_stmt edi then 
	    let len = Register.size edi									    in
	    let lv = V(if s.addr_sz <> len then P(edi, 0, s.addr_sz-1) else T edi)			    in
	    let e = BinOp(Add, Lval lv, BinOp(Mul, Const (Word.of_int (Z.of_int 2) len), Lval (V (T fdf)))) in
	    [Set(lv, BinOp(Add, Lval lv, e))]
	  else []
	in
	let rep_blk = s.b in 
	Cfa.update_stmts s.b [If (test', [Jmp (Some (A s.a))], [ ] )] s.operand_sz s.addr_sz;
	Cfa.add_edge s.g s.b rep_blk None;
	let ctx = { Cfa.State.op_sz = s.operand_sz ; Cfa.State.addr_sz = s.addr_sz } in	
	let instr_blk = Cfa.add_state s.g s.a rep_blk.Cfa.State.v (str_stmt @ [ecx_decr] @ esi_stmt @ edi_stmt @ [ If ( Cmp (EQ, Lval (V(T fdf)), Const (Word.of_int Z.one 1)), [Jmp None], [])]) ctx true in 
	Cfa.add_edge s.g rep_blk instr_blk (Some true);
	let step     	= Const (Word.of_int (Z.of_int (i / Config.size_of_byte)) s.addr_sz) in
	let decr     	= 
	  if s.addr_sz <> len then 
	    List.map (fun r -> Set(V (T r), BinOp(Sub, Lval (V (T r)), step))) regs    
	  else
	    List.map (fun r -> Set(V (P(r, 0, s.addr_sz-1)), BinOp(Sub, Lval(V (P(r, 0, s.addr_sz-1))), step))) regs                                          in
	let decr_blk = Cfa.add_state s.g s.a instr_blk.Cfa.State.v decr ctx true in
	Cfa.add_edge s.g instr_blk decr_blk (Some true);
	let incr     	= 
	  if s.addr_sz <> len then 
	    List.map (fun r -> Set(V (T r), BinOp(Add, Lval (V (T r)), step))) regs    
	  else
	    List.map (fun r -> Set(V (P(r, 0, s.addr_sz-1)), BinOp(Add, Lval(V (P(r, 0, s.addr_sz-1))), step))) regs  
	in
	let incr_blk = Cfa.add_state s.g s.a instr_blk.Cfa.State.v incr ctx true
					 
        in
	Cfa.add_edge s.g instr_blk incr_blk (Some false);
	Cfa.add_edge s.g decr_blk rep_blk None;
	Cfa.add_edge s.g incr_blk rep_blk None;
	s.o <- s.o + 1;
	[rep_blk ; instr_blk ; incr_blk ; decr_blk]
      ;;

      (******************************************************************************************************)
      (* Generation of state for string manipulation                                                        *)
      (******************************************************************************************************)

      (** state generation for MOVS *)
	let movs s i = 
	   let _edi', _esi' =
	     if Register.size edi = i then
	       T edi, T esi
	     else
	       P (edi, 0, i-1), P (esi, 0, i-1)
	   in
	   let stmts = [ Set(M(failwith "exp MOVS case 1", s.operand_sz), Lval (M((failwith "exp MOVS case 2", s.operand_sz)))) ]
	   in
	   make_rep s stmts [esi ; edi] i

	(** state generation for CMPS *)
	let cmps s i = 
	  (* TODO factorize with CMP *)
	   let _edi', _esi' =
	     if Register.size edi = i then
	       T edi, T esi
	     else
	       P (edi, 0, i-1), P (esi, 0, i-1)
	   in
	   let r = Register.make ~name:(Register.fresh_name()) ~size:i in
	   let src = M (failwith "exp CMPS case 1", i) in
	   let dst = M (failwith "exp CMPS case 2", i) in
	   let stmts = add_sub_flag_stmts [ Set(V(T r), BinOp(Sub, Lval dst, Lval src)) ] s.operand_sz dst Sub (Lval src) in
	   make_rep s stmts [esi ; edi] i

	(** state generation for LODS *)
	let lods s i = 
	   let _esi', _eax' =
	     if i = Register.size esi then T esi, T eax
	     else P(esi, 0, i-1), P(eax, 0, i-1)
	   in
	   make_rep s [ Set(M (failwith "exp LODS case 1", i), Lval (M(failwith "exp LODS case 2", i))) ] [esi] i

	(** state generation for SCAS *)
	let scas s i =
	   let t = Register.make ~name:(Register.fresh_name()) ~size:i in
	   let _edi', _eax' = 
	     if i = Register.size edi then T edi, T eax
	     else P (edi, 0, i-1), P (eax, 0, i-1)
	   in
	   let e = BinOp(Sub, Lval (M(failwith "exp SCAS case 1", i)), Lval (M(failwith "exp SCAS case 2", i))) in
	   let stmts = add_sub_flag_stmts [Set(V(T t), e) ; Directive (Remove t)] i (V (T t)) Sub e in
	   make_rep s stmts [edi] i

	(** state generation for STOS *)
	let stos s i =
	  let _edi', _eax' = 
	    if i = Register.size edi then T edi, T eax
	    else P (edi, 0, i-1), P (eax, 0, i-1)
	  in
	  make_rep s [ Set (M(failwith "exp STOS case 1", i), Lval (M(failwith "exp STOS case 2", i))) ] [edi] i
		    
	(****************************************************)
	(* State generation for loop, call and jump instructions *)
	(****************************************************)
	(** returns the asm condition of jmp statements from an expression *)
	let exp_of_cond v s =
	  let const c  = const s c in
	  let eq f = Cmp (EQ, Lval (V (T f)), const 1) in
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
	let create_jcc_stmts s e n =
	  let o  = sign_extension_of_byte (int_of_bytes s 1) (n-1) in
	  let a' = Address.add_offset s.a o					            in
	  check_jmp s a';
	  let na = Address.add_offset s.a Z.one					            in
	  check_jmp s na;
	  create s [ If (e, [Jmp (Some (A a'))], [ Jmp (Some (A na)) ] ) ]

	(** jump statements on condition *)
	 let jcc s v n =
	   let e = exp_of_cond v s in
	   create_jcc_stmts s e n

	 (** jump if eCX is zero *)
	 let jecxz s =
	   let ecx' = to_reg ecx s.addr_sz				   in
	   let e    = Cmp (EQ, Lval (V ecx'), Const (Word.zero s.addr_sz)) in
	   create_jcc_stmts s e s.addr_sz

	 (** unconditional jump by adding an offset to the current ip *)
	 let relative_jmp s i =
	   let o  = int_of_bytes s i in
	   let o' =
	     if i = 1 then sign_extension_of_byte o ((s.operand_sz / Config.size_of_byte)-1)
	     else o
	   in
	   let a' = Address.add_offset s.a o' in
	   check_jmp s a';
	   create s [ Jmp (Some (A a')) ]

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
	   create s [ Set (V (T cs), Const (Word.of_int v (Register.size cs))) ; Jmp (Some (A a')) ]
		  
	 let loop s i = 
	  (* TODO: check whether c and zero of length s.addr_sz rather than s.operand_sz *)
	  let ecx' = to_reg ecx s.addr_sz in
	  let c = Const (Word.of_int Z.one s.addr_sz) in
	  let stmts = add_sub_flag_stmts [Set(V ecx', BinOp(Sub, Lval (V ecx'), c))] s.addr_sz (V ecx') Sub c in 
	  let e =
	    let zero = Const (Word.of_int Z.zero s.addr_sz) in
	    let ecx_cond = BUnOp (Not, Cmp (EQ, Lval (V ecx'), zero)) in
	    match i with
	      0 -> (* loopne *) BBinOp (LogAnd, Cmp (EQ, Lval (V (T (fzf))), Const (Word.of_int Z.one (Register.size fzf))), ecx_cond)
	    | 1 -> (* loope *)  BBinOp (LogAnd, Cmp (EQ, Lval (V (T (fzf))), Const (Word.of_int Z.zero (Register.size fzf))), ecx_cond)
	    | _ -> (* loop *)  ecx_cond
	  in
	  let a' = Address.add_offset s.a (int_of_bytes s 1) in
	  Cfa.update_stmts s.b (stmts@[If (e, [Jmp (Some (A a'))], [ ])]) s.operand_sz s.addr_sz;
	  Cfa.add_edge s.g s.b s.b (Some true);
	  [s.b]
	    
	let call (s: state) v far =
	  let v = Cfa.add_state s.g s.a s.b.Cfa.State.v ([Set(V(T esp), BinOp(Sub, Lval (V (T esp)), 
									      Const (Word.of_int (Z.of_int !Config.stack_width) (Register.size esp))))
							 ]@(if far then [Set(V(T esp), BinOp(Sub, Lval (V (T esp)), Const (Word.of_int (Z.of_int !Config.stack_width) (Register.size esp))))] else []) @
							   [Call v]) ({Cfa.State.op_sz = s.operand_sz ; Cfa.State.addr_sz = s.addr_sz}) false
	   in
	   [v]

		  
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

      (** common statement to set (a chunk of) esp *)
      let set_esp op esp' n =
	Set (V esp', BinOp (op, Lval (V esp'), Const (Word.of_int (Z.of_int (n / Config.size_of_byte)) !Config.stack_width)) )

      (** builds a left value from esp that is consistent with the stack width *)
      let esp_lval () = if !Config.stack_width = Register.size esp then T esp else P(esp, 0, !Config.stack_width-1)

      (** common value used for the decoding of push and pop *)
      let size_push_pop v sz = if is_segment v then !Config.stack_width else sz

      (** state generation for pop instructions *)
      let pop s v =
	let esp'  = esp_lval () in
	let stmts = List.fold_left (fun stmts v -> 
			let n = size_push_pop v s.operand_sz in
			[ Set (V v,
			       Lval (M (Lval (V esp'), n))) ; set_esp Add esp' n ] @ stmts
		      ) [] v 
	in
	create s stmts

      (** generation of states for the push instructions *)
      let push s v =
	(* TODO: factorize with POP *)
	let esp' = esp_lval () in
	let t    = Register.make (Register.fresh_name ()) (Register.size esp) in
	(* in case esp is in the list, save its value before the first push (this is this value that has to be pushed for esp) *)
	(* this is the purpose of the pre and post statements *)
	let pre, post =
	  if List.exists (fun v -> match v with T r | P (r, _, _) -> Register.is_sp r) v then
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
	create s (pre @ stmts @ post)

      (** creates the state for the push of an immediate operands. Its size is given by the parameter *)
      let push_immediate s n =
	let c     = Const (Word.of_int (int_of_bytes s n) !Config.stack_width) in
	let esp'  = esp_lval ()						       in
	let stmts = [ Set (M (Lval (V esp'), !Config.stack_width), c) ; set_esp Sub esp' !Config.stack_width ]			 
	in
	create s stmts

      (********)
      (* misc *)
      (*****)
      let xchg s v = 
	let tmp   = Register.make ~name:(Register.fresh_name()) ~size:s.operand_sz in
	let r     = find_reg v s.operand_sz					   in
	let eax   = to_reg eax s.operand_sz					   in 
	let stmts = [ Set(V (T tmp), Lval (V eax)); Set(V eax, Lval (V r)) ; 
		      Set(V r, Lval (V (T tmp)))   ; Directive (Remove tmp)]
	in
	create s stmts
	    
      (** decoding of one instruction *)
      let decode s =
	let to_size s v =
	  if v land 1 = 1 then s.operand_sz
	  else Config.size_of_byte
	in
	let add_sub s op b c =
	  let v        = Char.code c		      in
	  let dst, src = operands_from_mod_reg_rm s v in
	  let sz       = to_size s v		      in
	  add_sub s op b dst src sz
	in
	let or_xor_and s op c =
	  let v        = Char.code c                  in
	  let dst, src = operands_from_mod_reg_rm s v in
	  or_xor_and s op dst src
	in
	let rec decode s =
	  match getchar s with
	  | c when '\x00' <= c && c <= '\x03'  -> add_sub s Sub false c
	  | '\x04' 			       -> add_sub_immediate s Add false eax Config.size_of_byte  
	  | '\x05' 			       -> add_sub_immediate s Add false eax s.operand_sz
	  | '\x06' 			       -> let es' = to_reg es s.operand_sz in push s [es']
	  | '\x07' 			       -> let es' = to_reg es s.operand_sz in pop s [es']
	  | c when '\x08' <= c &&  c <= '\x0D' -> or_xor_and s Or c
	  | '\x0E' 			       -> let cs' = to_reg cs s.operand_sz in push s[cs']
	  | '\x0F' 			       -> decode_snd_opcode s
									       
	  | c when '\x10' <= c && c <= '\x13' -> add_sub s Add true c
	  | '\x14' 			      -> add_sub_immediate s Add true eax Config.size_of_byte
	  | '\x15' 			      -> add_sub_immediate s Add true eax s.operand_sz
	  | '\x16' 			      -> let ss' = to_reg ss s.operand_sz in push s [ss']
	  | '\x17' 			      -> let ss' = to_reg ss s.operand_sz in pop s [ss']
	  | c when '\x18' <= c && c <='\x1B'  -> add_sub s Sub true c
	  | '\x1C' 			      -> add_sub_immediate s Sub true eax Config.size_of_byte
	  | '\x1D' 			      -> add_sub_immediate s Sub true eax s.operand_sz
	  | '\x1E' 			      -> let ds' = to_reg ds s.operand_sz in push s [ds']
	  | '\x1F' 			      -> let ds' = to_reg ds s.operand_sz in pop s [ds']
										       
	  | c when '\x20' <= c && c <= '\x25' -> or_xor_and s And c
	  | '\x26' 			      -> s.segments.data <- es; decode s
	  | c when '\x28' <= c && c <= '\x2B' -> add_sub s Sub false c
	  | '\x2C' 			      -> add_sub_immediate s Sub false eax Config.size_of_byte
	  | '\x2D' 			      -> add_sub_immediate s Sub false eax s.operand_sz
	  | '\x2E' 			      -> s.segments.data <- cs; (* will be set back to default value if the instruction is a jcc *) decode s
								       
	  | c when '\x30' <= c &&  c <= '\x35' -> or_xor_and s Xor c
	  | '\x36' 			       -> s.segments.data <- ss; decode s
	  | c when '\x38' <= c && c <= '\x3B'  -> (* cmp *) add_sub s Sub false c
	  | '\x3C' 			       -> add_sub_immediate s Sub false eax Config.size_of_byte
	  | '\x3D' 			       -> add_sub_immediate s Sub false eax s.operand_sz
	  | '\x3E' 			       -> s.segments.data <- ds (* will be set back to default value if the instruction is a jcc *); decode s
									
	  | c when '\x40' <= c && c <= '\x47' -> let r = find_reg ((Char.code c) - (Char.code '\x40')) s.operand_sz in inc_dec r Add s	
	  | c when '\x48' <= c && c <= '\x4f' -> let r = find_reg ((Char.code c) - (Char.code '\x48')) s.operand_sz in inc_dec r Sub s
															       
	  | c when '\x50' <= c && c <= '\x57' -> let r = find_reg ((Char.code c) - (Char.code '\x50')) s.operand_sz in push s [r]
	  | c when '\x58' <= c && c <= '\x5F' -> let r = find_reg ((Char.code c) - (Char.code '\x58')) s.operand_sz in pop s [r]
															   
	  | '\x60' -> let l = List.map (fun v -> find_reg v s.operand_sz) [0 ; 1 ; 2 ; 3 ; 5 ; 6 ; 7] in push s l
	  | '\x61' -> let l = List.map (fun v -> find_reg v s.operand_sz) [7 ; 6 ; 3 ; 2 ; 1 ; 0] in pop s l
	  | '\x64' -> s.segments.data <- fs; decode s
	  | '\x65' -> s.segments.data <- ss; decode s
	  | '\x66' -> s.operand_sz <- if s.operand_sz = 16 then 32 else 16; decode s
	  | '\x67' -> s.addr_sz <- if s.addr_sz = 16 then 32 else 16; decode s

	  | '\x68' -> push_immediate s 1
	  | '\x6A' -> push_immediate s (s.operand_sz / Config.size_of_byte)
				     
	  | c when '\x70' <= c && c <= '\x7F' -> let v = (Char.code c) - (Char.code '\x70') in jcc s v 1 
												   
	  | '\x80' -> grp1 s Config.size_of_byte Config.size_of_byte
	  | '\x81' -> grp1 s s.operand_sz s.operand_sz
	  | '\x82' -> raise (Exceptions.Error "Undefined opcode 0x82")
	  | '\x83' -> grp1 s s.operand_sz Config.size_of_byte
			   
	  | c when '\x88' <= c && c <= '\x8b' -> let dst, src = operands_from_mod_reg_rm s (Char.code c) in create s [ Set (dst, src) ]
														
	  | '\x90' 			    -> create s [Nop]
						      
	  | c when '\x91' <= c && c <= '\x97' -> xchg s ((Char.code c) - (Char.code '\x90'))
						      
						      
	  | '\xa4' -> movs s Config.size_of_byte
	  | '\xa5' -> movs s s.addr_sz
	  | '\xa6' -> cmps s Config.size_of_byte
	  | '\xa7' -> cmps s s.addr_sz
	  | '\xaa' -> stos s Config.size_of_byte
	  | '\xab' -> stos s s.addr_sz
	  | '\xac' -> lods s Config.size_of_byte
	  | '\xad' -> lods s s.addr_sz
	  | '\xae' -> scas s Config.size_of_byte
	  | '\xaf' -> scas s s.addr_sz
			   
	  | c when '\xe0' <= c && c <= '\xe2' -> loop s ((Char.code c) - (Char.code '\xe0'))
	  | '\xe3' 			    -> jecxz s

	  | '\xe9' -> relative_jmp s (s.operand_sz / Config.size_of_byte)
	  | '\xea' -> direct_jmp s
	  | '\xeb' -> relative_jmp s 1
			  
	  | '\xf0' as c -> Log.from_decoder (Printf.sprintf "Prefix 0x%X ignored \n" (Char.code c)); decode s
	  | '\xf2' as c -> s.rep_prefix <- Some false decode s
	  | '\xf3' as c -> s.rep_prefix <- Some true; decode s
	  | '\xf4' -> raise (Exceptions.Error "Decoder stopped: HLT reached")
			    
	  | c ->  raise (Exceptions.Error (Printf.sprintf "Unknown opcode 0x%x\n" (Char.code c)))

	and decode_snd_opcode s =
	  match getchar s with
	  | c when '\x80' <= c && c <= '\x8f' -> let v = (Char.code c) - (Char.code '\x80') in jcc s v (s.operand_sz / Config.size_of_byte)
	  | c 				      -> raise (Exceptions.Error (Printf.sprintf "unknown second opcode 0x%x\n" (Char.code c)))
	in
	  decode s
					      
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
	    }
	  in
	  try
	    decode s', s'.segments
	  with
	  | Exceptions.Error _ as e -> raise e
	  | _ 			    -> (*end of buffer *) [], is
  end
    (* end Decoder *)

