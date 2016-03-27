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
	  | _ -> Log.error "Invalid decription table selection"
	in
	{ rpl = rpl; ti = ti; index = Word.of_int (Z.shift_right v 3) index_sz }

      (** abstract data type of a segment type *)
      type segment_descriptor_type =
	| Data_r 	    (* 1000 read only *)
	| Data_rw   	    (* 1001 data *)
	| Stack_r 	    (* 1010 read only *)
	| Stack_rw          (* 1011 stack *)
	| Code_x 	    (* 1100 execute only *)
	| Code_rx 	    (* 1101 code execute or read *)
	| ConformingCode_x  (* 1110 conforming code execute-only *)
	| ConformingCode_rx (* 1111 conforming code execute or read *)
	| UndefSegment      (* undefine *)

      (** converts the given integer into a segment type *)
      let segment_descriptor_of_int v =
	match v with
	| 8  -> Data_r
	| 9  -> Data_rw
	| 10 -> Stack_r
	| 11 -> Stack_rw
	| 12 -> Code_x
	| 13 -> Code_rx
	| 14 -> ConformingCode_x
	| 15 -> ConformingCode_rx
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
	for _i = 0 to sz-1 do
	  n := Z.add (int_of_byte s) (Z.shift_left !n 1);
	done;
	!n;;
	
      (***********************************************************************)
      (* Lexing *)
      (***********************************************************************)

      (** tokens produced by the parsing of the opcodes *)
      (** when provided, length of operations are expressed in number of bits *)
      type token =
	| ADC	 of int         (** add with carry ; the argument is the size of the operation *)
	| ADC_i	 of (reg * int) (** add with carry between a register (first argument) and an immedidate data (length is the given by second argument) *)
	| ADD  	 of int         (** add; the argument is the size of the operation *)
	| ADD_i	 of (reg * int) (** add with carry between a register (first argument) and an immedidate data (length is the given by second argument) *)
	| AND  	 of int         (** logical AND; the argument is the size of the operation *)
	| CALL	 of fct * bool  (** function call; the boolean arguments indicates a far call (true) or a near call *)
	| CMP  	 of int         (** CMP i is an unsigned comparison on operands of size i *)
	| CMPS	 of int         (** CMPS i is a signed comparison on operands of size i *)
	| DEC  	 of reg         (** decrementation of the given register *)
	| ESC 		        (** escape to the two-byte opcode map *)
	| HLT                   (** halt *)
	| INC  	 of reg         (** incrementation of the given register *)
	| JECXZ                 (** jump short if ecx is zero *)
	| JCC  	 of int * int   (** JCC (o, n) is a jump such that o is its opcode ;  first is opcode ; second is the number of bytes to read to get the offset of the jump *)
	| JMP  	 of int         (** JMP i add i to the instruction pointer *)
	| LODS	 of int (* size in bits *)
	| LOOP	 of int (* stop condition : 0 (loopne) ; 1 (loope) ; 2 (loop) *)
	| MOVS	 of int (* size in bits *)
	| NOP
	| OR	 of int
	| POP  	 of reg list
	| PREFIX of char 
	| PUSH 	 of reg list
	| PUSH_i of int (* PUSH_i i push an immediate data of size i *)
	| SCAS	 of int (* size in bits *)
	| STOS	 of int (* size in bits *)
	| SBB  	 of int 
	| SBB_i	 of (reg * int) (* var is the destination register ; int is the length of the src immediate data *)
	| SUB  	 of int 
	| SUB_i	 of (reg * int) (* var is the destination register ; int is the length of the src immediate data *)    
	| XCHG 	 of int
	| XOR  	 of int (** XOR i is an exclusive or whose operands have size i *)
      ;;

      (** returns the right Asm.reg value from the given register and context of decoding *)
      let to_reg s r =
	if Register.size r = s.operand_sz then
	  T r
	else
	  P (r, 0, s.operand_sz-1)

      (** returns the right Asm.reg value from the register corresponding to the given numeber and context of decoding *)
      let find_reg s n =
	let r = Hashtbl.find register_tbl n in
	to_reg s r
	       
      let grp5 s v =
	let z7  = Z.of_int 7				               in
	let nnn = Z.to_int (Z.logand (Z.shift_right v 3) z7)	       in
	let r 	= Hashtbl.find register_tbl (Z.to_int (Z.logand v z7)) in
	match nnn with
	| 2 -> CALL (I (to_reg s r), false)
	| _ -> Log.error "Unknown decoding value in grp5"
      (* other cases can not be expressed in asm as it is a far CALL from memory where the selector is picked from [r][0:15] and the offset in [r][16:s.operand_sz-1] *)

     

      (** converts the given character into a token *)
      let parse s c =
	match c with
	| c when '\x00' <= c && c <= '\x03'  -> ADD (Char.code c)	
	| '\x04' 			     -> ADD_i (P(Hashtbl.find register_tbl 0, 0, 7), 1)  
	| '\x05' 			     -> let r = find_reg s 0 in ADD_i (r, s.operand_sz) 
	| '\x06' 			     -> let es' = to_reg s es in PUSH [es']
	| '\x07' 			     -> let es' = to_reg s es in POP [es']
	| c when '\x08' <= c &&  c <= '\x0D' -> OR ((Char.code c) - (Char.code '\x08'))
	| '\x0E' 			     -> let cs' = to_reg s cs in PUSH [cs']
	| '\x0F' 			     -> ESC
		      
	| c when '\x10' <= c && c <= '\x13' -> ADC ((Char.code c) - (Char.code '\x10'))
	| '\x14' 			    -> ADC_i (P(Hashtbl.find register_tbl 0, 0, 7), 1)
	| '\x15' 			    -> let r = find_reg s 0 in ADC_i (r, s.operand_sz)
	| '\x16' 			    -> let ss' = to_reg s ss in PUSH [ss']
	| '\x17' 			    -> let ss' = to_reg s ss in POP [ss']
	| '\x18' | '\x19' | '\x1A' | '\x1B' -> SBB ((Char.code c) - (Char.code '\x18'))
	| '\x1c' 			    -> SBB_i (P(Hashtbl.find register_tbl 0, 0, 7), 1)
	| '\x1d' 			    -> let r = find_reg s 0 in SBB_i (r, s.operand_sz)
	| '\x1E' 			    -> let ds' = to_reg s ds in PUSH [ds']
	| '\x1F' 			    -> let ds' = to_reg s ds in POP [ds']
															       
	| c when '\x20' <= c && c <= '\x25' -> AND ((Char.code c) - (Char.code '\x20'))
	| '\x26' 			    -> PREFIX c
	| c when '\x28' <= c && c <= '\x2B' -> SUB ((Char.code c) - (Char.code '\x28'))
	| '\x2C' 			    -> SUB_i (P(Hashtbl.find register_tbl 0, 0, 7), 1)
	| '\x2D' 			    -> let r = find_reg s 0 in SUB_i (r, s.operand_sz)	
	| '\x2E' 			    -> PREFIX c
			   
	| c when '\x30' <= c &&  c <= '\x35' -> XOR ((Char.code c) - (Char.code '\x30'))	
	| '\x36' 			     -> PREFIX c
	| c when '\x38' <= c && c <= '\x3D'  -> CMP ((Char.code c) - (Char.code '\x38')) 	
	| '\x3E' 			     -> PREFIX c
			   
	| c when '\x40' <= c && c <= '\x47' -> let r = find_reg s ((Char.code c) - (Char.code '\x40')) in INC r	
	| c when '\x48' <= c && c <= '\x4f' -> let r = find_reg s ((Char.code c) - (Char.code '\x48')) in DEC r
																						   
	| c when '\x50' <= c &&  c <= '\x57' -> let r = find_reg s ((Char.code c) - (Char.code '\x50')) in PUSH [r]
	| c when '\x58' <= c && c <= '\x5F'  -> let r = find_reg s ((Char.code c) - (Char.code '\x58')) in POP [r]

	| '\x60' -> let l = List.map (fun v -> find_reg s v) [0 ; 1 ; 2 ; 3 ; 5 ; 6 ; 7] in PUSH l
	| '\x61' -> let l = List.map (fun v -> find_reg s v) [7 ; 6 ; 3 ; 2 ; 1 ; 0] in POP l
	| '\x64' -> PREFIX c
	| '\x65' -> PREFIX c
	| '\x68' -> PUSH_i 1
	| '\x6A' -> PUSH_i (s.operand_sz / 8)

	| c when '\x70' <= c && c <= '\x7F' -> let v = (Char.code c) - (Char.code '\x70') in JCC (v, 1) 

	| '\x90' 			    -> NOP 
	| c when '\x91' <= c && c <= '\x97' -> XCHG ((Char.code c) - (Char.code '\x90'))

	| '\xa4' -> MOVS 8
	| '\xa5' -> MOVS s.addr_sz
	| '\xa6' -> CMPS 8
	| '\xa7' -> CMPS s.addr_sz
	| '\xaa' -> STOS 8
	| '\xab' -> STOS s.addr_sz
	| '\xac' -> LODS 8
	| '\xad' -> LODS s.addr_sz
	| '\xae' -> SCAS 8
	| '\xaf' -> SCAS s.addr_sz

	| c when '\xe0' <= c && c <= '\xe2' -> LOOP ((Char.code c) - (Char.code '\xe0'))
	| '\xe3' 			    -> JECXZ

	| '\xe9' -> JMP (s.operand_sz / Config.size_of_byte)
	| '\xeb' -> JMP 1

	| '\xf0' -> PREFIX c
	| '\xf2' -> PREFIX c
	| '\xf3' -> PREFIX c
	| '\xf4' -> HLT
	| '\xff' -> grp5 s (int_of_bytes s 1)

	| _  ->  Log.error (Printf.sprintf "Unknown opcode 0x%x \n" (Char.code c))

      (** parsing of the second opcode map *)
      let second_token s = 
	let c = getchar s in
	match c with
	| c when '\x80' <= c && c <= '\x8F' -> let v = (Char.code c) - (Char.code '\x80') in JCC (v, 1)
	| _ 				    -> Log.error (Printf.sprintf "Unknown second opcode 0x%x \n" (Char.code c))

(********************************************************************************************)
(* mod/rm byte decoding *)
(********************************************************************************************)


      let mod_rm_16 mod_field rm_field s =
	(*let word_of_byte s i =
	  let w = Word.of_int (int_of_bytes s i) (i*8) in 
	  if i = 1 then Word.sign_extend w 16 else w
	in
	 *)
	let n = s.operand_sz - 1 in
	match mod_field, rm_field with
	  0, 0 		       -> M(failwith "Decoder.mod_rm_16 (case 1)", s.operand_sz), 0
	| 0, 1 		       -> M(failwith "Decoder.mod_rm_16 (case 2)", s.operand_sz), 0
	| 0, 2 		       -> M(failwith "Decoder.mod_rm_16 (case 3)", s.operand_sz), 0
	| 0, 3 		       -> M(failwith "Decoder.mod_rm_16 (case 4)", s.operand_sz), 0
	| 0, 4 		       -> M(failwith "Decoder.mod_rm_16 (case 5)", s.operand_sz), 0
	| 0, 5 		       -> M(failwith "Decoder.mod_rm_16 (case 6)", s.operand_sz), 0
	| 0, 6 		       -> M(failwith "Decoder.mod_rm_16 (case 7)", s.operand_sz), 2
	| 0, 7 		       -> M(failwith "Decoder.mod_rm_16 (case 8)", s.operand_sz), 0
	| i, 0 when i = 1 || i = 2 -> M(failwith "Decoder.mod_rm_16 (case 9)", s.operand_sz), i
	| i, 1 when i = 1 || i = 2 -> M(failwith "Decoder.mod_rm_16 (case 10)", s.operand_sz), i
	| i, 2 when i = 1 || i = 2 -> M(failwith "Decoder.mod_rm_16 (case 11)", s.operand_sz), i
	| i, 3 when i = 1 || i = 2 -> M(failwith "Decoder.mod_rm_16 (case 12)", s.operand_sz), i
	| i, 4 when i = 1 || i = 2 -> M(failwith "Decoder.mod_rm_16 (case 13)", s.operand_sz), i
	| i, 5 when i = 1 || i = 2 -> M(failwith "Decoder.mod_rm_16 (case 14)", s.operand_sz), i
	| i, 6 when i = 1 || i = 2 -> M(failwith "Decoder.mod_rm_16 (case 15)", s.operand_sz), i
	| i, 7 when i = 1 || i = 2 -> M(failwith "Decoder.mod_rm_16 (case 16)", s.operand_sz), i
	| _, 5 		       -> V( P(ebp, 0, n)), 0
	| _, i 		       -> V( P(Hashtbl.find register_tbl i, 0, n)), 0
									     
      exception Illegal
		  
      let sib s mod_field =
	let b     = Z.to_int (int_of_bytes s 1) in
	let scale = b lsr 5         	        in
	let index = (b lsr 2) land 5            in
	let base  = b land 5        	        in
	match scale, index, base with
	  _, 4, _  -> Log.error "Illegal sib configuration"
	| n, i, 5  -> 
	   begin
	     let _r = T (Hashtbl.find register_tbl i) in
	     match n, mod_field with
	       0, 0 -> M(failwith "Decoder.sib (case 1)", s.operand_sz), 4
	     | _n, 0 -> M(failwith "Decoder.sib (case 2)", s.operand_sz), 4
	     | 0, 1 -> M(failwith "Decoder.sib (case 3)", s.operand_sz), 1
	     | _, _ -> M(failwith "Decoder.sib (case 4)", s.operand_sz), 4
	   end
	| 0, i, j  -> 
	   begin 
	     let _r  = T (Hashtbl.find register_tbl i) in
	     let _r2 = T (Hashtbl.find register_tbl j) in
	     match mod_field with
	       0    -> M(failwith "Decoder.mod_sib (case 5)", s.operand_sz), 0
	     | 1    -> M(failwith "Decoder.mod_sib (case 6)", s.operand_sz), 1
	     | _    -> M(failwith "Decoder.mod_sib (case 7)", s.operand_sz), 4
	   end
	| _n, i, j  ->
	   let _r  = T (Hashtbl.find register_tbl i) in
	   let _r2 = T (Hashtbl.find register_tbl j) in
	   match mod_field with
	     0      -> M(failwith "Decoder.mod_sib (case 8)", s.operand_sz), 0
	   | 1      -> M(failwith "Decoder.mod_sib (case 9)", s.operand_sz), 1
	   | _      -> M(failwith "Decoder.mod_sib (case 10)", s.operand_sz), 4
															      
															      
      let mod_rm_32 _mod_field _rm_field _s = Log.error "mod_rm_32"
	(*
	match mod_field, rm_field with
	  3, i -> V (T (Hashtbl.find register_tbl i)), 0
	| i, 4 -> sib s (i*8)
	| 0, 5 -> M (failwith "Decoder.mod_rm_32 (case 1)", s.operand_sz), 4
	| 0, _i -> M (failwith "Decoder.mod_rm_32 (case 2)", s.operand_sz), 0
	| i, _j -> 
	   let n, _w = 
	     if i = 1 then 1, Word.sign_extend (Word.of_int (int_of_bytes s 1) Config.size_of_byte) 32
	     else 4, Word.of_int (int_of_bytes s 4) 32 
	   in
	   M(failwith "Decoder.mod_rm_32 (case 3)", s.operand_sz), n *)
										     
      let mod_rm mod_field rm_field reg_field direction s =
	let r             = Hashtbl.find register_tbl reg_field in
	let op1, op2, off =
	  if s.operand_sz = 16 then
	    let op, off = mod_rm_16 mod_field rm_field s in 
	    op, P(r, 0, s.operand_sz-1), off
	  else 
	    let op, off = mod_rm_32 mod_field rm_field s in
	    op, T r, off
	in
	if direction = 0 then
	  op1, V op2, off
	else
	  V op2, op1, off
			

			
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
      let carry_flag_stmts _sz _res _op1 _op _op2 = Log.error "Decoder.carry_flag_stmts"
	(* fcf is set if the sz+1 bit of the result is 1 *)

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
      (* Decoding binary operations *)
      (**************************************************************************************)

      (** produces the list of statements for the flag settings involved in the ADD, ADC, SUB, SBB, ADD_i, SUB_i instructions *)
      let add_sub_flag_stmts istmts sz carry_or_borrow dst op op2 =
	let name 	= Register.fresh_name ()	    in
	let v  	 	= Register.make ~name:name ~size:sz in
	let tmp  	= V (T v)		  	    in
	let op1  	= Lval tmp		  	    in
	let res  	= Lval dst		  	    in
	let flags_stmts =
	  [
	    carry_flag_stmts sz res op1 op op2; overflow_flag_stmts res op1 op2; zero_flag_stmts sz res;
	    sign_flag_stmts res            ; parity_flag_stmts sz res       ; adjust_flag_stmts res op1 op2
	  ]
	in
	let stmts =
	  if carry_or_borrow then
	    [Set(dst, BinOp(Add, Lval dst, Lval (V (T fcf)))) ] @ istmts
	  else
	    istmts
	in
	(Set (tmp, Lval dst)):: stmts @ flags_stmts @ [ Directive (Remove v) ]

      (** produces the list of statements for the flag settings involved in the OR, XOR, AND instructions *)
      (** together with the right statements for flag settings *)
      let or_xor_and_flag_stmts sz stmt dst =
	let res 	= Lval dst in
	let flags_stmts =
	  [
	    clear_carry_flag_stmts (); clear_overflow_flag_stmts (); zero_flag_stmts sz res;
	    sign_flag_stmts res   ; parity_flag_stmts sz res    ; undefine_adjust_flag_stmts ()
	  ]
	in
	stmt::flags_stmts
		
      (** add a new state with the given statements *)
      (** an edge between the current state and this new state is added *)
      let create s stmts =
	let ctx = { Cfa.State.addr_sz = s.addr_sz ; Cfa.State.op_sz = s.operand_sz } in
	let v   = Cfa.add_state s.g (Address.add_offset s.a (Z.of_int s.o)) s.b.Cfa.State.v stmts ctx false in
	Cfa.add_edge s.g s.b v None;
	[v]

      (** produces the list of statement corresponding to the token ADD_i (add with immediate operand) and SUB_i (sub with immediate operand) *)
      (** together with the right statements for flag settings *)
      let add_sub_immediate op carry_or_borrow s r sz =
	let sz'   = sz / Config.size_of_byte                                                      in
	let w     = Word.of_int (int_of_bytes s sz') s.operand_sz			          in
	let o     = UnOp (SignExt s.operand_sz, Const w)				          in 
	let stmts = add_sub_flag_stmts [Set (r, BinOp (op, Lval r, o))] sz carry_or_borrow r op o in  
	create s stmts

	       
      let operands_from_mod_reg_rm v s =
	let d 	= (v lsr 1) land 1         in
	let n 	= Z.to_int (int_of_byte s) in
	let reg_field = (n lsr 3) land 7   in
	let mod_field = n lsr 6	           in
	let rm_field  = n land 7 	   in
	mod_rm mod_field rm_field reg_field d s
	 
      let binop_with_eax v s =
	match Char.chr v with
	  (* TODO: to be more readable, v should be a char not an int *)
	| '\x04' | '\x0c' | '\x14' | '\x1c'
	| '\x24' | '\x2c' | '\x34' | '\x3c' -> P(eax, 0, 7), Word.of_int (int_of_byte s) Config.size_of_byte, 1

	| '\x05' | '\x0d' | '\x15' | '\x1d'
	| '\x25' | '\x2d' | '\x35' | '\x3d' ->
				      let n = s.operand_sz / 8                            in
				      let w = Word.of_int (int_of_bytes s n) s.operand_sz in 
				      let r = to_reg s eax                                in
				      r, w, n
	| _ -> raise Exit
		       
      let add_sub op carry_or_borrow v s =
	try
	  let stmts =
	    try 
	      let r, w, off = binop_with_eax v s			 in
	      let stmt      = Set(V r, BinOp(op, Lval (V r), Const w)) in
	      add_sub_flag_stmts [stmt] (off*8) carry_or_borrow (V r) op (Const w)
	    with Exit -> 
	      begin
		let dst, src, _off = operands_from_mod_reg_rm v s	     in
		let stmt 	  = Set (dst, BinOp(op, Lval dst, Lval src)) in
		add_sub_flag_stmts [stmt] s.operand_sz carry_or_borrow dst op (Lval src)
	      end
	  in
	  create s stmts
	with Illegal -> create s [Undef]
			       
      let or_xor_and op v s =
	(* Factorize with add_and_sub *)
	try
	  let stmts =
	    try 
	      let r, w, off = binop_with_eax v s in
	      let stmt = Set(V r, BinOp(op, Lval (V r), Const w)) in
	      or_xor_and_flag_stmts (off*8) stmt (V r)
	    with Exit -> 
	      begin
		let dst, src, _off = operands_from_mod_reg_rm v s 
		in
		let stmt = Set (dst, BinOp(op, Lval dst, Lval src)) in
		or_xor_and_flag_stmts s.operand_sz stmt dst
	      end
	  in
	  create s stmts
	with Illegal -> create s [Undef]
			       
      let cmp v s =
	(* Factorize with add_and_sub *)
	try
	  let dst, src = 
	    try  let r, w, _o = binop_with_eax v s in V r, Const w
	    with Exit -> let d, s, _o = operands_from_mod_reg_rm v s in d, Lval s
	  in
	  let stmts =
	    let name  = Register.fresh_name ()						   in
	    let tmp   = Register.make ~name:name ~size:s.operand_sz			   in (* TODO: this size or (byte if binop_with_eax) or off ? *)
	    let stmt  = Set (V (T tmp), BinOp(Sub, Lval dst, src))			   in
	    let stmts = add_sub_flag_stmts [stmt] s.operand_sz false (V (T tmp)) Sub src in
	    stmts@[Directive (Remove tmp)]
	  in
	  create s stmts
	with Illegal -> create s [Undef]
			       
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
	    flags_stmts @ [Directive (Remove v)]              in
	create s stmts

    
      (** returns the asm condition of jmp statements from an expression *)
      let exp_of_cond v s n =
	let const c = const s c	in
	let e =
	  match v with
	  | 0 | 1   -> Cmp (EQ, Lval (V (T fof)), const (1-v))
	  | 2 | 3   -> Cmp (EQ, Lval (V (T fcf)), const (1-(v-2)))
	  | 4 | 5   -> Cmp (EQ, Lval (V (T fzf)), const (1-(v-4)))
	  | 6       -> let c1 = const 1 in BBinOp (LogOr, Cmp (EQ, Lval (V (T fcf)), c1), Cmp (EQ, Lval (V (T fzf)), c1))											   
	  | 7       -> let c0 = const 0 in BBinOp (LogAnd, Cmp (EQ, Lval (V (T fcf)), c0), Cmp (EQ, Lval (V (T fzf)), c0))
	  | 8 | 9   -> Cmp (EQ, Lval (V (T fsf)), const (1-(v-8)))
	  | 10 | 11 -> Cmp (EQ, Lval (V (T fpf)), const (1-(v-10)))
	  | 12      -> BUnOp (Not, Cmp (EQ, Lval (V (T fsf)), Lval (V (T fof))))
	  | 13      -> Cmp (EQ, Lval (V (T fsf)), Lval (V (T fof)))
	  | 14      -> BBinOp (LogOr, Cmp (EQ, Lval (V (T fzf)), const 1), BUnOp(Not, Cmp (EQ, Lval (V (T fsf)), Lval (V (T fof)))))
	  | 15      -> BBinOp (LogAnd, Cmp (EQ, Lval (V (T fzf)), const 0), Cmp (EQ, Lval (V (T fsf)), Lval (V (T fof))))
	  | _       -> Log.error "Opcode.exp_of_cond: illegal value"
	in
	e, int_of_bytes s n
				   
				   				   
      let parse_two_bytes s =
	match second_token s with
	  JCC (v, n) ->
	  let e, o = exp_of_cond v s n        in
	  let a'   = Address.add_offset s.a o in
	  create s [Jcc (e, Some (A a'))]
		 
	| _ -> Log.error "Opcode.parse_two_bytes: opcode"
			   
			   
			   
			   
      (*********************************************************************************************)
      (* Prefix management *)
      (*********************************************************************************************)
      type prefix_opt =
	Jcc_i
	| Esc
	| Str
	    
	    
      let update_prefix s c =
	begin
	  match s.rep_prefix with
	    Some _ when c = Str -> ()
	  | Some _ when c = Esc -> Log.error "prefix with escape opcode not implemented"
	  | _ -> s.rep_prefix <- None
	end;
	begin
	  match c with
	    Jcc_i -> s.segments.data <- ds
	  | _ -> ()
	end;
	if c = Esc then s.addr_sz <- !Config.address_sz
							       
      (** updates the decoder state with respect to the decoded prefix *)
      let push_prefix s c =
	match c with
	| '\xf0' -> Log.from_decoder (Printf.sprintf "Prefix 0x%X ignored \n" (Char.code c))
	| '\xf2' -> s.rep_prefix <- Some false
	| '\xf3' -> s.rep_prefix <- Some true
	| '\x26' -> s.segments.data <- es
	| '\x2e' -> s.segments.data <- cs (* will be set back to default value if the instruction is a jcc *)
	| '\x36' -> s.segments.data <- ss
	| '\x3e' -> s.segments.data <- ds (* will be set back to default value if the instruction is a jcc *)
	| '\x64' -> s.segments.data <- fs
	| '\x65' -> s.segments.data <- ss
	| '\x66' -> s.operand_sz <- if s.operand_sz = 16 then 32 else 16
	| '\x67' -> s.addr_sz <- if s.addr_sz = 16 then 32 else 16
	| _      -> Log.error "not a prefix"
		     
		     
      let is_register_set stmts r =
	let is_set stmt =
	  match stmt with
	  | Set (V (T r'), _) when Register.compare r r' = 0 	    -> true
	  | Set (V (P(r', _, _)), _) when Register.compare r r' = 0 -> true
	  | _ 						            -> false
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
	Cfa.update_stmts s.b [Jcc (test', Some (A s.a))] s.operand_sz s.addr_sz;
	Cfa.add_edge s.g s.b rep_blk None;
	let ctx = { Cfa.State.op_sz = s.operand_sz ; Cfa.State.addr_sz = s.addr_sz } in	
	let instr_blk = Cfa.add_state s.g s.a rep_blk.Cfa.State.v (str_stmt @ [ecx_decr] @ esi_stmt @ edi_stmt @ [Jcc( Cmp (EQ, Lval (V(T fdf)), Const (Word.of_int Z.one 1)), None)]) ctx true in 
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
	
      (****************************************************************************************)
      (* Parsing *)
      (****************************************************************************************)
      let is_segment r = 
	match r with
	  T r | P(r, _, _) -> Register.compare r cs = 0 || Register.compare r ds = 0 || Register.compare r ss = 0 || Register.compare r es = 0 || Register.compare r fs = 0 || Register.compare r gs = 0
      ;;
	
      let is_esp r = 
	match r with 
	  T r | P(r, _, _) -> Register.compare r esp = 0

      (** common statement to set (a chunk of) esp *)
      let set_esp esp' n =
	Set (V esp', BinOp (Sub, Lval (V esp'), Const (Word.of_int (Z.of_int (n / Config.size_of_byte)) !Config.stack_width)) )

      (** builds a left value from esp that is consistent with the stack width *)
      let esp_lval () = if !Config.stack_width = Register.size esp then T esp else P(esp, 0, !Config.stack_width-1)

      (** common value used for the decoding of push and pop *)
      let size_push_pop v sz = if is_segment v then !Config.stack_width else sz
									    
      let rec decode s =
	let c = getchar s in
	match parse s c with
	| ADC v	     -> add_sub Add true v s
				    
	| ADC_i (reg, n) -> add_sub_immediate Add true s (V reg) n
						  
	| ADD v	     -> add_sub Add false v s
				    
	| ADD_i (reg, n) -> add_sub_immediate Add false s (V reg) n
						  
   	| AND v -> or_xor_and And v s
				  
	| CALL (v, far) -> 
	   let v = Cfa.add_state s.g s.a s.b.Cfa.State.v ([Set(V(T esp), BinOp(Sub, Lval (V (T esp)), 
																      Const (Word.of_int (Z.of_int !Config.stack_width) (Register.size esp))))
								   ]@(if far then [Set(V(T esp), BinOp(Sub, Lval (V (T esp)), Const (Word.of_int (Z.of_int !Config.stack_width) (Register.size esp))))] else []) @
								     [Call v]) ({Cfa.State.op_sz = s.operand_sz ; Cfa.State.addr_sz = s.addr_sz}) false
	   in
	   [v]
	     
	     
	| CMP v -> cmp v s
		       
	| CMPS i -> 
	   update_prefix s Str; 
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
	   let stmts = add_sub_flag_stmts [ Set(V(T r), BinOp(Sub, Lval dst, Lval src)) ] s.operand_sz false dst Sub (Lval src) in
	   make_rep s stmts [esi ; edi] i
		    
	| DEC reg 	     -> inc_dec reg Sub s
					    
	| ESC ->
	   (* TODO: factorize with JCC *) update_prefix s Esc; parse_two_bytes s
									       
	| HLT -> create s []
			
	| INC reg 	     -> inc_dec reg Add s
					    
	| JCC (v, n)           -> 
	   (* TODO: factorize with JMP *)
	   update_prefix s Jcc_i;
	   let e, o = exp_of_cond v s n in
	   let a' = Address.add_offset s.a o in
	   create s [ Jcc (e, Some (A a')) ]
		  
	| JECXZ ->
	   (* TODO: factorize with JMP *)
	   update_prefix s Jcc_i;
	   let o    = int_of_bytes s (s.operand_sz/ Config.size_of_byte) in
	   let a'   = Address.add_offset s.a o in
	   let ecx' = if Register.size ecx = s.addr_sz then T ecx else P(ecx, 0, s.addr_sz-1) in
	   let e    = Cmp (EQ, Lval (V ecx'), Const (Word.zero (Register.size ecx))) in
	   create s [Jcc (e, Some (A a'))]
		  
	| JMP i 	     ->
	   let o  = int_of_bytes s i         in
	   let a' = Address.add_offset s.a o in
	   create s [ Jcc (BConst true, Some (A a')) ]
		  
	| LODS i -> 
	   let _esi', _eax' =
	     if i = Register.size esi then T esi, T eax
	     else P(esi, 0, i-1), P(eax, 0, i-1)
	   in
	   update_prefix s Str; 
	   make_rep s [ Set(M (failwith "exp LODS case 1", i), Lval (M(failwith "exp LODS case 2", i))) ] [esi] i
      
	| LOOP i ->
	   (* TODO: check whether c and zero of length s.addr_sz rather than s.operand_sz *)
	   let ecx' = if Register.size ecx = s.addr_sz then T ecx else P (ecx, 0, s.addr_sz -1) in  
	   let c = Const (Word.of_int Z.one s.addr_sz) in
	   let stmts = add_sub_flag_stmts [Set(V ecx', BinOp(Sub, Lval (V ecx'), c))] s.addr_sz false (V ecx') Sub c in 
	   let e =
	     let zero = Const (Word.of_int Z.zero s.addr_sz) in
	     let ecx_cond = BUnOp (Not, Cmp (EQ, Lval (V ecx'), zero)) in
	     match i with
	       0 -> (* loopne *) BBinOp (LogAnd, Cmp (EQ, Lval (V (T (fzf))), Const (Word.of_int Z.one (Register.size fzf))), ecx_cond)
	     | 1 -> (* loope *)  BBinOp (LogAnd, Cmp (EQ, Lval (V (T (fzf))), Const (Word.of_int Z.zero (Register.size fzf))), ecx_cond)
	     | _ -> (* loop *)  ecx_cond
	   in
	   let a' = Address.add_offset s.a (int_of_bytes s 1) in
	   Cfa.update_stmts s.b (stmts@[Jcc(e, Some (A a'))]) s.operand_sz s.addr_sz;
	   Cfa.add_edge s.g s.b s.b (Some true);
	   [s.b]
	     
	| MOVS i ->
	   let _edi', _esi' =
	     if Register.size edi = i then
	       T edi, T esi
	     else
	       P (edi, 0, i-1), P (esi, 0, i-1)
	   in
	   let stmts = [ Set(M(failwith "exp MOVS case 1", s.operand_sz), Lval (M((failwith "exp MOVS case 2", s.operand_sz)))) ]
	   in
	   update_prefix s Str; 
	   make_rep s stmts [esi ; edi] i
		    
	| NOP 	     ->  create s [Nop]
				
	| OR v -> or_xor_and Or v s
				 
	| POP v   	     ->
	   let esp'  = esp_lval () in
	   let stmts = List.fold_left (fun stmts v -> 
				       let n = size_push_pop v s.operand_sz in
				       [ Set (V v,
						Lval (M (Lval (V esp'), n))) ; set_esp esp' n ] @ stmts
			 ) [] v 
	   in
	   create s stmts
		  
	| PREFIX c -> push_prefix s c; decode s
					      
	| PUSH v  	     ->
	   (* TODO: factorize with POP *)
	   let esp' = esp_lval () in
	   let t    = Register.make (Register.fresh_name ()) (Register.size esp)                                  in
	   (* in case esp is in the list, save its value before the first push (this is this value that has to be pushed for esp) *)
	   (* this is the purpose of the pre and post statements *)
	   let pre, post =
	     if List.exists (fun v -> match v with T r | P (r, _, _) -> Register.is_sp r) v then
	       [ Set (V (T t), Lval (V esp')) ], [ Directive (Remove t) ]
	     else
	       [], []
	   in
	   let stmts = List.fold_left (
			   fun stmts v ->
			   let n = size_push_pop v s.operand_sz in 
			   let s =
			     if is_esp v then
			       (* save the esp value to its value before the first push (see PUSHA specifications) *)
			       Set (M (Lval (V esp'), n), Lval (V (T t)))
			     else
			       Set (M (Lval (V esp'), n), Lval (V v));
			   in
			   [ s ; set_esp esp' n ] @ stmts
			 ) [] v
	   in
	   create s (pre @ stmts @ post)
		  
	| PUSH_i n -> 
	   let c     = Const (Word.of_int (int_of_bytes s n) !Config.stack_width)  in
	   let esp'  = esp_lval ()							      in
	   let stmts = [ Set (M (Lval (V esp'), !Config.stack_width), c) ; set_esp esp' !Config.stack_width ]			 
	   in
	   create s stmts
		  
	| SBB v	     -> add_sub Sub true v s
				    
	| SBB_i (reg, n) -> add_sub_immediate Sub true s (V reg) n
						  
	| SUB v 	     -> add_sub Sub false v s
					    
					    
	| SUB_i (reg, n) -> add_sub_immediate Sub false s (V reg) n
						  
	| SCAS i ->
	   update_prefix s Str ;
	   let t = Register.make ~name:(Register.fresh_name()) ~size:i in
	   let _edi', _eax' = 
	     if i = Register.size edi then T edi, T eax
	     else P (edi, 0, i-1), P (eax, 0, i-1)
	   in
	   let e = BinOp(Sub, Lval (M(failwith "exp SCAS case 1", i)), Lval (M(failwith "exp SCAS case 2", i))) in
	   let stmts = add_sub_flag_stmts [Set(V(T t), e) ; Directive (Remove t)] i false (V (T t)) Sub e in
	   make_rep s stmts [edi] i
		    
		    
	| STOS i ->
	   update_prefix s Str ; 
	   let _edi', _eax' = 
	     if i = Register.size edi then T edi, T eax
	     else P (edi, 0, i-1), P (eax, 0, i-1)
	   in
	   make_rep s [ Set (M(failwith "exp STOS case 1", i), Lval (M(failwith "exp STOS case 2", i))) ] [edi] i
		    
				       
	| XCHG v          -> 
	   let tmp = Register.make ~name:(Register.fresh_name()) ~size:s.operand_sz in
	   let r = Hashtbl.find register_tbl v in
	   let eax, r = if Register.size eax = s.operand_sz then T eax, T r else P(eax, 0, s.operand_sz-1), P(r, 0, s.operand_sz-1) in 
	   let stmts = [ Set(V (T tmp), Lval (V eax)) ; 
			Set(V eax, Lval (V r)) ; 
			Set(V r, Lval (V (T tmp))) ; Directive (Remove tmp)] in
	   create s stmts
		  
		  
	| XOR v -> or_xor_and Xor v s

			      
      (** builds information from a value as supposed to contained in a segment register *)
      let mask_of_segment_register_content v =
	let lvl   = v land 3         in
	let ti    = (v lsr 2) land 1 in
	let index = (v lsr 3)        in
	{ rpl = privilege_level_of_int lvl; ti = if ti = 0 then GDT else LDT; index = Word.of_int (Z.of_int index) 13 }

      (** returns the base address corresponding to the given value (whose format is supposed to be compatible with the content of segment registers *)
      let get_base_address s v =
	if !Config.mode = Config.Protected then
	  let c = mask_of_segment_register_content v in
	  let dt = if c.ti = GDT then s.segments.gdt else s.segments.ldt in 
	  try
	      let e = Hashtbl.find dt c.index in
	      if c.rpl <= e.dpl then
		e.base
	      else
		Log.error "illegal requested privileged level"
	    with Not_found -> Log.error (Printf.sprintf "illegal requested index in %s Description Table" (if c.ti = GDT then "Global" else "Local"))
	else
	  Log.error "only protected mode supported"
				
      (** initialization of the segmentation *)
      let init () =
	let ldt = Hashtbl.create 5  in
	let gdt = Hashtbl.create 19 in
	let idt = Hashtbl.create 15 in
	(* builds the gdt *)
	Hashtbl.iter (fun o v -> Hashtbl.replace gdt (Word.of_int (Z.mul o (Z.of_int 64)) 64) (tbl_entry_of_int v)) Config.gdt;
	let reg = Hashtbl.create 6 in
	List.iter (fun (r, v) -> Hashtbl.add reg r (get_segment_register_mask v)) [cs, !Config.cs; ds, !Config.ds; ss, !Config.ss; es, !Config.es; fs, !Config.fs; gs, !Config.gs];
	{ gdt = gdt; ldt = ldt; idt = idt; data = ds; reg = reg; }

      let get_segments ctx =
	let registers = Hashtbl.create 6 in
	try
	  List.iter (fun r -> Hashtbl.add registers r (get_segment_register_mask (ctx#value_of_register r))) [ cs; ds; ss; es; fs; gs ];
	  registers
	with _ -> Log.error "Decoder: overflow in a segment register" 
	  
      let copy_segments s ctx = { gdt = Hashtbl.copy s.gdt; ldt = Hashtbl.copy s.ldt; idt = Hashtbl.copy s.idt; data = ds; reg = get_segments ctx  }
	
	  
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
	  with _ -> (*end of buffer *) [], is
  end
    (* end Decoder *)

