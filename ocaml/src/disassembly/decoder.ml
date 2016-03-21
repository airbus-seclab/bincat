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

      let index_sz = 64
		       
      type segment_register_mask = { rpl: privilege_level; ti: table_indicator; index: Word.t }
				     
      let get_segment_register_mask v =
	let rpl = privilege_level_of_int (v land 3) in
	let ti =
	  match (v lsr 2) land 1 with
	  | 0 -> GDT
	  | 1 -> LDT
	  | _ -> failwith "Only for exhaustive pattern matching"
	in
	{ rpl = rpl; ti = ti; index = Word.of_int (Z.of_int (v lsr 3)) index_sz }
	  
      type segment_descriptor_type =
	| Data_r 	    (* 1000 read only *)
	| Data_rw   	    (* 1001 data *)
	| Stack_r 	    (* 1010 read only *)
	| Code_x 	    (* 1100 execute only *)
	| Code_rx 	    (* 1101 code execute or read *)
	| ConformingCode_x  (* 1110 conforming code execute-only *)
	| ConformingCode_rx (* 1111 conforming code execute or read *)

      let segment_descriptor_of_int v =
	match v with
	| 8  -> Data_r
	| 9  -> Data_rw
	| 10 -> Stack_r
	| 11 -> Code_x
	| 12 -> Code_rx
	| 13 -> ConformingCode_x
	| 14 -> ConformingCode_rx
	| _  -> Log.error (Printf.sprintf "Illegal segment descriptor type %d\n" v)

      type tbl_entry = { base: int; limit: int; a: int; typ: segment_descriptor_type; dpl: privilege_level; p: int; u: int; x: int; d: int; g: int;}
				  
      let tbl_entry_of_int v =
	let limit = v land 0xffff			     in
	let v' 	  = v lsr 16				     in
	let base  = v land 0xffff			     in
	let v' 	  = v' lsr 16				     in
	let base  = base + (v' land 0xff) lsl 16	     in
	let v' 	  = v' lsr 8				     in
	let a 	  = v' land 1				     in
	let v' 	  = v' lsr 1				     in
	let typ   = segment_descriptor_of_int (v' land 0x0f) in
	let v' 	  = v' lsr 4				     in	
	let dpl   = v' land 3				     in
	let v' 	  = v' lsr 2				     in
	let p 	  = v' land 1				     in
	let v' 	  = v' lsr 1				     in 
	let limit = limit + (v' land 0x0f) lsl 16	     in	
	let v' 	  = v' lsr 4				     in
	let u 	  = v' land 1				     in
	let v' 	  = v' lsr 1				     in
	let x 	  = v' land 1				     in
	let v' 	  = v' lsr 1				     in
	let d 	  = v' land 1				     in
	let v' 	  = v' lsr 1				     in
	let g 	  = v' land 1				     in
	let base  = base + (v' lsr 1) lsl 24		     in
	{ limit = limit; base = base; a = a; typ = typ; dpl = privilege_level_of_int dpl; p = p; u = u; x = x; d = d; g = g; }
			 
      type desc_tbl = (Word.t, tbl_entry) Hashtbl.t (* the key is an offset in the table *)

      type segment_t = { mutable data: Register.t; gdt: desc_tbl; ldt: desc_tbl; idt: desc_tbl; reg: (Register.t, segment_register_mask) Hashtbl.t } (* data field contains the current segment register for data *)

      (** complete internal state of the decoder *)
      (** only the segment field is exported out of the functor (see parse signature) for further reloading *)
      type state = {
	  mutable g 	    : Cfa.t; 	   (* current cfa *)
	  mutable b 	    : Cfa.State.t; (* state predecessor *)
	  a 	     	    : Address.t;   (* current address to decode *)
	  mutable addr_sz   : int;   	   (* current address size in bits *)
	  mutable operand_sz: int;  	   (* current operand size in bits *)
	  buf 	     	    : string;      (* buffer to decode *)
	  mutable o 	    : int; 	   (* offset into the buffer *)
	  mutable rep_prefix: bool option; (* None = no rep prefix ; Some true = rep prefix ; Some false = repne/repnz prefix *)
	  mutable segments  : segment_t;   (* all about segmentation *)								       
	}

      

      (***********************************************************************)
      (* Char transformations *)
      (***********************************************************************)
      let getchar s = 
	let c = String.get s.buf s.o in
	s.o <- s.o + 1;
	c
 
      let int_of_byte s = Char.code (getchar s)
				    
				    
      let int_of_bytes s sz =
	let n = ref 0 in
	for _i = 0 to sz-1 do
	  n := (int_of_byte s) +  2 * !n;
	  s.o <- s.o + 1
	done;
	!n;;
	
      (***********************************************************************)
      (* Lexing *)
      (***********************************************************************)
	
      let error_msg c =
	Printf.printf "Unknown opcode 0x%x \n" (Char.code c) ; 
	flush stdout 
      ;; 
	
      type token =
	| ADC of int
	| ADC_i of (reg * int) (* var is the destination register ; int is the length of the src immediate data *) 
	| ADD   of int
	| ADD_i of (reg * int) (* var is the destination register ; int is the length of the src immediate data *) 
	| AND   of int
	| CALL of fct * bool (* true if far call *)
	| CMP   of int
	| CMPS of int (* size in bits ! *)
	| DEC   of reg
	| ESC (* 0x0F *)
	| HLT
	| INC   of reg
	| JECX
	| JCC   of int * int (* first is opcode ; second is the number of bytes to read to get the offset of the jump *)
	| JMP   of int (* offset to add to the instruction pointer *)
	| LODS of int (* size in bits *)
	| LOOP of int (* stop condition : 0 (loopne) ; 1 (loope) ; 2 (loop) *)
	| MOVS of int (* size in bits *)
	| NOP
	| OR of int
	| POP   of reg list
	| PREFIX of char 
	| PUSH  of reg list
	| PUSH_i of int (* number of bytes to push *)
	| SCAS of int (* size in bits *)
	| STOS of int (* size in bits *)
	| SBB   of int 
	| SBB_i of (reg * int) (* var is the destination register ; int is the length of the src immediate data *)
	| SUB   of int 
	| SUB_i of (reg * int) (* var is the destination register ; int is the length of the src immediate data *)    
	| UNKNOWN
	| XCHG  of int
	| XOR   of int
      ;;
	
	
      let grp5 s v =
	let nnn = (v lsr 3) land 7 in
	let r = Hashtbl.find register_tbl (v land 7) in
	match nnn with
	  2 -> CALL (I (if Register.size r = s.operand_sz then T r else P(r, 0, s.operand_sz-1)), false)
	| 3 -> UNKNOWN (* can not be expressed in asm as it is a far CALL from memory where the selector is picked from [r][0:15] and the offset in [r][16:s.operand_sz-1] *)
	| _ -> UNKNOWN
		 
		 
      let parse s c =
	match c with
	| c when '\x00' <= c && c <= '\x03' -> ADD (Char.code c)	
	| '\x04' -> ADD_i (P(Hashtbl.find register_tbl 0, 0, 7), 1)  
	| '\x05' -> let r = Hashtbl.find register_tbl 0 in let r' = if Register.size r = s.operand_sz then T r else P(r, 0, s.operand_sz-1) in ADD_i (r', s.operand_sz / 8) 
	| '\x06' -> let es' = if Register.size es = s.operand_sz then T es else P(es, 0, s.operand_sz-1) in PUSH [es']
	| '\x07' -> let es' = if Register.size es = s.operand_sz then T es else P(es, 0, s.operand_sz-1) in POP [es']
	| c when '\x08' <= c &&  c <= '\x0D' -> OR ((Char.code c) - (Char.code '\x08'))
	| '\x0E' -> let cs' = if Register.size cs = s.operand_sz then T cs else P(cs, 0, s.operand_sz-1) in PUSH [cs']
	| '\x0F' -> ESC
		      
	| c when '\x10' <= c && c <= '\x13' -> ADC ((Char.code c) - (Char.code '\x10'))
	| '\x14' -> ADC_i (P(Hashtbl.find register_tbl 0, 0, 7), 1)
	| '\x15' -> let r = Hashtbl.find register_tbl 0 in let r' = if Register.size r = s.operand_sz then T r else P(r, 0, s.operand_sz-1) in ADC_i (r', s.operand_sz / 8)
	| '\x16' -> let ss' = if Register.size ss = s.operand_sz then T ss else P(ss, 0, s.operand_sz-1) in PUSH [ss']
	| '\x17' -> let ss' = if Register.size ss = s.operand_sz then T ss else P(ss, 0, s.operand_sz-1) in POP [ss']
	| '\x18' | '\x19' | '\x1A' | '\x1B' -> SBB ((Char.code c) - (Char.code '\x18'))
	| '\x1c' -> SBB_i (P(Hashtbl.find register_tbl 0, 0, 7), 1)
	| '\x1d' -> let r = Hashtbl.find register_tbl 0 in let r' = if Register.size r = s.operand_sz then T r else P(r, 0, s.operand_sz-1) in SBB_i (r', s.operand_sz / 8)
	| '\x1E' -> let ds' = if Register.size ds = s.operand_sz then T ds else P(ds, 0, s.operand_sz-1) in PUSH [ds']
	| '\x1F' -> let ds' = if Register.size ds = s.operand_sz then T ds else P(ds, 0, s.operand_sz-1) in POP [ds']
															       
	| c when '\x20' <= c && c <= '\x25' -> AND ((Char.code c) - (Char.code '\x20'))
	| '\x26' -> PREFIX c
	| c when '\x28' <= c && c <= '\x2B' -> SUB ((Char.code c) - (Char.code '\x28'))
	| '\x2C' -> SUB_i (P(Hashtbl.find register_tbl 0, 0, 7), 1)
	| '\x2D' -> let r = Hashtbl.find register_tbl 0 in let r' = if Register.size r = s.operand_sz then T r else P(r, 0, s.operand_sz-1) in SUB_i (r', s.operand_sz / 8)	
	| '\x2E' -> PREFIX c
			   
	| c when '\x30' <= c &&  c <= '\x35' -> XOR ((Char.code c) - (Char.code '\x30'))	
	| '\x36' -> PREFIX c
	| c when '\x38' <= c && c <= '\x3D' -> CMP ((Char.code c) - (Char.code '\x38')) 	
	| '\x3E' -> PREFIX c
			   
	| c when '\x40' <= c && c <= '\x47' -> let r = Hashtbl.find register_tbl ((Char.code c) - (Char.code '\x47')) in if Register.size r = s.operand_sz then INC (T r) else INC (P(r, 0, s.operand_sz-1))
	| c when '\x48' <= c && c <= '\x4f' -> let r = Hashtbl.find register_tbl ((Char.code c) - (Char.code '\x48')) in if Register.size r = s.operand_sz then DEC (T r) else DEC (P(r, 0, s.operand_sz-1))
																						   
	| c when '\x50' <= c &&  c <= '\x57' -> let v = (Char.code c) - (Char.code '\x50') in let r = Hashtbl.find register_tbl v in let r'= if Register.size r = s.operand_sz then T r else P (r, 0, s.operand_sz-1) in PUSH [r']
	| c when '\x58' <= c && c <= '\x5F' -> let v = (Char.code c) - (Char.code '\x50') in 
					       let r = Hashtbl.find register_tbl v in let r'= if Register.size r = s.operand_sz then T r else P (r, 0, s.operand_sz-1) in 
										      POP [r']

	| '\x60' -> let l = List.map (fun v -> let r = Hashtbl.find register_tbl v in if Register.size r = s.operand_sz then T r else P(r, 0, s.operand_sz-1)) [0 ; 1 ; 2 ; 3 ; 5 ; 6 ; 7] in PUSH l
	| '\x61' -> let l = List.map (fun v -> let r = Hashtbl.find register_tbl v in if Register.size r = s.operand_sz then T r else P(r, 0, s.operand_sz-1)) [7 ; 6 ; 3 ; 2 ; 1 ; 0] in POP l
	| '\x64' -> PREFIX c
	| '\x65' -> PREFIX c
	| '\x68' -> PUSH_i 1
	| '\x6A' -> PUSH_i (s.operand_sz / 8)

	| c when '\x70' <= c && c <= '\x7F' -> let v = (Char.code c) - (Char.code '\x70') in JCC (v, 1) 

	| '\x90' -> NOP 
	| c when '\x91' <= c && c <= '\x97' -> XCHG ((Char.code c) - (Char.code '\x90'))
	| '\x9a' -> failwith "Decoder: 0x9a"   

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
	| '\xe3' -> JECX
	| '\xe8' -> failwith "Decoder: 0xe8"
	| '\xe9' -> JMP (s.operand_sz / 8)
	| '\xeb' -> JMP 1

	| '\xf0' -> PREFIX c
	| '\xf2' -> PREFIX c
	| '\xf3' -> PREFIX c
	| '\xf4' -> HLT
	| '\xff' -> grp5 s (int_of_bytes s 1)

	| _  -> UNKNOWN

      let second_token s (*TODO: factorize with token, \x70-\x7F*) = 
	let c = getchar s in
	match c with
	| c when '\x80' <= c && c <= '\x8F' -> let v = (Char.code c) - (Char.code '\x80') in JCC (v, 1)
	| _ -> error_msg c ; UNKNOWN

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
	let b     = int_of_bytes s 1 in
	let scale = b lsr 5          in
	let index = (b lsr 2) land 5 in
	let base  = b land 5         in
	match scale, index, base with
	  _, 4, _  -> raise Illegal
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
															      
															      
      let mod_rm_32 mod_field rm_field s =
	match mod_field, rm_field with
	  3, i -> V(T (Hashtbl.find register_tbl i)), 0
	| i, 4 -> sib s (i*8)
	| 0, 5 -> M(failwith "Decoder.mod_rm_32 (case 1)", s.operand_sz), 4
	| 0, _i -> M(failwith "Decoder.mod_rm_32 (case 2)", s.operand_sz), 0
	| i, _j -> 
	   let n, _w = 
	     if i = 1 then 1, Word.sign_extend (Word.of_int (Z.of_int (int_of_bytes s 1)) 8) 32
	     else 4, Word.of_int (Z.of_int (int_of_bytes s 4)) 32
	   in
	   M(failwith "Decoder.mod_rm_32 (case 3)", s.operand_sz), n
										     
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
      let fof_sz = Register.size fof
      let fcf_sz = Register.size fcf
      let fsf_sz = Register.size fsf								       
      let faf_sz = Register.size faf
      let fzf_sz = Register.size fzf
				 
      (** produce common statements to set the overflow flag and the adjust flag *) 
      let overflow flag n nth sz res op1 op2 =
	(* flag is set if both op1 and op2 have the same nth bit whereas different from the hightest bit of res *)
	let nth'      = Const (Word.of_int (Z.of_int nth) sz)	       	 in
	let sign_res  = BinOp (Shrs, res, nth')	 	    	       	 in
	let sign_op1  = BinOp (Shrs, op1, nth')	 	    	       	 in
	let sign_op2  = BinOp (Shrs, op2, nth')	 	    	       	 in
	let c1 	      = Cmp (Eq, sign_op1, sign_op2)   	       		 in
	let c2 	      = BUnOp (Not, Cmp (Eq, sign_res, sign_op1))  	 in
	let one_stmt  = Set (V (T flag), Const (Word.one n))		 in
	let zero_stmt = Set (V (T flag), Const (Word.zero n))		 in
	If (c1, [ If (c2, [ one_stmt ], [ zero_stmt ]) ], [ zero_stmt ]) 

      (** produce the statement to set the overflow flag according to the current operation whose operands are op1 and op2 and result is res *)
      let overflow_flag_stmts sz res op1 op2 = overflow fof fof_sz (!Config.operand_sz -1) sz res op1 op2

      (** produce the statement to clear the overflow flag *)
      let clear_overflow_flag_stmts () = Set (V (T fof), Const (Word.zero fof_sz)) 

      (** produce the statement to set the carry flag according to the current operation whose operands are op1 and op2 and result is res *)
      let carry_flag_stmts sz res op1 op op2 =
	(* fcf is set if res is different from the result of SignExt (op1) op SignExtend (op2)  *)
	let res' = BinOp (op, UnOp(SignExt (sz+1), op1), UnOp(SignExt (sz+1), op2)) in
        let e    = BUnOp(Not, Cmp (Eq, res, res'))		                                      in
	If (e, [ Set (V (T fcf), Const (Word.one fcf_sz)) ], [ Set (V (T fcf), Const (Word.zero fcf_sz)) ])

      (** produce the statement to unset the carry flag *)
      let clear_carry_flag_stmts () = Set (V (T fcf), Const (Word.zero fcf_sz))

      (** produce the statement to undefine the adjust flag *)
      let undefine_adjust_flag_stmts () = Directive (Forget faf)

      (** produce the statement to set the sign flag *)					    
      let sign_flag_stmts sz res =
	let c = Cmp (Eq, Const (Word.one fsf_sz), BinOp(Shrs, res, Const (Word.of_int (Z.of_int 31) sz))) in
	If (c, [ Set (V (T fsf), Const (Word.one fsf_sz)) ], [ Set (V (T fsf), Const (Word.zero fsf_sz))] ) 
	     
      (** produce the statement to set the zero flag *)	
      let zero_flag_stmts sz res =
	let c = Cmp (Eq, res, Const (Word.zero sz)) in
	If (c, [ Set (V (T fzf), Const (Word.one fzf_sz))], [Set (V (T fzf), Const (Word.zero fzf_sz))])

      (** produce the statement to set the adjust flag *)
      (** faf is set if there is an overflow on the bit 3 *)
      let adjust_flag_stmts sz res op1 op2 = overflow faf faf_sz 3 sz res op1 op2
					      
      (** produce the statement to set the parity flag *)					      
      let parity_flag_stmts sz res =
	(* fpf is set if res contains an even number of 1 in the least significant byte *)
	(* we sum every bits and check whether this sum is even or odd *)
	(* using the modulo of the divison by 2 *)
	let nth i =
	  let one = Const (Word.one (sz-i)) in
	  BinOp (And, BinOp(Shrs, res, Const (Word.of_int (Z.of_int i) sz)), one)
	in
	let e = ref (nth 0) in
	for i = 1 to 7 do
	  e := BinOp(Add, !e, nth i)
	done;
	let if_stmt   = Set (V (T fzf), Const (Word.one fzf_sz))			                    in
	let else_stmt = Set (V (T fzf), Const (Word.zero fzf_sz))			                    in
	let c 	      = Cmp (Eq, BinOp(Mod, !e, Const (Word.of_int (Z.of_int 2) sz)), Const (Word.zero sz)) in
	If(c, [ if_stmt ], [ else_stmt ]) 
	  
	  
      (**************************************************************************************)
      (* Decoding binary operations *)
      (**************************************************************************************)
      let add_sub_flag_stmts istmts sz carry_or_borrow dst op op2 =
	(* TODO : simplify and factorize with inc_and_dec *)
	let name 	= Register.fresh_name ()	    in
	let v  	 	= Register.make ~name:name ~size:sz in
	let tmp  	= V (T v)		  	    in
	let op1  	= Lval tmp		  	    in
	let res  	= Lval dst		  	    in
	let flags_stmts =
	  [
	    carry_flag_stmts sz res op1 op op2; overflow_flag_stmts sz res op1 op2; zero_flag_stmts sz res;
	    sign_flag_stmts sz res            ; parity_flag_stmts sz res          ; adjust_flag_stmts sz res op1 op2
	  ]
	in
	let stmts =
	  if carry_or_borrow then
	    [Set(dst, BinOp(Add, Lval dst, Lval (V (T fcf)))) ] @ istmts
	  else
	    istmts
	in
	(Set (tmp, Lval dst)):: stmts @ flags_stmts @ [Directive (Remove v)]
							
      let or_xor_and_flag_stmts sz stmt dst =
	let res 	= Lval dst in
	let flags_stmts =
	  [
	    clear_carry_flag_stmts (); clear_overflow_flag_stmts (); zero_flag_stmts sz res;
	    sign_flag_stmts sz res   ; parity_flag_stmts sz res    ; undefine_adjust_flag_stmts ()
	  ]
	in
	stmt::flags_stmts
		
      (* add a new state with the given statements *)
      (* an edge between the current state and this new state is added *)
      (* the offset o' is used to set the ip field of the new state to the current ip plus this offset *)
      let create s stmts o' =
	s.o <- o';
	let ctx = { Cfa.State.addr_sz = s.addr_sz ; Cfa.State.op_sz = s.operand_sz } in
	let v   = Cfa.add_state s.g (Address.add_offset s.a (Z.of_int o')) s.b.Cfa.State.v stmts ctx false in
	Cfa.add_edge s.g s.b v None;
	[v]

	  
      let add_sub_immediate op carry_or_borrow s r sz = 
	let w     = Word.of_int (Z.of_int (int_of_bytes s sz)) s.operand_sz			     in
	let o     = UnOp (SignExt s.operand_sz, Const w)				             in 
	let stmts = add_sub_flag_stmts [Set (r, BinOp (op, Lval r, o))] sz carry_or_borrow r op o in  
	create s stmts (sz+1)
	       
      let operands_from_mod_reg_rm v s =
	let d 	= (v lsr 1) land 1       in
	let n 	= int_of_byte s          in
	let reg_field = (n lsr 3) land 7 in
	let mod_field = n lsr 6	         in
	let rm_field  = n land 7 	 in
	mod_rm mod_field rm_field reg_field d s
	 
      let binop_with_eax v s =
	match Char.chr v with
	  (* TODO: to be more readable, v should be a char not an int *)
	  '\x04' | '\x0c' | '\x14' | '\x1c' | '\x24' | '\x2c' | '\x34' | '\x3c' -> P(eax, 0, 7), Word.of_int (Z.of_int (int_of_byte s)) 8, 1
	  | '\x05' | '\x0d' | '\x15' | '\x1d' | '\x25' | '\x2d' | '\x35' | '\x3d' -> 
									    let n = s.operand_sz / 8                              in
									    let w = Word.of_int (Z.of_int (int_of_bytes s n)) s.operand_sz in 
									    let r = 
									      if s.operand_sz = Register.size eax then T eax
									      else P(eax, 0, s.operand_sz-1)    in
									    r, w, n
	  | _ -> raise Exit
		       
      let add_sub op carry_or_borrow v s =
	try
	  let stmts, off =
	    try 
	      let r, w, off = binop_with_eax v s			 in
	      let stmt      = Set(V r, BinOp(op, Lval (V r), Const w)) in
	      add_sub_flag_stmts [stmt] (off*8) carry_or_borrow (V r) op (Const w), off
	    with Exit -> 
	      begin
		let dst, src, off = operands_from_mod_reg_rm v s	     in
		let stmt 	  = Set (dst, BinOp(op, Lval dst, Lval src)) in
		add_sub_flag_stmts [stmt] s.operand_sz carry_or_borrow dst op (Lval src), off
	      end
	  in
	  create s stmts (off+2)
	with Illegal -> create s [Undef] 2
			       
      let or_xor_and op v s =
	(* Factorize with add_and_sub *)
	try
	  let stmts, off =
	    try 
	      let r, w, off = binop_with_eax v s in
	      let stmt = Set(V r, BinOp(op, Lval (V r), Const w)) in
	      or_xor_and_flag_stmts (off*8) stmt (V r), off
	    with Exit -> 
	      begin
		let dst, src, off = operands_from_mod_reg_rm v s 
		in
		let stmt = Set (dst, BinOp(op, Lval dst, Lval src)) in
		or_xor_and_flag_stmts s.operand_sz stmt dst, off
	      end
	  in
	  create s stmts (off+2)
	with Illegal -> create s [Undef] 2
			       
      let cmp v s =
	(* Factorize with add_and_sub *)
	try
	  let dst, src, off = 
	    try  let r, w, o = binop_with_eax v s in V r, Const w, o
	    with Exit -> let d, s, o = operands_from_mod_reg_rm v s in d, Lval s, o
	  in
	  let stmts =
	    let name  = Register.fresh_name ()						   in
	    let tmp   = Register.make ~name:name ~size:s.operand_sz			   in (* TODO: this size or (byte if binop_with_eax) or off ? *)
	    let stmt  = Set (V (T tmp), BinOp(Sub, Lval dst, src))			   in
	    let stmts = add_sub_flag_stmts [stmt] s.operand_sz false (V (T tmp)) Sub src in
	    stmts@[Directive (Remove tmp)]
	  in
	  create s stmts (off+2)
	with Illegal -> create s [Undef] 2
			       
			       
      let inc_dec reg op s =
	let dst 	= V reg                                       in
	let name        = Register.fresh_name ()                      in
	let v           = Register.make ~name:name ~size:s.operand_sz in
	let tmp         = V (T v)				      in
	let op1         = Lval tmp			              in
	let op2         = Const (Word.one s.operand_sz)               in
	let res         = Lval dst			              in
	let flags_stmts =
	  [
	    overflow_flag_stmts s.operand_sz res op1 op2; zero_flag_stmts s.operand_sz res;
	    parity_flag_stmts s.operand_sz res          ; adjust_flag_stmts s.operand_sz res op1 op2
	  ]
	in
	let stmts = 
	  [ Set(tmp, Lval dst); Set (dst, BinOp (op, Lval dst, op2)) ] @ 
	    flags_stmts @ [Directive (Remove v)]              in
	create s stmts 1
	       
      let exp_of_cond v s n =
	match v with
	| 0 | 1   -> Cmp (Eq, Lval (V (T fof)), Const (Word.of_int (Z.of_int (1-v)) s.operand_sz)), int_of_bytes s n
	| 2 | 3   -> Cmp (Eq, Lval (V (T fcf)), Const (Word.of_int (Z.of_int (1-(v-2))) s.operand_sz)), int_of_bytes s n
	| 4 | 5   -> Cmp (Eq, Lval (V (T fzf)), Const (Word.of_int (Z.of_int (1-(v-4))) s.operand_sz)), int_of_bytes s n
	| 6       -> BBinOp (LogOr, Cmp (Eq, Lval (V (T fcf)), Const (Word.one s.operand_sz)), Cmp (Eq, Lval (V (T fzf)), Const (Word.one s.operand_sz))), int_of_bytes s n
	| 7       -> BBinOp (LogAnd, Cmp (Eq, Lval (V (T fcf)), Const (Word.zero s.operand_sz)), Cmp (Eq, Lval (V (T fzf)), Const (Word.zero s.operand_sz))), int_of_bytes s n
	| 8 | 9   -> Cmp (Eq, Lval (V (T fsf)), Const (Word.of_int (Z.of_int (1-(v-8))) s.operand_sz)), int_of_bytes s n
	| 10 | 11 -> Cmp (Eq, Lval (V (T fpf)), Const (Word.of_int (Z.of_int (1-(v-10))) s.operand_sz)), int_of_bytes s n
	| 12      -> BUnOp (Not, Cmp (Eq, Lval (V (T fsf)), Lval (V (T fof)))), int_of_bytes s n
	| 13      -> Cmp (Eq, Lval (V (T fsf)), Lval (V (T fof))), int_of_bytes s n
	| 14      -> BBinOp (LogOr, Cmp (Eq, Lval (V (T fzf)), Const (Word.one s.operand_sz)), BUnOp(Not, Cmp (Eq, Lval (V (T fsf)), Lval (V (T fof))))), int_of_bytes s n
	| 15      -> BBinOp (LogAnd, Cmp (Eq, Lval (V (T fzf)), Const (Word.zero s.operand_sz)), Cmp (Eq, Lval (V (T fsf)), Lval (V (T fof)))), int_of_bytes s n
	| _       -> Log.error "Opcode.exp_of_cond: illegal value"
				 
				   
				   
				   
      let parse_two_bytes s =
	match second_token s with
	  JCC (v, n) ->
	  (* TODO: factorize with JMP *)
	  let e, o = exp_of_cond v s n in
	  let a'   = Address.add_offset s.a (Z.of_int o) in
	  create s [Jcc (e, Some (A a'))] o
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
	| _ -> Log.error "not a prefix"
		     
		     


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
	let test     = BUnOp (Not, Cmp (Eq, Lval lv, Const (Word.zero len)))         in (* lv <> 0 *)
	let test'    = 
	  if is_register_set str_stmt fzf then
	    let c = if s.rep_prefix = Some true then Const (Word.zero len) else Const (Word.one len)
	    in
	    BBinOp (LogOr, test, Cmp (Eq, Lval (V (T fzf)), c)) 
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
	let instr_blk = Cfa.add_state s.g s.a rep_blk.Cfa.State.v (str_stmt @ [ecx_decr] @ esi_stmt @ edi_stmt @ [Jcc( Cmp (Eq, Lval (V(T fdf)), Const (Word.of_int Z.one 1)), None)]) ctx true in 
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
									       
	| HLT -> create s [] 1
			
	| INC reg 	     -> inc_dec reg Add s
					    
	| JCC (v, n)           -> 
	   (* TODO: factorize with JMP *)
	   update_prefix s Jcc_i;
	   let e, o = exp_of_cond v s n in
	   let a' = Address.add_offset s.a (Z.of_int o) in
	   create s [ Jcc (e, Some (A a')) ] o
		  
	| JECX ->
	   (* TODO: factorize with JMP *)
	   update_prefix s Jcc_i;
	   let o    = int_of_bytes s (s.operand_sz/ Config.size_of_byte) in
	   let a'   = Address.add_offset s.a (Z.of_int o) in
	   let ecx' = if Register.size ecx = s.addr_sz then T ecx else P(ecx, 0, s.addr_sz-1) in
	   let e    = Cmp (Eq, Lval (V ecx'), Const (Word.zero (Register.size ecx))) in
	   create s [Jcc (e, Some (A a'))] o
		  
	| JMP i 	     ->
	   let o  = int_of_bytes s i                    in
	   let a' = Address.add_offset s.a (Z.of_int o) in
	   create s [ Jcc (BConst true, Some (A a')) ] o
		  
	| LODS i -> 
	   let _esi', _eax' =
	     if i = Register.size esi then T esi, T eax
	     else P(esi, 0, i-1), P(eax, 0, i-1)
	   in
	   update_prefix s Str; 
	   make_rep s [ Set(M (failwith "exp LODS case 1", i), Lval (M(failwith "exp LODS case 2", i))) ] [esi] i
      
	| LOOP i ->
	   let ecx' = if Register.size ecx = s.addr_sz then T ecx else P (ecx, 0, s.addr_sz -1) in  
	   let c = Const (Word.of_int Z.one s.addr_sz) in
	   let stmts = add_sub_flag_stmts [Set(V ecx', BinOp(Sub, Lval (V ecx'), c))] s.addr_sz false (V ecx') Sub c in 
	   let e =
	     let zero = Const (Word.of_int Z.zero s.addr_sz) in
	     let ecx_cond = BUnOp (Not, Cmp (Eq, Lval (V ecx'), zero)) in
	     match i with
	       0 -> (* loopne *) BBinOp (LogAnd, Cmp (Eq, Lval (V (T (fzf))), Const (Word.of_int Z.one (Register.size fzf))), ecx_cond)
	     | 1 -> (* loope *)  BBinOp (LogAnd, Cmp (Eq, Lval (V (T (fzf))), Const (Word.of_int Z.zero (Register.size fzf))), ecx_cond)
	     | _ -> (* loop *)  ecx_cond
	   in
	   let a' = Address.add_offset s.a (Z.of_int (int_of_bytes s 1)) in
	   Cfa.update_stmts s.b (stmts@[Jcc(e, Some (A a'))]) s.operand_sz s.addr_sz;
	   s.o <- s.o + 1;
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
		    
	| NOP 	     ->  create s [Nop] 1
				
	| OR v -> or_xor_and Or v s
				 
	| POP v   	     -> 
	   let esp'  = if !Config.stack_width = Register.size esp then T esp else P(esp, 0, !Config.stack_width-1) in
	   let stmts = List.fold_left (fun stmts v -> 
				       let n = if is_segment v then !Config.stack_width else s.operand_sz in
				       [ Set (V v,
						Lval (M (Lval (V esp'), n))) ;
						Set(V esp', BinOp(Add, Lval (V esp'), Const (Word.of_int (Z.of_int (n / Config.size_of_byte)) !Config.stack_width)))
				       ]@stmts
			 ) [] v 
	   in
	   create s stmts 1
		  
	| PREFIX c -> push_prefix s c; decode s
					      
	| PUSH v  	     ->
	   (* TODO: factorize with POP *)
	   let esp' = if !Config.stack_width = Register.size esp then T esp else P(esp, 0, !Config.stack_width-1) in
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
			   let n = if is_segment v then !Config.stack_width else s.operand_sz in
			   let s =
			     if is_esp v then
			       (* save the esp value to its value before the first push (see PUSHA specifications) *)
			       Set (M (Lval (V esp'), n), Lval (V (T t)))
			     else
			       Set (M (Lval (V esp'), n), Lval (V v));
			   in
			   [ s ; Set (V esp', BinOp (Sub, Lval (V esp'), Const (Word.of_int (Z.of_int (n / Config.size_of_byte)) !Config.stack_width)) )(*update the stack pointer *)
			   ] @ stmts
			 ) [] v
	   in
	   create s (pre @ stmts @ post) 1
		  
	| PUSH_i n -> 
	   let c     = Const (Word.of_int (Z.of_int (int_of_bytes s n)) !Config.stack_width)                       in
	   let esp'  = if !Config.stack_width = Register.size esp then T esp else P(esp, 0, !Config.stack_width-1) in
	   let stmts = [
	       Set (M (Lval (V esp'), !Config.stack_width), c) ;
	       Set (V esp', BinOp(Sub, Lval (V esp'), Const (Word.of_int (Z.of_int (!Config.stack_width / Config.size_of_byte)) !Config.stack_width))) ]			 
	   in
	   create s stmts 1
		  
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
		    
	| UNKNOWN 	     -> create s [Unknown] 1
				       
	| XCHG v          -> 
	   let tmp = Register.make ~name:(Register.fresh_name()) ~size:s.operand_sz in
	   let r = Hashtbl.find register_tbl v in
	   let eax, r = if Register.size eax = s.operand_sz then T eax, T r else P(eax, 0, s.operand_sz-1), P(r, 0, s.operand_sz-1) in 
	   let stmts = [ Set(V (T tmp), Lval (V eax)) ; 
			Set(V eax, Lval (V r)) ; 
			Set(V r, Lval (V (T tmp))) ; Directive (Remove tmp)] in
	   create s stmts 1
		  
		  
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
	Hashtbl.iter (fun o v -> Hashtbl.replace gdt (Word.of_int (Z.mul o (Z.of_int 64)) 64) (tbl_entry_of_int (Z.to_int v))) Config.gdt;
	let reg = Hashtbl.create 6 in
	Hashtbl.add reg cs (get_segment_register_mask (Z.to_int !Config.cs));
	Hashtbl.add reg ds (get_segment_register_mask (Z.to_int !Config.ds));
	Hashtbl.add reg ss (get_segment_register_mask (Z.to_int !Config.ss));
	Hashtbl.add reg es (get_segment_register_mask (Z.to_int !Config.es));
	Hashtbl.add reg fs (get_segment_register_mask (Z.to_int !Config.fs));
	Hashtbl.add reg gs (get_segment_register_mask (Z.to_int !Config.gs));
	{ gdt = gdt; ldt = ldt; idt = idt; data = ds; reg = reg; }

      let get_segments ctx =
	let registers = Hashtbl.create 6 in
	try
	  Hashtbl.add registers cs (get_segment_register_mask (Z.to_int (ctx#value_of_register cs)));
	  Hashtbl.add registers ds (get_segment_register_mask (Z.to_int (ctx#value_of_register ds)));
	  Hashtbl.add registers ss (get_segment_register_mask (Z.to_int (ctx#value_of_register ss)));
	  Hashtbl.add registers es (get_segment_register_mask (Z.to_int (ctx#value_of_register es)));
	  Hashtbl.add registers fs (get_segment_register_mask (Z.to_int (ctx#value_of_register fs)));
	  Hashtbl.add registers gs (get_segment_register_mask (Z.to_int (ctx#value_of_register gs)));
	  registers
	with _ -> Log.error "Overflow in a segment register" 
	  
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

