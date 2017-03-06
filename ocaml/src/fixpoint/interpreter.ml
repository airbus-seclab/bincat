(** Fixpoint iterator *)

(** external signature of the module *)
module type T =
  sig
    type domain
    module Cfa:
    sig
      type t
      module State:
      sig
	(** data type for the decoding context *)
	  type ctx_t = {
	      addr_sz: int; (** size in bits of the addresses *)
	      op_sz  : int; (** size in bits of operands *)
	    }

	  (** abstract data type of a state *)
	  type t = {
	      id: int; 	     		    (** unique identificator of the state *)
	      mutable ip: Data.Address.t;   (** instruction pointer *)
	      mutable v: domain; 	    (** abstract value *)
	      mutable ctx: ctx_t ; 	    (** context of decoding *)
	      mutable stmts: Asm.stmt list; (** list of statements of the successor state *)
	      mutable final: bool;          (** true whenever a widening operator has been applied to the v field *)
	      mutable back_loop: bool; (** true whenever the state belongs to a loop that is backward analysed *)
	      mutable forward_loop: bool; (** true whenever the state belongs to a loop that is forward analysed in CFA mode *)
	      mutable branch: bool option; (** None is for unconditional predecessor. Some true if the predecessor is a If-statement for which the true branch has been taken. Some false if the false branch has been taken *)
	      mutable bytes: char list;      (** corresponding list of bytes *)
	    mutable is_tainted: bool; (** true whenever a source left value is the stmt list (field stmts) may be tainted *)
	    }
      end
      val init: Data.Address.t -> State.t
      val create: unit -> t
      val add_vertex: t -> State.t -> unit
      val print: string -> string -> t -> unit
      val unmarshal: string -> t
      val marshal: string -> t -> unit
      val init_abstract_value: unit -> domain
      val last_addr: t -> Data.Address.t -> State.t
    end
    val forward_bin: Code.t -> Cfa.t -> Cfa.State.t -> (Cfa.t -> unit) -> Cfa.t
    val forward_cfa: Cfa.t -> Cfa.State.t -> (Cfa.t -> unit) -> Cfa.t 
    val backward: Cfa.t -> Cfa.State.t -> (Cfa.t -> unit) -> Cfa.t
    val interleave_from_cfa: Cfa.t -> (Cfa.t -> unit) -> Cfa.t
  end
    
module Make(D: Domain.T): (T with type domain = D.t) =
  struct

    type domain = D.t

    (** Decoder *)
    module Decoder = Decoder.Make(D)
				 
    (** Control Flow Automaton *)
    module Cfa = Decoder.Cfa 

    (** stubs *)
    module Stubs =
    struct
      let strlen (d: D.t) (args: Asm.exp list): D.t * bool =
	Log.from_analysis "strlen stub";
	match args with
	| [Asm.Lval ret ; buf] ->
	   let zero = Asm.Const (Data.Word.zero !Config.operand_sz) in
	   let len = D.get_offset_from buf Asm.EQ zero !Config.operand_sz 10000 d in
	   if len > !Config.unroll then
	     begin
	       Log.from_analysis (Printf.sprintf "updates automatic loop unrolling with the computed string length = %d" len);
	       Config.unroll := len
	     end;
	   D.set ret (Asm.Const (Data.Word.of_int (Z.of_int len) !Config.operand_sz)) d
	| _ -> Log.error "invalid call to strlen stub"

      let memcpy (d: D.t) (args: Asm.exp list): D.t * bool =
	Log.from_analysis "memcpy stub";
	match args with
	| [Asm.Lval ret ; dst ; src ; sz] ->
	   begin
	     try
	       let n = Z.to_int (D.value_of_exp d sz) in
	       let d' = D.copy d dst src n in
	       D.set ret dst d'
	     with _ -> Log.error "too large copy size in memcpy stub"
	   end
	| _ -> Log.error "invalid call to memcpy stub"

      let print (d: D.t) ret format_addr va_args (to_buffer: Asm.exp option): D.t * bool =
	     (* ret has to contain the number of bytes stored in dst ;
		format_addr is the address of the format string ;
		va_args is the address of the first parameter 
		(hence the second one will be at va_args + !Config.stack_width/8, 
		the third one at va_args + 2*!Config.stack_width/8, etc. *) 
	try
	  let zero = Asm.Const (Data.Word.of_int Z.zero 8) in
	  let str_len, format_string = D.get_bytes format_addr Asm.EQ zero 1000 8 d in
	  Log.from_analysis (Printf.sprintf "format string: %s" format_string);
	  let off_arg = !Config.stack_width / 8 in
	  let copy_num d len c off arg pad_char pad_left: int * int * D.t =
	    let rec compute digit_nb off =
	      match Bytes.get format_string off with
	      | c when '0' <= c && c <= '9' ->
		 let n = ((Char.code c) - (Char.code '0')) in
		 compute (digit_nb*10+n) (off+1)
	      | 'l' -> 
		 begin
		   let c = Bytes.get format_string (off+1) in 
		   match c with
		   | 'x' | 'X' ->
		      let sz = Config.size_of_long () in
		      Log.from_analysis (Printf.sprintf "hypothesis used in format string: size of long = %d bits" sz);
		      let dump =
			match to_buffer with
			| Some dst ->
			   let dst' = Asm.BinOp (Asm.Add, dst, Asm.Const (Data.Word.of_int (Z.of_int len) !Config.stack_width))  in
			   D.copy_hex d dst'
			| _ -> D.print_hex d
		      in
		      let d', len' = dump arg digit_nb (Char.compare c 'X' = 0) (Some (pad_char, pad_left)) sz in
		      off+2, len', d'
		   | c ->  Log.error (Printf.sprintf "%x: Unknown format in format string" (Char.code c))
		 end
	      | 'x' | 'X' ->
		 let copy =
		   match to_buffer with
		   | Some dst ->
		      let dst' = Asm.BinOp (Asm.Add, dst, Asm.Const (Data.Word.of_int (Z.of_int len) !Config.stack_width))  in
		      D.copy_hex d dst'
		   | _ -> D.print_hex d
		 in
		 let d', len' = copy arg digit_nb (Char.compare c 'X' = 0) (Some (pad_char, pad_left)) !Config.operand_sz in
		 off+1, len', d' 
	      | 's' ->
		 let dump =
		   match to_buffer with
		   | Some dst ->
		      let dst' = Asm.BinOp (Asm.Add, dst, Asm.Const (Data.Word.of_int (Z.of_int len) !Config.stack_width))
		      in
		      D.copy_chars d dst'
		   | _ -> D.print_chars d
		 in
		 off+1, digit_nb, dump arg digit_nb (Some (pad_char, pad_left))
		   
	      (* value is in memory *)
	      | _ -> Log.error "Unknown format in format string"
	    in
	    let n = ((Char.code c) - (Char.code '0')) in
	    compute n off
	  in
	  let copy_arg d off len arg: int * int * D.t =
	    let c = Bytes.get format_string off in 
	    match c with		
	    | 's' ->
	       let dump =
		 match to_buffer with
		 | Some dst ->
		    let dst' = Asm.BinOp (Asm.Add, dst, Asm.Const (Data.Word.of_int (Z.of_int len) !Config.stack_width))  in
		    D.copy_until d dst' 
		 | None ->
		   D.print_until d
	       in
	       let sz, d' = dump arg (Asm.Const (Data.Word.of_int Z.zero 8)) 8 10000 true None in off+1, sz, d'
	    | c when '0' <= c && c <= '9' -> copy_num d len c (off+1) arg '0' true
	    | 'x' | 'X' ->
	       let dump =
		 match to_buffer with
		 | Some dst ->
		    let dst' = Asm.BinOp (Asm.Add, dst, Asm.Const (Data.Word.of_int (Z.of_int len) !Config.stack_width))  in
		    D.copy_hex d dst'
		 | None ->
		   D.print_hex d
	       in
	       let digit_nb = !Config.operand_sz/8 in
	       let d', len' = dump arg digit_nb (Char.compare c 'X' = 0) None !Config.operand_sz in
	       off+1, len', d'    
	    | ' ' -> copy_num d len '0' (off+1) arg ' ' true  
	    | '-' -> copy_num d len '0' (off+1) arg ' ' false
	    | _ -> Log.error "Unknown format in format string"
	  in
	  let rec copy_char d c (off: int) len arg_nb: int * D.t =
	    let src = (Asm.Const (Data.Word.of_int (Z.of_int (Char.code c)) 8)) in
	    let dump =
	      match to_buffer with
	      | Some dst -> D.copy d (Asm.BinOp (Asm.Add, dst, Asm.Const (Data.Word.of_int (Z.of_int len) !Config.address_sz)))
	      | _ -> D.print d
	    in
	    let d' = dump src 8 in
	    fill_buffer d' (off+1) 0 (len+1) arg_nb	    
	  and fill_buffer (d: D.t) (off: int) (state_id: int) (len: int) arg_nb: int * D.t =	    
	    if off < str_len then
	      match state_id with
	      | 0 -> 
		 begin
		   match Bytes.get format_string off with
		   | '%' -> fill_buffer d (off+1) 1 len arg_nb
		   | c -> copy_char d c off len arg_nb
		 end
	      | 1 ->
		 let c = Bytes.get format_string off in
		 begin
		   match c with
		   | '%' -> copy_char d c off len arg_nb 
		   | _ -> fill_buffer d off 2 len arg_nb
		 end
	      | _ (* = 2 ie previous char is % *) ->
		 let arg = Asm.Lval (Asm.M (Asm.BinOp (Asm.Add, va_args, Asm.Const (Data.Word.of_int (Z.of_int (arg_nb*off_arg)) !Config.stack_width)), !Config.stack_width)) in
		 let off', buf_len, d' = copy_arg d off len arg in
		 fill_buffer d' off' 0 (len+buf_len) (arg_nb+1)
	    else
	      (* add a zero to the end of the buffer *)
	      match to_buffer with
	      | Some dst ->	
		 let dst' = Asm.BinOp (Asm.Add, dst, Asm.Const (Data.Word.of_int (Z.of_int len) !Config.stack_width))  in
		 len, D.copy d dst' (Asm.Const (Data.Word.of_int Z.zero 8)) 8
	      | None -> len, d
		
	  in
	  let len', d' = fill_buffer d 0 0 0 0 in
	  (* set the number of bytes (excluding the string terminator) read into the given register *)
	  D.set ret (Asm.Const (Data.Word.of_int (Z.of_int len') !Config.operand_sz)) d'
	    
	with
	| Exceptions.Enum_failure | Exceptions.Concretization ->
	   Log.error "(s)printf: Unknown address of the format string or imprecise value of the format string"		  	  
	| Not_found ->
	   Log.error "address of the null terminator in the format string in (s)printf not found"

      

      let sprintf (d: D.t) (args: Asm.exp list): D.t * bool =
	match args with
	| [Asm.Lval ret ; dst ; format_addr ; va_args] ->
	   print d ret format_addr va_args (Some dst)	     
	| _ -> Log.error "invalid call to (s)printf stub"
	   
      let printf d args =
	(* TODO: not optimal as buffer destination is built as for sprintf *)
	match args with
	| [Asm.Lval ret ; format_addr ; va_args] ->
	   (* creating a very large temporary buffer to store the output of printf *)
	   Log.open_stdout();
	   let d', is_tainted = print d ret format_addr va_args None in
	   Log.from_analysis "printf output:";
	   Log.dump_stdout();
	   Log.from_analysis "--- end of printf--";
	   d', is_tainted
	| _ -> Log.error "invalid call to printf stub" 
	   
	
      let process d fun_name (args: Asm.exp list): D.t * bool =
	let d, is_tainted =
	  try
	    let apply_f =
	      match fun_name with
	      | "memcpy" -> memcpy
	      | "sprintf" -> sprintf 
	      | "printf" -> printf 
	      | "strlen" -> strlen 
	      | _ -> raise Exit
	    in
	    apply_f d args
	  with _ -> Log.from_analysis (Printf.sprintf "no stub or uncomputable stub for %s. Skipped" fun_name); d, false
	in
	if !Config.call_conv = Config.STDCALL then
	  let sp = Register.stack_pointer () in
	  let vsp = Asm.V (Asm.T sp) in
	  let sp_sz = Register.size sp in
	  let c = Data.Word.of_int (Z.of_int (!Config.stack_width / 8)) sp_sz in
	  let e = Asm.BinOp (Asm.Add, Asm.Lval vsp, Asm.Const c) in 
	  let d', is_tainted' =
	    D.set vsp e d
	  in
	  d', is_tainted || is_tainted'
	else
	  d, is_tainted
    end
    open Asm
      
    (* Hash table to know when a widening has to be processed, that is when the associated value reaches the threshold Config.unroll *)
    let unroll_tbl: ((Data.Address.t, int * D.t) Hashtbl.t) ref = ref (Hashtbl.create 1000)

    (* Hash table to store number of times a function has been analysed *)
    let fun_unroll_tbl: (Data.Address.t, int) Hashtbl.t = Hashtbl.create 10
      
    (* current unroll value *)
    (* None is for the default value set in Config *)
    let unroll_nb = ref None
    (** opposite the given comparison operator *)
    let inv_cmp (cmp: Asm.cmp): Asm.cmp =
      match cmp with
      | EQ  -> NEQ
      | NEQ -> EQ
      | LT  -> GEQ
      | GEQ -> LT
      | LEQ -> GT
      | GT  -> LEQ
		 
    let restrict (d: D.t) (e: Asm.bexp) (b: bool): (D.t * bool) =
      let rec process e b =
        match e with
        | BConst b' 		  -> if b = b' then d, false else D.bot, false
        | BUnOp (LogNot, e) 	  -> process e (not b)
					     
        | BBinOp (LogOr, e1, e2)  ->
           let v1, b1 = process e1 b in
           let v2, b2 = process e2 b in
	   let is_tainted = if b then b1||b2 else b1&&b2 in
           if b then D.join v1 v2, is_tainted
           else D.meet v1 v2, is_tainted
		       
        | BBinOp (LogAnd, e1, e2) ->
           let v1, b1 = process e1 b in
           let v2, b2 = process e2 b in
	   let is_tainted = if b then b1&&b2 else b1||b2 in
           if b then D.meet v1 v2, is_tainted
           else D.join v1 v2, is_tainted
		       
        | Asm.Cmp (cmp, e1, e2)   ->
           let cmp' = if b then cmp else inv_cmp cmp in
           D.compare d e1 cmp' e2
      in
      process e b

	      		   
    (** widen the given vertex with all previous vertices that have the same ip as v *)
    let widen prev v =
      let join_v = D.join prev v.Cfa.State.v in
      v.Cfa.State.final <- true;
      v.Cfa.State.v <- D.widen prev join_v
			       
			       
    (** update the abstract value field of the given vertices wrt to their list of statements and the abstract value of their predecessor *)
    (** the widening may be also launched if the threshold is reached *)
    let update_abstract_value (g: Cfa.t) (v: Cfa.State.t) (ip: Data.Address.t) (process_stmts: Cfa.t -> Cfa.State.t -> Data.Address.t -> Cfa.State.t list): Cfa.State.t list =
      try
        let l = process_stmts g v ip in
        List.iter (fun v ->
            let n, jd =
              try
		let n', jd' = Hashtbl.find !unroll_tbl ip in
		let d' = D.join jd' v.Cfa.State.v in
		Hashtbl.replace !unroll_tbl ip (n'+1, d'); n'+1, jd'
              with Not_found ->
		Hashtbl.add !unroll_tbl v.Cfa.State.ip (1, v.Cfa.State.v);
		1, v.Cfa.State.v
            in
	    let nb_max =
	      match !unroll_nb with
	      | None -> !Config.unroll
	      | Some n -> n
	    in
            if n <= nb_max then
              ()
            else
	      begin
		Log.from_analysis (Printf.sprintf "widening occurs at %s" (Data.Address.to_string ip));
		widen jd v
	      end
        ) l;

       List.fold_left (fun l' v -> if D.is_bot v.Cfa.State.v then
                                      begin
					Log.from_analysis (Printf.sprintf "unreachable state at address %s" (Data.Address.to_string ip));
					Cfa.remove_state g v; l'
                                      end
	 else v::l') [] l (* TODO: optimize by avoiding creating a state then removing it if its abstract value is bot *)
      with Exceptions.Empty -> Log.from_analysis (Printf.sprintf "No new reachable states from %s\n" (Data.Address.to_string ip)); []
								
 
    (*************************** Forward from binary file ************************)
    (*****************************************************************************)

   
    (** returns true whenever the given list of statements has a jump stmt (Jmp, Call, Return) *)
    let rec has_jmp stmts =
        match stmts with
        | [] -> false
        | s::stmts' ->
           let b =
             match s with
             | Call _ | Return  | Jmp _ -> true
             | If (_, tstmts, estmts)   -> (has_jmp tstmts) || (has_jmp estmts)
             | _ 			      -> false
           in
           b || (has_jmp stmts')

    let unroll_wrapper (f: unit -> int): unit =
      try
	match !unroll_nb with
	| Some _ -> ()
	| None ->
	   let n = f () in
	   unroll_nb := Some n;
	   Log.from_analysis (Printf.sprintf "automatic loop unrolling detection. Computed value is 0x%x" n)
      with _ -> ()
      
    exception Jmp_exn

    type fun_stack_t = ((string * string) option * Data.Address.t * Cfa.State.t * (Data.Address.t, int * D.t) Hashtbl.t) list ref
    
    let rec process_value (d: D.t) (s: Asm.stmt) (fun_stack: fun_stack_t) =
        match s with
        | Nop 				 -> d, false
        | If (e, then_stmts, else_stmts) -> process_if d e then_stmts else_stmts fun_stack   
        | Set (dst, src) 		 -> D.set dst src d
        | Directive (Remove r) 		 -> let d' = D.remove_register r d in Register.remove r; d', false
        | Directive (Forget r) 		 -> D.forget_lval (V (T r)) d, false
	| Directive (Unroll (e, bs)) ->
	   begin
	     try
	       let f () = min ((Z.to_int (D.value_of_exp d e)) + 1) bs in
	       unroll_wrapper f
	     with _ -> ()
	   end;
	  d, false
	     
	| Directive (Default_unroll) ->
	   Log.from_analysis "set unroll parameter to its default value";
	  unroll_nb := None;
	  d, false

	| Asm.Directive (Asm.Unroll_until (addr, cmp, terminator, upper_bound, sz)) ->
	   begin
	     try
	       let f () =
		 D.get_offset_from addr cmp terminator upper_bound sz d
	       in
	       unroll_wrapper f;
	     with _ -> ()
	   end;
	   d, false
	    
	| Directive (Taint (e, lv)) 	 ->
	   begin
	     let cond =
	       match e with
	       | None -> true
	       | Some c -> D.is_tainted c d  
	     in
	     match lv with
	     | V (T r) ->
	       let mask = Config.Taint (Bits.ff ((Register.size r) / 8)) in
	       if cond then
		 D.taint_register_mask r mask d, true
	       else
		 d, false
	     | M (_, 8) ->
		if cond then
		  try
		    match Data.Address.Set.elements (fst (D.mem_to_addresses d (Lval lv))) with
		    | [a] -> D.taint_address_mask a (Config.Taint (Z.of_int 0xff)) d, true
		    | _ -> raise Exit 
		  with _ -> Log.from_analysis "Tainting directive ignored"; d, false
		else
		  d, false
	     | _ -> Log.from_analysis (Printf.sprintf "Tainting directive for %s ignored" (Asm.string_of_lval lv false)); d, false   
	   end
	| Directive (Type (lv, t)) -> D.set_type lv t d, false
	| Directive (Stub (fun_name, args)) -> Stubs.process d fun_name args
	   (* fun_stack := List.tl !fun_stack; *)
        | _ 				 -> raise Jmp_exn
						     
    and process_if (d: D.t) (e: Asm.bexp) (then_stmts: Asm.stmt list) (else_stmts: Asm.stmt list) fun_stack =
      if has_jmp then_stmts || has_jmp else_stmts then
             raise Jmp_exn
           else
             let dt, bt = List.fold_left (fun (d, b) s -> let d', b' = process_value d s fun_stack in d', b||b') (restrict d e true) then_stmts in
             let de, be = List.fold_left (fun (d, b) s -> let d', b' = process_value d s fun_stack in d', b||b') (restrict d e false) else_stmts in
             D.join dt de, bt||be

   
    let process_ret (fun_stack: fun_stack_t) v =
      try
	begin
	let d = v.Cfa.State.v in
	let d', ipstack, prev_unroll_tbl =
            let _f, ipstack, _v, prev_unroll_tbl = List.hd !fun_stack in
            fun_stack := List.tl !fun_stack;	
            (* check and apply tainting and typing rules *)
	    (* 1. check for assert *)
	    (* 2. taint ret *)
	    (* 3. type ret *)
            d, Some ipstack, prev_unroll_tbl
	    in   
	    (* check whether instruction pointers supposed and effective do agree *)
	    try
              let sp = Register.stack_pointer () in
              let ip_on_stack, is_tainted = D.mem_to_addresses d' (Asm.Lval (Asm.M (Asm.Lval (Asm.V (Asm.T sp)), (Register.size sp)))) in
              match Data.Address.Set.elements (ip_on_stack) with
              | [a] -> 
		 v.Cfa.State.ip <- a;
		 begin
		   match ipstack with
		   | Some ip' -> 
                      if not (Data.Address.equal ip' a) then
			Log.from_analysis (Printf.sprintf "computed instruction pointer %s differs from instruction pointer found on the stack %s at RET instruction"
							  (Data.Address.to_string ip') (Data.Address.to_string a))
		   | None -> ()
		 end;
		 unroll_tbl := prev_unroll_tbl;
		 Some v, is_tainted
              | _ -> raise Exit
	    with
              _ -> Log.error "computed instruction pointer at return instruction is either undefined or imprecise"
	  end
	with Failure "hd" -> Log.from_analysis (Printf.sprintf "RET without previous CALL at address %s" (Data.Address.to_string v.Cfa.State.ip)); None, false
		       

    (** returns the result of the transfert function corresponding to the statement on the given abstract value *)
    let import_call vertices a (pred_fun: Cfa.State.t -> Cfa.State.t) fun_stack =
      let fundec = Hashtbl.find Decoder.Imports.tbl a in
      Log.from_analysis (Printf.sprintf "at %s: stub of %s analysed" (Data.Address.to_string a) (fundec.Decoder.Imports.name));
      let b =
	List.fold_left (fun b v ->
	  let stmts = fundec.Decoder.Imports.prologue @ fundec.Decoder.Imports.stub @ fundec.Decoder.Imports.epilogue in
	  if stmts <> [] then
	    Config.interleave := true;
	  let d', b' =
	    List.fold_left (fun (d, b) stmt -> let d', b' = process_value d stmt fun_stack in d', b||b') (v.Cfa.State.v, false) stmts
	  in
	  v.Cfa.State.v <- d';
	  let pred = pred_fun v in
	  v.Cfa.State.ip <- Data.Address.add_offset pred.Cfa.State.ip (Z.of_int (List.length pred.Cfa.State.bytes));
	  (* set back the stack register to its pred value *)
	  let stack_register = Register.stack_pointer () in
	  v.Cfa.State.v <- D.copy_register stack_register v.Cfa.State.v pred.Cfa.State.v;
	  b||b') false vertices
      in
      vertices, b
		
    let process_stmts fun_stack g (v: Cfa.State.t) (ip: Data.Address.t): Cfa.State.t list =
      let fold_to_target (apply: Data.Address.t -> unit) (vertices: Cfa.State.t list) (target: Asm.exp) (ip_pred: Cfa.State.t -> Cfa.State.t) : (Cfa.State.t list * bool) =
	let import = ref false in
	let res =
		List.fold_left (fun (l, b) v ->
                    try
		      let addrs, is_tainted = D.mem_to_addresses v.Cfa.State.v target in
                      let addresses = Data.Address.Set.elements addrs in
                      match addresses with
                      | [a] ->
			 begin
			   try let res = import_call [v] a ip_pred fun_stack in import := true; res
			   with Not_found -> v.Cfa.State.ip <- a; apply a; v::l, b||is_tainted
			 end
                      | [] -> Log.error (Printf.sprintf "Unreachable jump target from ip = %s\n" (Data.Address.to_string v.Cfa.State.ip))
                      | l -> Log.error (Printf.sprintf "Interpreter: please select between the addresses %s for jump target from %s\n"
						       (List.fold_left (fun s a -> s^(Data.Address.to_string a)) "" l) (Data.Address.to_string v.Cfa.State.ip))
                    with
                    | Exceptions.Enum_failure -> Log.error (Printf.sprintf "Interpreter: uncomputable set of address targets for jump at ip = %s\n" (Data.Address.to_string v.Cfa.State.ip))
		) ([], false) vertices
	in
	if !import then fun_stack := List.tl !fun_stack;
	res

      in
      let add_to_fun_stack a =
	begin
	    try
	      let n' = (Hashtbl.find fun_unroll_tbl a) + 1 in
	      if n' <= !Config.fun_unroll then
		  Hashtbl.replace fun_unroll_tbl a n'
	      else
		Log.error (Printf.sprintf "function at %s has been analysed more than %d times. Analysis stops" (Data.Address.to_string a) !Config.fun_unroll)
	  with Not_found -> Hashtbl.add fun_unroll_tbl a 1
	end;
	let f =
          try
            Some (Hashtbl.find Config.import_tbl (Data.Address.to_int a))
          with Not_found -> None
	in
	fun_stack := (f, ip, v, !unroll_tbl)::!fun_stack;
	unroll_tbl := Hashtbl.create 1000
      in
      let copy v d branch is_pred =
	(* TODO: optimize with Cfa.State.copy that copies every field and then here some are updated => copy them directly *)
        let v' = Cfa.copy_state g v in
        v'.Cfa.State.stmts <- [];
        v'.Cfa.State.v <- d;
	v'.Cfa.State.branch <- branch;
        if is_pred then
          Cfa.add_edge g v v'
        else
          Cfa.add_edge g (Cfa.pred g v) v';
        v'
      in
      

      let rec process_if_with_jmp (vertices: Cfa.State.t list) (e: Asm.bexp) (istmts: Asm.stmt list) (estmts: Asm.stmt list) =
	let process_branch stmts branch =
	  let vertices', b = (List.fold_left (fun (l, b) v ->
					      try
						let d, is_tainted = restrict v.Cfa.State.v e branch in
						if D.is_bot d then
						  l, b
						else
						  (copy v d (Some true) false)::l, b||is_tainted
					      with Exceptions.Empty -> l, b) ([], false) vertices)
	  in
	  let vert, b' = process_list vertices' stmts in
	  vert, b||b'
	in
	let then', bt = process_branch istmts true in
	let else', be = process_branch estmts false in
	List.iter (fun v -> Cfa.remove_state g v) vertices;
	then' @ else', be||bt
     
	      
      and process_vertices (vertices: Cfa.State.t list) (s: Asm.stmt): (Cfa.State.t list * bool) =
        try
          List.fold_left (fun (l, b) v -> let d, b' = process_value v.Cfa.State.v s fun_stack in v.Cfa.State.v <- d; v::l, b||b') ([], false) vertices
        with Jmp_exn ->
             match s with 
             | If (e, then_stmts, else_stmts) -> process_if_with_jmp vertices e then_stmts else_stmts
		
             | Jmp (A a) ->
		begin
		  try
		    let res = import_call vertices a (fun v -> Cfa.pred g (Cfa.pred g v)) fun_stack in
		    fun_stack := List.tl !fun_stack;
		    res
		  with Not_found ->
		    List.map (fun v -> v.Cfa.State.ip <- a; v) vertices, false		      
		end
		  
             | Jmp (R target) ->
		  fold_to_target (fun _a -> ()) vertices target (fun v -> Cfa.pred g (Cfa.pred g v))
			 
             | Call (A a) ->
		begin
		  try		   
		    import_call vertices a (fun v -> Cfa.pred g v) fun_stack 
		  with Not_found ->
		    add_to_fun_stack a;
		    List.iter (fun v -> v.Cfa.State.ip <- a) vertices;
		    vertices, false
		end
	     | Call (R target) -> fold_to_target add_to_fun_stack vertices target (fun v -> Cfa.pred g v)
		
             | Return -> List.fold_left (fun (l, b) v ->
			     let v', b' = process_ret fun_stack v in
			     match v' with
			     | None -> l, b||b'
			     | Some v -> v::l, b||b') ([], false) vertices
				  
             | _       -> vertices, false
			    
      and process_list (vertices: Cfa.State.t list) (stmts: Asm.stmt list): (Cfa.State.t list * bool) =
        match stmts with
        | s::stmts ->
	   begin
	     try
               let (new_vertices: Cfa.State.t list), (b: bool) = process_vertices vertices s in
               let vert, b' = process_list new_vertices stmts in vert, (b||b')
	     with Exceptions.Bot_deref -> [], false (* in case of undefined dereference corresponding vertices are no more explored. They are not added to the waiting list neither *)
	   end
        | []       -> vertices, false
      in
      let vstart = copy v v.Cfa.State.v None true
      in
      vstart.Cfa.State.ip <- ip;
      vstart.Cfa.State.is_tainted <- false;
      let vertices, b = process_list [vstart] v.Cfa.State.stmts in
      if b then
	begin
	  v.Cfa.State.is_tainted <- true;
	  List.iter (fun (_f, _ip, v, _tbl) -> v.Cfa.State.is_tainted <- true) !fun_stack
	end;
      vertices

    (** [filter_vertices g vertices] returns vertices in _vertices_ that are already in _g_ (same address and same decoding context and subsuming abstract value) *)
    let filter_vertices g vertices =
      (* predicate to check whether a new vertex has to be explored or not *)
      let same prev v' =
        Data.Address.equal prev.Cfa.State.ip v'.Cfa.State.ip &&
          prev.Cfa.State.ctx.Cfa.State.addr_sz = v'.Cfa.State.ctx.Cfa.State.addr_sz &&
            prev.Cfa.State.ctx.Cfa.State.op_sz = v'.Cfa.State.ctx.Cfa.State.op_sz &&
              (* fixpoint reached *)
              D.subset v'.Cfa.State.v prev.Cfa.State.v
      in
      List.fold_left (fun l v ->
          try
            (* filters on cutting instruction pointers *)
            if Config.SAddresses.mem (Data.Address.to_int v.Cfa.State.ip) !Config.blackAddresses then
              begin
              Log.from_analysis (Printf.sprintf "Address %s reached but not explored because it belongs to the cut off branches\n"
				   (Data.Address.to_string v.Cfa.State.ip));
		Cfa.remove_state g v;
              raise Exit
              end
            else
              (** explore if a greater abstract state of v has already been explored *)
              Cfa.iter_vertex (fun prev ->
                  if v.Cfa.State.id = prev.Cfa.State.id then
                    ()
                  else
                    if same prev v then raise Exit
                ) g;
            v::l
          with
            Exit -> l
        ) [] vertices
		     
  (** oracle used by the decoder to know the current value of a register *)
    class decoder_oracle s =
    object
      method value_of_register r = D.value_of_register s r
    end
      
    (** fixpoint iterator to build the CFA corresponding to the provided code starting from the initial vertex s *)
    (** g is the initial CFA reduced to the singleton s *) 
    let forward_bin (code: Code.t) (g: Cfa.t) (s: Cfa.State.t) (dump: Cfa.t -> unit): Cfa.t =
      let module Vertices = Set.Make(Cfa.State) in
      (* check whether the instruction pointer is in the black list of addresses to decode *)
      if Config.SAddresses.mem (Data.Address.to_int s.Cfa.State.ip) !Config.blackAddresses then
        Log.error "Interpreter not started as the entry point belongs to the cut off branches\n";
      (* boolean variable used as condition for exploration of the CFA *)
      let continue = ref true		      in
      (* set of waiting nodes in the CFA waiting to be processed *)
      let waiting  = ref (Vertices.singleton s) in
      (* set d to the initial internal state of the decoder *)
      let d = ref (Decoder.init ())             in
      (* function stack *)
      let fun_stack = ref []                    in
      (* compute override rules to apply *)
      let overrides = Hashtbl.create 5 in
      Hashtbl.iter (fun z rules ->
	let ip = Data.Address.of_int Data.Address.Global z !Config.address_sz in
	let check reg vals =
	      (* check the size of taint mask is compatible with the size of the register *)
	  let len = Register.size reg in
	  List.iter (fun v -> if String.length (Bits.z_to_bit_string v) > len then
	      Log.error (Printf.sprintf "Illegal taint mask for register %s" (Register.name reg))) vals
	in
	let rules' =
	  List.map (fun (reg, rule) ->
	    begin
	      match rule with
	      | Config.Taint v -> check reg [v]
	      | Config.TMask (v, m) -> check reg [v ; m]
	    end;
	    D.taint_register_mask reg rule) rules
	in
	Hashtbl.add overrides ip rules'
      ) Config.reg_override;

      List.iter (fun (tbl, region) ->
	Hashtbl.iter (fun z rules ->
	let ip = Data.Address.of_int Data.Address.Global z !Config.address_sz in
	let check vals =
	  List.iter (fun v ->
	    let sz = String.length (Bits.z_to_bit_string v) in
	    if  sz <> 8 && sz <> 0 then
	      Log.error (Printf.sprintf "Illegal taint mask for address %s" (Data.Address.to_string ip))) vals
	in
	let rules' =
	  List.map (fun (a, rule) ->
	    begin
	      match rule with
	      | Config.Taint v -> check [v]
	      | Config.TMask (v, m) -> check [v ; m]
	    end;
	    D.taint_address_mask (Data.Address.of_int region a !Config.address_sz) rule) rules
	in
	Hashtbl.add overrides ip rules'
	  
	) tbl)
	[(Config.mem_override, Data.Address.Global) ;
	 (Config.stack_override, Data.Address.Stack) ; (Config.heap_override, Data.Address.Heap)];
      while !continue do
        (* a waiting node is randomly chosen to be explored *)
        let v = Vertices.choose !waiting in
        waiting := Vertices.remove v !waiting;
        begin
          try
            (* the subsequence of instruction bytes starting at the offset provided the field ip of v is extracted *)
            let text'        = Code.sub code v.Cfa.State.ip						         in
            (* the corresponding instruction is decoded and the successor vertex of v are computed and added to    *)
            (* the CFA                                                                                             *)
            (* except the abstract value field which is set to v.Cfa.State.value. The right value will be          *)
            (* computed next step                                                                                  *)
            (* the new instruction pointer (offset variable) is also returned                                      *)
            let r = Decoder.parse text' g !d v v.Cfa.State.ip (new decoder_oracle v.Cfa.State.v)                   in
            match r with
            | Some (v, ip', d') ->
               (* these vertices are updated by their right abstract values and the new ip                         *)
               let new_vertices = update_abstract_value g v ip' (process_stmts fun_stack)                in
	       	(* add overrides if needed *)
	       let new_vertices =
		 try
		   let rules = Hashtbl.find overrides v.Cfa.State.ip in
		   Log.from_analysis "applied tainting override";
		   List.map (fun v ->
		     v.Cfa.State.v <- List.fold_left (fun d f -> f d) v.Cfa.State.v rules; v) new_vertices
		 with
		   Not_found -> new_vertices
	       in
	       (* among these computed vertices only new are added to the waiting set of vertices to compute       *)
               let vertices'  = filter_vertices g new_vertices in
               List.iter (fun v -> waiting := Vertices.add v !waiting) vertices';
               (* udpate the internal state of the decoder *)
               d := d'
            | None -> ()
          with
          | Exceptions.Error msg 	  -> dump g; Log.error msg
          | Exceptions.Enum_failure -> dump g; Log.error "analysis stopped (computed value too much imprecise)"
          | e			  -> dump g; raise e
        end;
        (* boolean condition of loop iteration is updated *)
        continue := not (Vertices.is_empty !waiting);
      done;
      g								      
	
   
    (******************** BACKWARD *******************************)
    (*************************************************************)
    let back_add_sub op dst e1 e2 d =
      match e1, e2 with
      | Lval lv1, Lval lv2 ->
	 let e = Lval dst in
	 let d', b = D.set lv1 (BinOp (op, e, e2)) d in
	 let d, b' = D.set lv2 (BinOp (op, e, e1)) d' in
	 d, b||b'
		 
      | Lval lv, e
      | e, Lval lv -> 
	 let e' = Lval dst in
	 D.set lv (BinOp (op, e', e)) d
      | _ -> D.forget_lval dst d, false
			   
    let back_set (dst: Asm.lval) (src: Asm.exp) (d: D.t): (D.t * bool) =
      match src with
      | Lval lv -> D.set lv (Lval dst) d
      | UnOp (Not, Lval lv) -> D.set lv (UnOp (Not, Lval dst)) d 
      | BinOp (Add, e1, e2)  -> back_add_sub Sub dst e1 e2 d
      | BinOp (Sub, e1, e2) -> back_add_sub Add dst e1 e2 d
      | _ -> D.forget_lval dst d, false 
	
    (** backward transfert function on the given abstract value *)
    (** BE CAREFUL: this function does not apply to nested if statements *)
    let backward_process (branch: bool option) (d: D.t) (stmt: Asm.stmt) : (D.t * bool) =
      let rec back d stmt =
	match stmt with
	| Call _
	| Return
	| Jmp _
	| Nop -> d, false
	| Directive (Forget _) -> d, false 
	| Directive (Remove r) -> D.add_register r d, false
	| Directive (Taint _) -> D.forget d, false
	| Directive (Type _) -> D.forget d, false
	| Directive (Unroll _) -> d, false
	| Directive (Unroll_until _) -> d, false
	| Directive Default_unroll -> d, false
	| Directive (Stub _) -> d, false
	| Set (dst, src) -> back_set dst src d
	| Assert (_bexp, _msg) -> d, false (* TODO *)
	| If (e, istmts, estmts) ->
	   match branch with
	   | Some true -> let d', b = List.fold_left (fun (d, b) s -> let d', b' = back d s in d', b||b') (d, false) istmts in let v, b' = restrict d' e true in v, b||b'
	   | Some false -> let d', b = List.fold_left (fun (d, b) s -> let d', b' = back d s in d', b||b') (d, false) estmts in let v, b' = restrict d' e false in v, b||b'
	   | None -> D.forget d, false
      in
      back d stmt

    let back_update_abstract_value (g:Cfa.t) (v: Cfa.State.t) (ip: Data.Address.t) (pred: Cfa.State.t): Cfa.State.t list =
      let backward _g v _ip =
	let d', is_tainted = List.fold_left (fun (d, b) s ->
	  let d', b' = backward_process v.Cfa.State.branch d s in
	  d', b||b') (v.Cfa.State.v, false) (List.rev pred.Cfa.State.stmts)
	in
	let d' = D.meet pred.Cfa.State.v d' in
	pred.Cfa.State.v <- D.meet pred.Cfa.State.v d';
	pred.Cfa.State.is_tainted <- is_tainted;
	[pred]
      in
      update_abstract_value g v ip backward
      
			      
    let back_unroll g v pred =
      if v.Cfa.State.final then
	begin
	  v.Cfa.State.final <- false;
	  let new_pred = Cfa.copy_state g v in
	  new_pred.Cfa.State.back_loop <- true;
	  Cfa.remove_edge g pred v;
	  Cfa.add_vertex g new_pred;
	  Cfa.add_edge g pred new_pred;
	  Cfa.add_edge g new_pred v;
	  new_pred
	end
      else
	pred

    (*************************************)
    (* FORWARD AUXILARY FUNCTIONS ON CFA *)
    (*************************************)
    let unroll g v succ =
      if v.Cfa.State.final then
	begin
	  v.Cfa.State.final <- false;
	  let new_succ = Cfa.copy_state g v in
	  new_succ.Cfa.State.forward_loop <- true;
	  Cfa.remove_edge g v succ;
	  Cfa.add_vertex g new_succ;
	  Cfa.add_edge g v new_succ;
	  Cfa.add_edge g new_succ succ;
	  new_succ
	end
      else
	succ

      
    let forward_process (d: D.t) (stmt: Asm.stmt) (branch: bool option): (D.t * bool) =
      (* function stack *)
      let fun_stack = ref [] in
      let rec forward (d: D.t) (stmt: Asm.stmt): (D.t * bool) =
	match stmt with
	| Asm.Nop 
	| Asm.Directive (Asm.Forget _) 
	| Asm.Directive (Asm.Remove _)
	| Asm.Directive (Asm.Taint _)
	| Asm.Directive (Asm.Type _)
	| Asm.Directive (Asm.Unroll _)
	| Asm.Directive (Asm.Stub _)
	| Asm.Directive (Asm.Unroll_until _)
	| Asm.Directive Asm.Default_unroll
	| Asm.Jmp (Asm.A _)
	| Asm.Return
	| Asm.Call (Asm.A _) -> d, false
	| Asm.Set (dst, src) -> D.set dst src d
	| Assert (_bexp, _msg) -> d, false (* TODO *)
	| Asm.If (e, istmts, estmts) ->
	   begin
	     try process_if d e istmts estmts fun_stack
	     with Jmp_exn ->
	       match branch with
	       | Some true -> List.fold_left (fun (d, b) stmt -> let d', b' = forward d stmt in d', b||b') (restrict d e true) istmts
	       | Some false -> List.fold_left (fun (d, b) stmt -> let d', b' = forward d stmt in d', b||b') (restrict d e false) estmts
	       | None -> Log.error "Illegal call to Interpreter.forward_process"
	   end
	| Asm.Call (Asm.R _) -> D.forget d, true
	| Asm.Jmp (Asm.R _) -> D.forget d, true (* TODO may be more precise but check whether the target is really in the CFA. If not then go back to forward_bin for that branch *)
      in
      forward d stmt
	      
    let forward_abstract_value (g:Cfa.t) (succ: Cfa.State.t) (ip: Data.Address.t) (v: Cfa.State.t): Cfa.State.t list =
      let forward _g v _ip =
	let d', is_tainted = List.fold_left (fun (d, b) s ->
				 let d', b' = forward_process d s (succ.Cfa.State.branch) in
				 d', b||b') (v.Cfa.State.v, false) (succ.Cfa.State.stmts)
       in
      	succ.Cfa.State.v <- D.meet succ.Cfa.State.v d';
	succ.Cfa.State.is_tainted <- is_tainted;
	[succ]
      in
      update_abstract_value g v ip forward
    (****************************)
    (* FIXPOINT ON CFA *)
    (****************************)
      let cfa_iteration (update_abstract_value: Cfa.t -> Cfa.State.t -> Data.Address.t -> Cfa.State.t list -> Cfa.State.t list)
			(next: Cfa.t -> Cfa.State.t -> Cfa.State.t list)
			(unroll: Cfa.t -> Cfa.State.t -> Cfa.State.t -> Cfa.State.t) (g: Cfa.t) (s: Cfa.State.t) (dump: Cfa.t -> unit): Cfa.t =
	if D.is_bot s.Cfa.State.v then
	begin
	  dump g;
	  Log.error "analysis not started: empty meet with previous computed value"
	end
      else
	let module Vertices = Set.Make(Cfa.State) in
	let continue = ref true in
	let waiting = ref (Vertices.singleton s) in
	try
	  while !continue do
	    let v = Vertices.choose !waiting in	
	    waiting := Vertices.remove v !waiting;
	    let v' = next g v in
	    let new_vertices = List.fold_left (fun l v' -> (update_abstract_value g v v'.Cfa.State.ip [v'])@l) [] v' in
	    let new_vertices' = List.map (unroll g v) new_vertices in
	    let vertices' = filter_vertices g new_vertices' in
	    List.iter (fun v -> waiting := Vertices.add v !waiting) vertices';
	    continue := not (Vertices.is_empty !waiting)
	  done;
	  g
	with
	| Invalid_argument _ -> Log.from_analysis "entry node of the CFA reached"; g
	| e -> dump g; raise e
			     
      let backward (g: Cfa.t) (s: Cfa.State.t) (dump: Cfa.t -> unit): Cfa.t =
	cfa_iteration (fun g v ip vert -> back_update_abstract_value g v ip (List.hd vert))
		      (fun g v -> [Cfa.pred g v]) back_unroll g s dump		    
  
      let forward_cfa (g: Cfa.t) (s: Cfa.State.t) (dump: Cfa.t -> unit): Cfa.t =
	cfa_iteration (fun g v ip vert -> List.fold_left (fun l v' -> (forward_abstract_value g v ip v')@l) [] vert)
		      Cfa.succs unroll g s dump
      
    (************* INTERLEAVING OF FORWARD/BACKWARD ANALYSES *******)
    (******************************************************)
  	  
      let interleave_from_cfa (g: Cfa.t) (dump: Cfa.t -> unit): Cfa.t =
	Log.from_analysis "entering interleaving mode";
	let process mode cfa =
	  Hashtbl.clear !unroll_tbl;
	  List.fold_left (fun g s0 -> mode g s0 dump) cfa (Cfa.last cfa)
	in
	let g_bwd = process backward g in
	process forward_cfa g_bwd
  end
     
