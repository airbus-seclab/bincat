module Make (D: Domain.T) =
struct
  let strlen (d: D.t) (args: Asm.exp list): D.t * bool =
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
              | c ->  Log.error (Printf.sprintf "%x: Unknown format in format string" (Char.code c))
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
	      | Some dst ->  D.copy d (Asm.BinOp (Asm.Add, dst, Asm.Const (Data.Word.of_int (Z.of_int len) !Config.address_sz)))
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
