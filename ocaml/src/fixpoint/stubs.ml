(*
    This file is part of BinCAT.
    Copyright 2014-2021 - Airbus

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

module L = Log.Make(struct let name = "stubs" end)

module type T =
sig
  type domain_t

  val process : Data.Address.t -> Data.Address.t option -> domain_t -> string -> Asm.calling_convention_t -> 
    domain_t * Taint.Set.t * Asm.stmt list

  val skip: domain_t -> Config.fun_t -> Asm.calling_convention_t -> domain_t *  Taint.Set.t * Asm.stmt list
    
  val init: unit -> unit

  val default_handler: int -> Asm.stmt list
    
  val stubs : (string, (Data.Address.t -> Data.Address.t option -> domain_t -> Asm.lval -> (int -> Asm.lval) ->
                         domain_t * Taint.Set.t) * int) Hashtbl.t
end

module Make(D: Domain.T) = struct

    type domain_t = D.t

    let shift argfun n = fun x -> (argfun (n+x))

    let heap_allocator (ip: Data.Address.t) (calling_ip: Data.Address.t option) (d: domain_t) ret args: domain_t * Taint.Set.t =
      try
        let sz = D.value_of_exp d (Asm.Lval (args 0)) in
        let region, id = Data.Address.new_heap_region (Z.mul (Z.of_int 8) sz) in
        Hashtbl.add Dump.heap_id_tbl id ip;
        let d' = D.allocate_on_heap d id in
        let zero = Data.Word.zero !Config.address_sz in
        let addr = region, zero in
        let success_msg = "successfull heap allocation " in
        let failure_msg = "heap allocation failed  " in
        let postfix =
          match calling_ip with
          | Some ip -> let ip_str = Data.Address.to_string ip in "at " ^ ip_str
          | None -> ""
        in
        let success_msg = success_msg ^ postfix in
        let failure_msg = failure_msg ^ postfix in
        D.set_lval_to_addr ret [ (addr, success_msg) ; (Data.Address.of_null (), failure_msg) ] d'
      with Z.Overflow -> raise (Exceptions.Too_many_concrete_elements "heap allocation: imprecise size to allocate")


    let check_free (ip: Data.Address.t) (a: Data.Address.t): Data.Address.heap_id_t =
      match a with
      | Data.Address.Heap (id, _), o ->
         if Data.Word.compare o (Data.Word.zero !Config.address_sz) <> 0 then
           raise (Exceptions.Undefined_free
                    (Printf.sprintf "at instruction %s: base address to free is not zero (%s)"
           (Data.Address.to_string ip)
           (Data.Address.to_string a)))
         else
           id

      | _ ->
         raise (Exceptions.Undefined_free
                  (Printf.sprintf "at instruction %s: base address (%s) to free not in the heap or NULL"
                  (Data.Address.to_string ip)
                  (Data.Address.to_string a)))
           
    let heap_deallocator (ip: Data.Address.t) _ (d: domain_t) _ret args: domain_t * Taint.Set.t =
      let mem = Asm.Lval (args 0) in
      try
        let addrs, taint = D.mem_to_addresses d mem in
        let addrs' = Data.Address.Set.elements addrs in 
        match addrs' with
        | [a] ->
           let id = check_free ip a in
           L.debug2 (fun p -> p "check_free");
           D.deallocate d id, taint
             
        | _::_ ->
           let ids = List.fold_left (fun ids a -> (check_free ip a)::ids) [] addrs' in
           D.weak_deallocate d ids, taint
             
        | [] ->
           let msg = Printf.sprintf "Illegal dereference of %s (null)" (Asm.string_of_lval (args 0) true) in
           raise (Exceptions.Null_deref msg)
      with
        Exceptions.Too_many_concrete_elements _  ->
          raise (Exceptions.Too_many_concrete_elements "Stubs: too many addresses to deallocate")
      
    let strlen (_ip: Data.Address.t) _ (d: domain_t) ret args: domain_t * Taint.Set.t =
      let zero = Asm.Const (Data.Word.zero 8) in
      let len = D.get_offset_from (Asm.Lval (args 0)) Asm.EQ zero 10000 8 d in
      if len > !Config.unroll then
        begin
          L.info (fun p -> p "updates automatic loop unrolling with the computed string length = %d" len);
          Config.unroll := len
        end;
      D.set ret (Asm.Const (Data.Word.of_int (Z.of_int len) !Config.operand_sz)) d

    let memcpy (_ip: Data.Address.t) _ (d: domain_t) ret args: domain_t * Taint.Set.t =
      L.info (fun p -> p "memcpy stub");
      let dst = Asm.Lval (args 0) in
      let src = Asm.Lval (args 1) in
      let sz =  Asm.Lval (args 2) in
      try
        let n = Z.to_int (D.value_of_exp d sz) in
        let d' = D.copy d dst (Asm.Lval (Asm.M (src, (8*n)))) (8*n) in
        D.set ret dst d'
      with _ -> L.abort (fun p -> p "too large copy size in memcpy stub")

    let memcmp (_ip: Data.Address.t) _ (d: domain_t) ret args: domain_t * Taint.Set.t =
      L.info (fun p -> p "memcmp stub");
      let sz =  Asm.Lval (args 2) in
      try
        let n = Z.to_int (D.value_of_exp d sz) in
        let lv1 = Asm.M (Asm.Lval (args 0), 8*n) in
        let lv2 = Asm.M (Asm.Lval (args 1), 8*n) in
        let taint =
          try
            Taint.join (D.get_taint lv1 d) (D.get_taint lv2 d)
          with _ -> Taint.TOP
        in
        let v1 = D.value_of_exp d (Asm.Lval lv1) in
        let v2 = D.value_of_exp d (Asm.Lval lv2) in
        let res = Asm.Const (Data.Word.of_int (Z.sub v1 v2) !Config.operand_sz) in
        let d' = fst (D.set ret res d) in
        D.taint_lval ret taint d'
      with _ -> D.forget_lval ret d, Taint.Set.singleton Taint.TOP
      
    let memset (_ip: Data.Address.t) _ (d: domain_t) ret args: domain_t * Taint.Set.t =
      let arg0 = args 0 in
      let dst = Asm.Lval arg0 in
      let src = args 1 in
      let nb = Asm.Lval (args 2) in
      
      try
        let nb' = D.value_of_exp d nb in
        let byte =
        match src with
        | Asm.V (Asm.T r) -> Asm.V (Asm.P (r, 0, 7))
        | Asm.V (Asm.P (r, l, u)) when u-l>=7-> Asm.V (Asm.P (r, l, l+7)) (* little endian only ? *)
        | Asm.M (e, n) when Z.compare (Z.of_int n) nb' >= 0 -> Asm.M(e, 8) (* little endian only ? *)
        | _ -> raise (Exceptions.Error "inconsistent argument for memset")
        in
        let sz = Asm.lval_length arg0 in
        let byte_exp = Asm.Lval byte in
        L.info (fun p -> p "memset(%s, %s, %s) stub" (Z.to_string (D.value_of_exp d dst)) (Z.to_string (D.value_of_exp d byte_exp)) (Z.to_string nb'));
        let one_set d i =
          if Z.compare i nb' < 0 then
            let addr = Asm.BinOp (Asm.Add, dst, Asm.Const (Data.Word.of_int i sz)) in
            fst (D.set (Asm.M(addr, 8)) byte_exp d) (* we ignore taint as the source is a constant *)
          else
            d
        in            
        let rec set_loop d i = if Z.sign i < 0 then d
                               else let d'=one_set d i in set_loop d' (Z.pred i) in
        let d' = set_loop d nb' in
        (* result is tainted if the destination to copy the byte is tainted *)
        D.set ret dst d'
      with _ -> L.abort (fun p -> p "too large number of bytes to copy in memset stub")
        
    let print (d: domain_t) ret format_addr va_args (to_buffer: Asm.exp option): domain_t * Taint.Set.t =
        (* ret has to contain the number of bytes stored in dst ;
           format_addr is the address of the format string ;
           va_args the list of values needed to fill the format string *)
        try
            let zero = Asm.Const (Data.Word.of_int Z.zero 8) in
            let str_len, format_string = D.get_bytes format_addr Asm.EQ zero 1000 8 d in
            L.info (fun p -> p "(s)printf stub, format string: \"%s\"" (String.escaped (Bytes.to_string format_string)));
            let format_num d dst_off c fmt_pos arg pad_char pad_left: int * int * domain_t =
              let rec compute digit_nb fmt_pos =
                let c = Bytes.get format_string fmt_pos in
                    match c with
                    | c when '0' <= c && c <= '9' ->
                      let n = ((Char.code c) - (Char.code '0')) in
                          compute (digit_nb*10+n) (fmt_pos+1)
                    | 'l' ->
                      begin
                          let c = Bytes.get format_string (fmt_pos+1) in
                          match c with
                          | 'x' | 'X' ->
                            let sz = Config.size_of_long () in
                            L.info (fun p -> p "hypothesis used in format string: size of long = %d bits" sz);
                            let dump =
                                match to_buffer with
                                | Some dst ->
                                  let dst' = Asm.BinOp (Asm.Add, dst, Asm.Const (Data.Word.of_int (Z.of_int dst_off) !Config.stack_width))  in
                                  D.copy_hex d dst'
                                | _ -> D.print_hex d
                            in
                            let d', dst_off' = dump arg digit_nb (Char.compare c 'X' = 0) (Some (pad_char, pad_left)) sz in
                            fmt_pos+2, dst_off', d'
                          | c ->  L.abort (fun p -> p "(s)printf: Unknown format char in format string: %c" c)
                      end
                    | 'x' | 'X' | 'd' ->
                       let format_copy, format_print =
                         match c with
                         |'x' | 'X' -> D.copy_hex, D.print_hex
                         | _ -> D.copy_int, D.print_int
                       in
                       let copy =
                         match to_buffer with
                         | Some dst ->
                            let dst' = Asm.BinOp (Asm.Add, dst, Asm.Const (Data.Word.of_int (Z.of_int dst_off) !Config.stack_width))  in
                            format_copy d dst'
                          | _ -> format_print d
                       in
                       let d', dst_off' = copy arg digit_nb (Char.compare c 'X' = 0) (Some (pad_char, pad_left)) !Config.operand_sz in
                       fmt_pos+1, dst_off', d'

                       
                    | 's' ->
                      let dump =
                          match to_buffer with
                          | Some dst ->
                            let dst' = Asm.BinOp (Asm.Add, dst, Asm.Const (Data.Word.of_int (Z.of_int dst_off) !Config.stack_width))
                            in
                            D.copy_chars d dst'
                          | _ -> (fun arg1 arg2 arg3 -> fst (D.print_chars d arg1 arg2 arg3))
                      in
                      fmt_pos+1, digit_nb, dump arg digit_nb (Some (pad_char, pad_left))

                    (* value is in memory *)
                    | c ->  L.abort (fun p -> p "(s)printf: Unknown format char in format string: %c" c)
                in
                let n = ((Char.code c) - (Char.code '0')) in
                    compute n fmt_pos
            in
            let format_arg d fmt_pos dst_off arg: int * int * domain_t =
                let c = Bytes.get format_string fmt_pos in
                match c with
                | 's' -> (* %s *)
                  let dump =
                      match to_buffer with
                      | Some dst ->
                        let dst' = Asm.BinOp (Asm.Add, dst, Asm.Const (Data.Word.of_int (Z.of_int dst_off) !Config.stack_width))  in
                        D.copy_until d dst'
                      | None ->
                        D.print_until d
                  in
                  let sz, d' = dump arg (Asm.Const (Data.Word.of_int Z.zero 8)) 8 10000 true None in fmt_pos+1, sz, d'
                | 'x' | 'X' -> (* %x | %X *)
                  let dump =
                      match to_buffer with
                      | Some dst ->
                        let dst' = Asm.BinOp (Asm.Add, dst, Asm.Const (Data.Word.of_int (Z.of_int dst_off) !Config.stack_width))  in
                        D.copy_hex d dst'
                      | None ->
                        D.print_hex d
                  in
                  let digit_nb = !Config.operand_sz/8 in
                  let d', dst_off' = dump arg digit_nb (Char.compare c 'X' = 0) None !Config.operand_sz in
                  fmt_pos+1, dst_off', d'
                | 'd' -> (* %d *)
                   let dump =
                      match to_buffer with
                      | Some dst ->
                        let dst' = Asm.BinOp (Asm.Add, dst, Asm.Const (Data.Word.of_int (Z.of_int dst_off) !Config.stack_width))  in
                        D.copy_int d dst'
                      | None ->
                        D.print_int d
                  in
                  let digit_nb = !Config.operand_sz/8 in
                  let d', dst_off' = dump arg digit_nb (Char.compare c 'X' = 0) None !Config.operand_sz in
                  fmt_pos+1, dst_off', d'
                | c when '1' <= c && c <= '9' -> format_num d dst_off c (fmt_pos+1) arg '0' true
                | '0' -> format_num d dst_off '0' (fmt_pos+1) arg '0' true
                | ' ' -> format_num d dst_off '0' (fmt_pos+1) arg ' ' true
                | '-' -> format_num d dst_off '0' (fmt_pos+1) arg ' ' false
                | _ -> L.abort (fun p -> p "Unknown format or modifier in format string: %c" c)
            in
            let rec copy_char d c (fmt_pos: int) dst_off arg_nb: int * domain_t =
                let src = (Asm.Const (Data.Word.of_int (Z.of_int (Char.code c)) 8)) in
                let dump =
                    match to_buffer with
                    | Some dst ->  D.copy d (Asm.BinOp (Asm.Add, dst, Asm.Const (Data.Word.of_int (Z.of_int dst_off) !Config.address_sz)))
                    | _ -> D.print d
                in
                let d' = dump src 8 in
                    fill_buffer d' (fmt_pos+1) 0 (dst_off+1) arg_nb
            (* state machine for format string parsing *)
            and fill_buffer (d: domain_t) (fmt_pos: int) (state_id: int) (dst_off: int) arg_nb: int * domain_t =
                if fmt_pos < str_len then
                    match state_id with
                    | 0 -> (* look for % *)
                      begin
                          match Bytes.get format_string fmt_pos with
                          | '%' -> fill_buffer d (fmt_pos+1) 1 dst_off arg_nb
                          | c -> copy_char d c fmt_pos dst_off arg_nb
                      end
                    | 1 -> (* % found, do we have %% ? *)
                      let c = Bytes.get format_string fmt_pos in
                      begin
                          match c with
                          | '%' -> copy_char d c fmt_pos dst_off arg_nb
                          | _ -> fill_buffer d fmt_pos 2 dst_off arg_nb
                      end
                    | _ (* = 2 ie previous char is % *) ->
                      let arg = Asm.Lval (va_args arg_nb) in
                      let fmt_pos', buf_len, d' = format_arg d fmt_pos dst_off arg in
                      fill_buffer d' fmt_pos' 0 (dst_off+buf_len) (arg_nb+1)
                else
                    (* add a zero to the end of the buffer *)
                    match to_buffer with
                    | Some dst ->
                      let dst' = Asm.BinOp (Asm.Add, dst, Asm.Const (Data.Word.of_int (Z.of_int dst_off) !Config.stack_width))  in
                      dst_off, D.copy d dst' (Asm.Const (Data.Word.of_int Z.zero 8)) 8
                    | None -> dst_off, d

            in
            let len', d' = fill_buffer d 0 0 0 0 in
            (* set the number of bytes (excluding the string terminator) read into the given register *)
            D.set ret (Asm.Const (Data.Word.of_int (Z.of_int len') !Config.operand_sz)) d'

        with
        | Exceptions.Too_many_concrete_elements _ as e ->
           L.exc_and_abort e (fun p -> p "(s)printf: Unknown address of the format string or imprecise value of the format string")
        | Not_found as e ->
           L.exc_and_abort e (fun p -> p "address of the null terminator in the format string in (s)printf not found")


    let sprintf (_ip: Data.Address.t) _ (d: domain_t) ret args: domain_t * Taint.Set.t =
      let dst = Asm.Lval (args 0) in
      let format_addr = Asm.Lval (args 1) in
      let  va_args = shift args 2 in
      print d ret format_addr va_args (Some dst)

    let sprintf_chk (_ip: Data.Address.t) _ (d: domain_t) ret args: domain_t * Taint.Set.t =
      let dst = Asm.Lval (args 0) in
      let format_addr = Asm.Lval (args 3) in
      let va_args = shift args 4 in
      print d ret format_addr va_args (Some dst)

    let printf (_ip: Data.Address.t) _ d ret args =
        (* TODO: not optimal as buffer destination is built as for sprintf *)
      let format_addr = Asm.Lval (args 0) in
      let va_args = shift args 1 in
      (* creating a very large temporary buffer to store the output of printf *)
      let d', is_tainted = print d ret format_addr va_args None in
      d', is_tainted

    let printf_chk (ip: Data.Address.t) calling_ip d ret args = printf ip calling_ip d ret (shift args 1) 

    let puts (_ip: Data.Address.t) _ d ret args =
      let str = Asm.Lval (args 0) in
      let len, d' = D.print_until d str (Asm.Const (Data.Word.of_int Z.zero 8)) 8 10000 true None in
      let d', taint = D.set ret (Asm.Const (Data.Word.of_int (Z.of_int len) !Config.operand_sz)) d' in
      Log.Stdout.stdout (fun p -> p "\n");
      d', taint


    let write _ip _ d ret args =
      let fd =
        try
         Z.to_int (D.value_of_exp d (Asm.Lval (args 0)))
        with _ -> L.abort (fun p -> p "imprecise file descriptor as argument of write")
      in
      if fd = 1 then
        let buf = Asm.Lval (args 1) in
        try
          let char_nb = Z.to_int (D.value_of_exp d (Asm.Lval (args 2))) in
          let d', len = D.print_chars d buf char_nb None in
          let d', taint = D.set ret (Asm.Const (Data.Word.of_int (Z.of_int len) !Config.operand_sz)) d' in
          d', taint
        with Exceptions.Too_many_concrete_elements _ -> L.abort (fun p -> p "imprecise number of char to write")
      else
        L.abort (fun p -> p "write output implemented only for stdout")
      
    let stubs = Hashtbl.create 5

    let signal_process d call_conv: domain_t * Taint.Set.t * Asm.stmt list =
      let args = call_conv.Asm.arguments in
      let d, taint, stmts =
        try
        let int_nb = Z.to_int (D.value_of_exp d (Asm.Lval (args 0))) in
        let addrs, taint = D.mem_to_addresses d (Asm.Lval (args 1)) in
        (* int_nb and addr has to be concrete values *)
        match Data.Address.Set.elements addrs with
        | [a] -> d, taint, [Asm.Directive (Asm.Handler (int_nb, a))]
        | _ -> raise (Exceptions.Too_many_concrete_elements "several possible handler addresses")
        with Exceptions.Too_many_concrete_elements _ ->
          L.warn (fun p -> p "uncomputable argument of signal call (signal number or handler address). Skipped");
          d, Taint.Set.singleton Taint.U, []
      in
      let cleanup_stmts = (call_conv.Asm.callee_cleanup 2) in
      d, taint, stmts@cleanup_stmts

             
    let putchar (_ip) _ d ret args =
      let str = Asm.Lval (args 0) in
      let d' = D.print d str !Config.operand_sz in
      D.set ret (Asm.Const (Data.Word.of_int Z.one !Config.operand_sz)) d'

    (* TODO: merge all tainting src to have the same id *)
    let getc _  _ d ret _ =
      let d' = D.forget_lval ret d in
      if !Config.taint_input then
        let taint_mask = Taint.S (Taint.SrcSet.singleton (Taint.Src.Tainted (Taint.Src.new_src()))) in
        D.taint_lval ret taint_mask d'
      else
        d', Taint.Set.singleton Taint.U
      
    let getchar = getc
                                                 
    let bin_exit (_ip) _ _d _ret _args =
      raise (Exceptions.Stop "on exit call")

    let process ip calling_ip d fun_name call_conv: domain_t * Taint.Set.t * Asm.stmt list =
       if String.compare fun_name "signal" = 0 then
        signal_process d call_conv 
      else     
      let apply_f, arg_nb =
        try Hashtbl.find stubs fun_name
        with Not_found -> L.abort (fun p -> p "No stub available for function [%s]" fun_name)
      in
      let d', taint =
        try apply_f ip calling_ip d call_conv.Asm.return call_conv.Asm.arguments
        with
        | Exit -> d, Taint.Set.singleton Taint.U
        | Exceptions.Use_after_free _ as e -> raise e 
        | Exceptions.Double_free -> raise Exceptions.Double_free
        | Exceptions.Null_deref _ as e  -> raise e
        | Exceptions.Stop _ as e -> raise e
        | Exceptions.Error _ as e -> raise e
        | e ->
          L.exc e (fun p -> p "error while processing stub [%s]" fun_name);
          L.warn (fun p -> p "uncomputable stub for [%s]. Skipped." fun_name);
          d, Taint.Set.singleton Taint.U 
           
      in
      let cleanup_stmts = (call_conv.Asm.callee_cleanup arg_nb) in
      d', taint, cleanup_stmts


  
        
    let skip d f call_conv: domain_t * Taint.Set.t * Asm.stmt list =
      let arg_nb, ret_val = Hashtbl.find Config.funSkipTbl f in
      let d, taint =
        match ret_val with
        | None -> D.forget_lval call_conv.Asm.return d, Taint.Set.singleton Taint.TOP
        | Some ret_val' ->
           let sz = Config.size_of_config ret_val' in
           match call_conv.Asm.return with
           | Asm.V (Asm.T r)  when Register.size r = sz -> D.set_register_from_config r ret_val' d 
           | Asm.M (e, n) when sz = n ->
              let addrs, _ = D.mem_to_addresses d e in
              let d', taint' =
                match Data.Address.Set.elements addrs with
                | [a] ->     
                   D.set_memory_from_config a  ret_val' 1 d
                | _ -> D.forget d, Taint.Set.singleton Taint.TOP (* TODO: be more precise *)
              in
              d', taint'
              
           | _ -> D.forget d, Taint.Set.singleton Taint.TOP (* TODO: be more precise *)
      in
      let cleanup_stmts = call_conv.Asm.callee_cleanup (Z.to_int arg_nb) in
      d,taint, cleanup_stmts

    let default_handler sig_nb =
      (* see man 7 signal. Implementation of POSIX.1-2001 *)
      let ignore_sig sig_text =
        L.analysis (fun p -> p "Handling signal %s: ignored" sig_text);
        []
      in
      let abort sig_text =
        L.analysis (fun p -> p "Handling signal %s: analysis stops" sig_text);
        L.abort (fun p -> p "see above")
      in
      match sig_nb with
      | 1 (* SIGHUP *) -> abort "SIGHUP"
      | 2 (* SIGINT *) -> abort "SIGINT"                        
      | 3 (* SIGQUIT *) -> abort "SIGQUIT"
      | 4 (* SIGIL *) -> abort "SIGIL"
      | 5 (* SIGTRAP *) -> abort "SIGTRAP"
      | 6 (* SIGABRT *) -> abort "SIGABRT"
      | 7 | 10 (* SIGBUS *) -> abort "SIGBUS"
      | 8 (* SIGFPE *) -> abort "SIGFPE"
      | 9 (* SIGKILL *) -> abort "SIGKILL"
      | 11 (* SIGSEGV *) -> abort "SIGSEGV"
      | 12 | 31 (* SIGSYS *) -> abort "SIGSYS"
      | 13 (* SIGPIPE *) -> abort "SIGPIPE"
      | 14 (* SIGALRM *) -> ignore_sig "SIGALRM"
      | 15 (* SIGTERM *) -> abort "SIGTERM"
      | 16 (* SIGUSR1 *) -> ignore_sig "SIGUSR1"
      | 17 | 18 (* SIGCHLD *) -> abort "SIGCHLD"
      | 19 | 25 (* SIGCONT *) -> ignore_sig "SIGCONT"
      | 20 | 24 (* SIGTSTP *) -> ignore_sig "SIGSTP"
      | 26 (* SIGTTIN *) -> ignore_sig "SIGTTIN"
      | 27 (* SIGTTOU *) -> ignore_sig "SIGTTOU"
      | _ -> L.analysis (fun p -> p "received Illegal signal %d. Ignored" sig_nb); []
      
    let init () =
      Hashtbl.replace stubs "memcpy"        (memcpy,      3);
      Hashtbl.replace stubs "memcmp"        (memcmp,      3);
      Hashtbl.replace stubs "memset"        (memset,      3);
      Hashtbl.replace stubs "sprintf"       (sprintf,     0);
      Hashtbl.replace stubs "printf"        (printf,      0);
      Hashtbl.replace stubs "write" (write, 3);
      Hashtbl.replace stubs "__sprintf_chk" (sprintf_chk, 0);
      Hashtbl.replace stubs "__printf_chk"  (printf_chk,  0);
      Hashtbl.replace stubs "puts"          (puts,        1);
      Hashtbl.replace stubs "strlen"        (strlen,      1);
      Hashtbl.replace stubs "signal"        ((fun _ _ _ _ _ -> raise (Exceptions.Stop "on signal that stops execution of the program")),  0); (* special treatment for signal see signal_process *)
      Hashtbl.replace stubs "putchar"        (putchar,      1);
      Hashtbl.replace stubs "getchar" (getchar, 0);
      Hashtbl.replace stubs "getc" (getc, 1);
      Hashtbl.replace stubs "exit"        (bin_exit,      1);
      Hashtbl.replace stubs "malloc" (heap_allocator, 1);
      Hashtbl.replace stubs "free" (heap_deallocator, 1);;


end
