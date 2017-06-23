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

module L = Log.Make(struct let name = "stubs" end)

module Make (D: Domain.T) =
struct
    let strlen (d: D.t) (args: Asm.exp list): D.t * bool =
        match args with
        | [Asm.Lval ret ; buf] ->
          let zero = Asm.Const (Data.Word.zero !Config.operand_sz) in
          let len = D.get_offset_from buf Asm.EQ zero !Config.operand_sz 10000 d in
          if len > !Config.unroll then
              begin
                  L.analysis (fun p -> p "updates automatic loop unrolling with the computed string length = %d" len);
                  Config.unroll := len
              end;
          D.set ret (Asm.Const (Data.Word.of_int (Z.of_int len) !Config.operand_sz)) d
        | _ -> L.abort (fun p -> p "invalid call to strlen stub")

    let memcpy (d: D.t) (args: Asm.exp list): D.t * bool =
        L.analysis (fun p -> p "memcpy stub");
        match args with
        | [Asm.Lval ret ; dst ; src ; sz] ->
          begin
              try
                  let n = Z.to_int (D.value_of_exp d sz) in
                  let d' = D.copy d dst (Asm.Lval (Asm.M (src, (8*n)))) (8*n) in
                  D.set ret dst d'
              with _ -> L.abort (fun p -> p "too large copy size in memcpy stub")
          end
        | _ -> L.abort (fun p -> p "invalid call to memcpy stub")

    let print (d: D.t) ret format_addr va_args (to_buffer: Asm.exp option): D.t * bool =
        (* ret has to contain the number of bytes stored in dst ;
           format_addr is the address of the format string ;
           va_args is the address of the first parameter
           (hence the second one will be at va_args + !Config.stack_width/8,
           the third one at va_args + 2*!Config.stack_width/8, etc. *)
        try
            let zero = Asm.Const (Data.Word.of_int Z.zero 8) in
            let str_len, format_string = D.get_bytes format_addr Asm.EQ zero 1000 8 d in
            L.analysis (fun p -> p "format string: %s" format_string);
            let off_arg = !Config.stack_width / 8 in
            let format_num d dst_off c fmt_pos arg pad_char pad_left: int * int * D.t =
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
                            L.analysis (fun p -> p "hypothesis used in format string: size of long = %d bits" sz);
                            let dump =
                                match to_buffer with
                                | Some dst ->
                                  let dst' = Asm.BinOp (Asm.Add, dst, Asm.Const (Data.Word.of_int (Z.of_int dst_off) !Config.stack_width))  in
                                  D.copy_hex d dst'
                                | _ -> D.print_hex d
                            in
                            let d', dst_off' = dump arg digit_nb (Char.compare c 'X' = 0) (Some (pad_char, pad_left)) sz in
                            fmt_pos+2, dst_off', d'
                          | c ->  L.abort (fun p -> p "%x: Unknown format in format string" (Char.code c))
                      end
                    | 'x' | 'X' ->
                      let copy =
                          match to_buffer with
                          | Some dst ->
                            let dst' = Asm.BinOp (Asm.Add, dst, Asm.Const (Data.Word.of_int (Z.of_int dst_off) !Config.stack_width))  in
                            D.copy_hex d dst'
                          | _ -> D.print_hex d
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
                          | _ -> D.print_chars d
                      in
                      fmt_pos+1, digit_nb, dump arg digit_nb (Some (pad_char, pad_left))

                    (* value is in memory *)
                    | c ->  L.abort (fun p -> p "%x: Unknown format in format string" (Char.code c))
                in
                let n = ((Char.code c) - (Char.code '0')) in
                    compute n fmt_pos
            in
            let format_arg d fmt_pos dst_off arg: int * int * D.t =
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
                | c when '1' <= c && c <= '9' -> format_num d dst_off c (fmt_pos+1) arg '0' true
                | '0' -> format_num d dst_off '0' (fmt_pos+1) arg '0' true
                | ' ' -> format_num d dst_off '0' (fmt_pos+1) arg ' ' true
                | '-' -> format_num d dst_off '0' (fmt_pos+1) arg ' ' false
                | _ -> L.abort (fun p -> p "Unknown format in format string")
            in
            let rec copy_char d c (fmt_pos: int) dst_off arg_nb: int * D.t =
                let src = (Asm.Const (Data.Word.of_int (Z.of_int (Char.code c)) 8)) in
                let dump =
                    match to_buffer with
                    | Some dst ->  D.copy d (Asm.BinOp (Asm.Add, dst, Asm.Const (Data.Word.of_int (Z.of_int dst_off) !Config.address_sz)))
                    | _ -> D.print d
                in
                let d' = dump src 8 in
                    fill_buffer d' (fmt_pos+1) 0 (dst_off+1) arg_nb
            (* state machine for format string parsing *)
            and fill_buffer (d: D.t) (fmt_pos: int) (state_id: int) (dst_off: int) arg_nb: int * D.t =
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
                      let arg = Asm.Lval (Asm.M (Asm.BinOp (Asm.Add, va_args, Asm.Const (Data.Word.of_int (Z.of_int (arg_nb*off_arg)) !Config.stack_width)), !Config.stack_width)) in
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
        | Exceptions.Enum_failure | Exceptions.Concretization ->
          L.abort (fun p -> p "(s)printf: Unknown address of the format string or imprecise value of the format string")
        | Not_found ->
          L.abort (fun p -> p "address of the null terminator in the format string in (s)printf not found")



    let sprintf (d: D.t) (args: Asm.exp list): D.t * bool =
        match args with
        | [Asm.Lval ret ; dst ; format_addr ; va_args] ->
          print d ret format_addr va_args (Some dst)
        | _ -> L.abort (fun p -> p "invalid call to (s)printf stub")

    let printf d args =
        (* TODO: not optimal as buffer destination is built as for sprintf *)
        match args with
        | [Asm.Lval ret ; format_addr ; va_args] ->
          (* creating a very large temporary buffer to store the output of printf *)
          Log.open_stdout();
          let d', is_tainted = print d ret format_addr va_args None in
          L.analysis (fun p -> p "printf output:");
          Log.dump_stdout();
          L.analysis (fun p -> p "--- end of printf--");
          d', is_tainted
        | _ -> L.abort (fun p -> p "invalid call to printf stub")

    let puts d args =
      match args with
      | [Asm.Lval ret ; str] ->
	 Log.open_stdout();
	L.analysis (fun p -> p "puts output:");
	let len, d' = D.print_until d str (Asm.Const (Data.Word.of_int Z.zero 8)) 8 10000 true None in
	let d', is_tainted = D.set ret (Asm.Const (Data.Word.of_int (Z.of_int len) !Config.operand_sz)) d' in
        Log.dump_stdout();
        L.analysis (fun p -> p "--- end of puts--");
	d', is_tainted
	  
      | _ -> L.abort (fun p -> p "invalid call to puts stub")
	 
    let process d fun_name (args: Asm.exp list): D.t * bool =
        let d, is_tainted =
            try
                let apply_f =
                    match fun_name with
                    | "memcpy" -> memcpy
                    | "sprintf" -> sprintf
                    | "printf" -> printf
		    | "puts" -> puts
                    | "strlen" -> strlen
                    | _ -> raise Exit
                in
                apply_f d args
            with _ -> L.analysis (fun p -> p "no stub or uncomputable stub for %s. Skipped" fun_name); d, false
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
