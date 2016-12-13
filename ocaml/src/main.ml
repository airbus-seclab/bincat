(** Main Module contains the entry points of the library *)

(** [process cfile rfile lfile] launches on analysis run with
    - [cfile] as configuration file
    - [rfile] as result file
    - [lfile] as log file *)
let process (configfile:string) (resultfile:string) (logfile:string): unit =
  (* cleaning global data structures *)
  Config.clear_tables();
  Register.clear();
  (* generating modules needed for the analysis *)
  let module Vector 	 = Vector.Make(Reduced_value_tainting) in
  let module Pointer 	 = Pointer.Make(Vector)		       in
  let module Domain 	 = Reduced_unrel_typenv.Make(Pointer)  in
  let module Interpreter = Interpreter.Make(Domain)	       in
  (* setting the log file *)
  Log.init logfile;
  (* setting the backtrace parameters for debugging purpose *)
  Printexc.record_backtrace true;
  let print_exc exc raw_bt =
    Printf.fprintf stdout "%s" (Printexc.to_string exc);
    Printexc.print_raw_backtrace stdout raw_bt
  in
  Printexc.set_uncaught_exception_handler print_exc;
  
  (* opening the configuration file *)
  let cin =
    try open_in configfile
    with Sys_error _ -> Log.error "Failed to open the configuration file"
  in
    (* parsing the configuration file to fill configuration information *)
  let lexbuf = Lexing.from_channel cin in
  let string_of_position pos =
    Printf.sprintf "(%d, %d)" pos.Lexing.lex_curr_p.Lexing.pos_lnum (pos.Lexing.lex_curr_p.Lexing.pos_cnum - pos.Lexing.lex_curr_p.Lexing.pos_bol)
  in
  begin
    try
      lexbuf.Lexing.lex_curr_p <- { lexbuf.Lexing.lex_curr_p with Lexing.pos_fname = configfile; };
      Parser.process Lexer.token lexbuf
    with
    | Parser.Error ->
       close_in cin;
      Log.error (Printf.sprintf "Syntax error near location %s" (string_of_position lexbuf))
	
    | Failure "lexing: empty token" ->
       close_in cin;
      Log.error (Printf.sprintf "Parse error near location %s" (string_of_position lexbuf))
  end;
  close_in cin;
  
  (* defining the dump function to provide to the fixpoint engine *)
  let dump cfa = Interpreter.Cfa.print resultfile !Config.dotfile cfa in
  
    (* internal function to launch backward/forward analysis from a previous CFA and config *)
    let from_cfa fixpoint =
        let orig_cfa = Interpreter.Cfa.unmarshal !Config.in_mcfa_file in
        let ep'      = Data.Address.of_int Data.Address.Global !Config.ep !Config.address_sz in
        let d        = Interpreter.Cfa.init_abstract_value () in
        try
            let prev_s = Interpreter.Cfa.last_addr orig_cfa ep' in
            prev_s.Interpreter.Cfa.State.v <- Domain.meet prev_s.Interpreter.Cfa.State.v d;
            fixpoint orig_cfa prev_s dump
        with
        | Not_found -> Log.error "entry point of the analysis not in the given CFA"
    in

    (* launching the right analysis depending on the value of !Config.analysis *)
    let cfa =
        match !Config.analysis with

        (* forward analysis from a binary *)
        | Config.Forward Config.Bin ->
          (* 6: generate code *)
          let code = Code.make !Config.text !Config.rva_code !Config.ep		        in
          (* 7: generate the nitial cfa with only an initial state *)
          let ep' 	= Data.Address.of_int Data.Address.Global !Config.ep !Config.address_sz in
          let s  	= Interpreter.Cfa.init ep'					        in
          let g 	= Interpreter.Cfa.create ()					        in
          Interpreter.Cfa.add_vertex g s;
          let cfa =
              Interpreter.forward_bin code g s dump
          in
          (* launch an interleaving of backward/forward if an inferred property can be backward propagated *)
          (*if !Config.interleave then*)
          Interpreter.interleave_from_cfa cfa dump
        (* else
             cfa *)

        (* forward analysis from a CFA *)
        | Config.Forward Config.Cfa -> from_cfa Interpreter.forward_cfa

        (* backward analysis from a CFA *)
        | Config.Backward -> from_cfa Interpreter.backward

    in

    (* dumping results *)
    if !Config.store_mcfa = true then
        Interpreter.Cfa.marshal !Config.out_mcfa_file cfa;
    dump cfa;
    Log.close()
;;

(* enables the process function to be callable from the .so *)
Callback.register "process" process;;
