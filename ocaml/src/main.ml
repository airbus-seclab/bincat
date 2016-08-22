

(* string conversion of a position in the configuration file *)
let string_of_position pos =
  Printf.sprintf "%d" pos.Lexing.lex_curr_p.Lexing.pos_lnum

let print_exc exc raw_bt =
    Printf.fprintf stdout "%s" (Printexc.to_string exc);
    Printexc.print_raw_backtrace stdout raw_bt

(* main function *)
let process ~configfile ~resultfile ~logfile =
   (* 0 cleaning global data structures *)
  Config.clear_tables();
  Register.clear();
  (* generation of all modules depending on the memory model (main type of addresses) *)
  let module Vector      = Vector.Make(Reduced_value_tainting) in
  let module Pointer     = Pointer.Make(Vector) in
  let module Domain      = Unrel.Make(Pointer) in
  let module Interpreter = Interpreter.Make(Domain) in

  (*1 set the log file *)
  Log.init logfile;
  Printexc.record_backtrace true;
  Printexc.set_uncaught_exception_handler print_exc;
  (* 2: open the configuration file *)
  let cin =
    try open_in configfile
    with Sys_error _ -> Log.error "Failed to open the configuration file"
  in
  (* 3: parse the configuration file to fill configuration information *)
  let lexbuf = Lexing.from_channel cin in
  begin
    try
      lexbuf.Lexing.lex_curr_p <- { lexbuf.Lexing.lex_curr_p with Lexing.pos_fname = configfile; };
      Parser.process Lexer.token lexbuf
    with
    | Parser.Error -> close_in cin; Log.error (Printf.sprintf "Syntax error near location %s\n" (string_of_position lexbuf))

    | Failure "lexing: empty token" -> close_in cin; Log.error (Printf.sprintf "Parse error near location %s\n" (string_of_position lexbuf))
  end;
  close_in cin;

  (* 6: runs the fixpoint engine *)

  let dump cfa = Interpreter.Cfa.print resultfile !Config.dotfile cfa               in
  let cfa = match !Config.analysis with
   | Config.Forward Config.Bin ->
       (* 4: generate code *)
       let code  = Code.make !Config.text !Config.rva_code !Config.ep                    in
       (* 5: generate the initial cfa with only an initial state *)
       let ep' = Data.Address.of_int Data.Address.Global !Config.ep !Config.address_sz in
       let s  = Interpreter.Cfa.init ep' in
	let g = Interpreter.Cfa.create () in
	Interpreter.Cfa.add_vertex g s;
	Interpreter.forward_bin code g s dump
				
   | Config.Forward Config.Cfa ->
       let orig_cfa = Interpreter.Cfa.unmarshal !Config.mcfa_file in
       let find_initstate id = id (** XXX actually search state *)
       in
       let init_state = find_initstate 0 in
       Interpreter.forward_cfa orig_cfa init_state
			       
  | Config.Backward -> 
       let orig_cfa = Interpreter.Cfa.unmarshal !Config.mcfa_file in
       (* XXX find state having requested address orig_cfa & final=true *)
       let ep' = Data.Address.of_int Data.Address.Global !Config.ep !Config.address_sz in
       let d = Interpreter.Cfa.init_abstract_value () in
       try
	 let prev_s = Interpreter.Cfa.last_addr orig_cfa ep' in
	 prev_s.Interpreter.Cfa.State.v <- Domain.meet prev_s.Interpreter.Cfa.State.v d;
	 Interpreter.backward orig_cfa prev_s dump
       with Not_found -> Log.error "entry point of the backward analysis not in the given CFA"
  in

  (* 7: dumps the results *)
  if !Config.store_mcfa = true then
    Interpreter.Cfa.marshal !Config.mcfa_file cfa;
  dump cfa;
  Printexc.print_backtrace stdout;
  Log.close()
 ;;

(* enables the process function to be callable from the .so *)
   Callback.register "process" process;;


