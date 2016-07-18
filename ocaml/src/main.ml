
				    
(* string conversion of a position in the configuration file *)
let string_of_position pos =
  Printf.sprintf "%d" pos.Lexing.lex_curr_p.Lexing.pos_lnum

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
  (* 4: generate code *)
  let code  = Code.make !Config.text !Config.rva_code !Config.ep                    in
  (* 5: generate the initial cfa with only an initial state *)
  let ep'   = Data.Address.of_int Data.Address.Global !Config.ep !Config.address_sz in
  let g, s  = Interpreter.Cfa.init ep'                                              in
  (* 6: runs the fixpoint engine *)
  let dump cfa = Interpreter.Cfa.print resultfile !Config.dotfile cfa               in
  let cfa  = Interpreter.process code g s dump                                      in
  (* 7: dumps the results *)
  dump cfa;
  Log.close()
 ;; 
  
(* enables the process function to be callable from the .so *)
   Callback.register "process" process;;


