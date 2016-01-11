(* generation of all modules depending on the memory model (main type of addresses) *)
module Ptr        = Unrel.Make(Ptr)
module Taint      = Unrel.Make(Tainting)
module Domain      = Pair.Make(Ptr)(Taint)
module Interpreter = Interpreter.Make(Domain)

				    
(* string conversion of a position in the configuration file *)
let string_of_position pos =
  Printf.sprintf "%d" pos.Lexing.lex_start_pos

(* main function *)
let process ~configfile ~resultfile =
  (* 1: open the configuration file *)
  let cin    =
    try
      let cin = open_in configfile in
      seek_in cin !Config.phys_code_addr;
      cin
    with _ -> failwith "Opening configuration file failed"
  in
  
  (* 2: parse the configuration file to fill configuration information *)
  let lexbuf = Lexing.from_channel cin in
  begin
    try
      lexbuf.Lexing.lex_curr_p <- { lexbuf.Lexing.lex_curr_p with Lexing.pos_fname = configfile; };
    Parser.process Lexer.token lexbuf
    with
    | Parser.Error ->
       Printf.eprintf "Syntax error at %s\n" (string_of_position lexbuf);
       raise Parser.Error
    | Failure "lexing: empty token" as e ->
       Printf.eprintf "Parse error at %s\n" (string_of_position lexbuf);
       raise e
  end;
  close_in cin;
  
  (* 3: generate code *)
  let code  = Code.make !Config.text !Config.ep                                                      in
  
  (* 4: generate the initial cfa with only an initial state *)
  let ep'   = Data.Address.add_offset (Data.Address.of_int !Config.cs !Config.address_sz) !Config.ep in
  let g, s  = Interpreter.Cfa.init ep'                                                               in
  
  (* 5: runs the fixpoint engine *)
  let cfa  = Interpreter.process code g s                                                            in
  
  (* 6: dumps the results *)
  Interpreter.Cfa.print cfa resultfile
 ;; 
  
(* enables the process function to be callable from the .so *)
Callback.register "process" process;;


