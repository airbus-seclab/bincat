module Make(Abi: Data.T) =
  struct
    (* generation of all modules depending on memory model (main type of addresses) *)
    module Asm 	       = Asm.Make(Abi)
    module Ptr 	       = (Ptr.Make(Asm): Unrel.T with module Asm = Asm)
    module UPtr        = (Unrel.Make(Asm)(Ptr): Domain.T with module Asm = Ptr.Asm)
    module Taint       = (Tainting.Make(Asm): Unrel.T with module Asm = Ptr.Asm)
    module UTaint      = (Unrel.Make(Asm)(Taint): Domain.T with module Asm = UPtr.Asm)
    module Domain      = Pair.Make(UPtr)(UTaint)
    module Address     = Domain.Asm.Address
    module Interpreter = Interpreter.Make(Domain)
    module Cfa 	       = Interpreter.Cfa
    module Code        = Interpreter.Code
			
    let process text text_addr e resultfile =
      Printf.printf 
      (* code generation *)
      let code   = Interpreter.Code.make text text_addr e !Config.address_sz in
      (* intial cfa with only an initial state *)
      let g, s   = Interpreter.Cfa.init e in
      (* running the fixpoint engine *)
      let cfa 	 = Interpreter.process code g s	in
      (* dumping results *)
      Cfa.print cfa resultfile
  end
    
module Flat 	  = Make(Abi.Flat)
module Segmented  = Make(Abi.Segmented)
			
(* string conversion of a position in the configuration file *)
let string_of_position pos =
  Printf.sprintf "%d" pos.Lexing.lex_start_pos
		 
let process ~configfile ~resultfile =
  (* 1: open the configuration file *)
  let cin    =
    try open_in configfile
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
  (* 3: launch the fixpoint corresponding to the memory model provided by the configuration file *)
  match !Config.memory_model with
  | Config.Flat      -> Flat.process !Config.text !Config.code_addr_start !Config.ep resultfile
  | Config.Segmented -> Segmented.process !Config.text !Config.code_addr_start !Config.ep resultfile;;
  
(* enables the process function to be callable from the .so *)
Callback.register "process" process;;


