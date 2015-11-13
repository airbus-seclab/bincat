module Make(Abi: Data.T) =
  struct
    (* generation of all modules depending on memory model (main type of addresses) *)
    module Asm 	    = Asm.Make(Abi)
    module Ptr 	    = Ptr.Make(Asm)
    module UPtr     = (Unrel.Make(Ptr): Domain.T with module Asm = Asm)
    module Taint    = Tainting.Make(Asm)
    module UTaint   = (Unrel.Make(Taint): Domain.T with module Asm = Asm)
    module Offset   = Asm.Offset
    module Domain   = Pair.Make(UPtr)(UTaint)
    module Address  = Domain.Asm.Address
    module Fixpoint = Fixpoint.Make(Domain)
    module Cfa 	    = Fixpoint.Cfa
    module Code     = Fixpoint.Code
			
    let process text text_addr e resultfile =
      (* code generation *)
      let code   = Fixpoint.Code.make text text_addr e !Config.address_sz in
      (* intial cfa with only an initial state *)
      let g, s   = Fixpoint.Cfa.make e					  in
      (* running the fixpoint engine *)
      let cfa 	 = Fixpoint.process code g s				  in
      (* dumping results *)
      Cfa.print cfa resultfile
  end
    
module Flat 	  = Make(Abi.Flat)
module Segmented  = Make(Abi.Segmented)
			
			
let process ~configfile ~resultfile =
  (* open the configuration file *)
  let cin    =
    try open_in configfile
    with _ -> failwith "Opening configuration file failed"
  in
  
  (* parse the configuration file to fill configuration information *)
  let lexbuf = Lexing.from_channel cin in
  Parser.process Lexer.token lexbuf;
  close_in cin;
  
  (* launch the fixpoint corresponding to the memory model provided by the configuration file *)
  match !Config.memory_model with
  | Config.Flat      -> Flat.process !Config.text !Config.code_addr_start !Config.ep resultfile
  | Config.Segmented -> Segmented.process !Config.text !Config.code_addr_start !Config.ep resultfile;;
  
(* enables the process function to be callable from the .so *)
Callback.register "process" process;;


