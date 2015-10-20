module Make(Abi: Data.T) =
  struct
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
      let code   = Fixpoint.Code.make text text_addr e !Context.address_sz in
      let g, s   = Fixpoint.Cfa.make e in
      let segments = {
	  Fixpoint.cs = Address.of_string (!Context.cs^":\x00") !Context.address_sz;
	  Fixpoint.ds = Address.of_string (!Context.ds^":\x00") !Context.address_sz;
	  Fixpoint.ss = Address.of_string (!Context.ss^":\x00") !Context.address_sz;
	  Fixpoint.es = Address.of_string (!Context.es^":\x00") !Context.address_sz;
	  Fixpoint.fs = Address.of_string (!Context.fs^":\x00") !Context.address_sz;
	  Fixpoint.gs = Address.of_string (!Context.gs^":\x00") !Context.address_sz;
	}
      in	
      let cfa = Fixpoint.process code g s segments in
      Cfa.print cfa resultfile
  end

module Flat 	  = Make(Abi.Flat)
module Segmented  = Make(Abi.Segmented)

let process ~configfile ~resultfile =
  let cin    =
    try open_in configfile
    with _ -> failwith "Opening configuration file failed"
  in
  let lexbuf = Lexing.from_channel cin in
  Parser.process Lexer.token lexbuf;
  close_in cin;
  match !Context.memory_model with
  | Context.Flat      -> Flat.process !Context.text !Context.code_addr_start !Context.ep resultfile
  | Context.Segmented -> Segmented.process !Context.text !Context.code_addr_start !Context.ep resultfile;;

Callback.register "process" process;;


