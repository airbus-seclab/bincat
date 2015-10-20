%{
   
    let illegal_item pos item section =
      (* error message printing *)
      Printf.eprintf "location %d: illegal %s in section %s" pos item section;
      exit (-1);;

    let missing_item item section =
      (* error message printing *)
      Printf.eprintf "missing %s in section %s" item section;
      exit (-1);;

    (* physical address (offset in the binary file) of the code *)
    let phys_textsection_start = ref 0
				     
    (* current section name *)
    let section_name = ref "";;
		      
    (* temporary table to store tainting rules on functions of a given library *)
    let libraries = Hashtbl.create 7;;

    (* name of binary file to analyze *)
    let filename = ref ""
		       
    (* temporay table used to check that all mandatory elements are filled in the configuration file *)
    let mandatory_keys = Hashtbl.create 20;;
    let mandatory_items = [
	(MEM_MODEL, "mem-model", "settings");
	(CALL_CONV, "call-conv", "settings");
	(MEM_SZ, "mem-sz", "settings");
	(OP_SZ, "op-sz", "settings");
	(STACK_WIDTH, "stack-width", "settings");
	(RVA_STACK, "rva-stack", "loader");
	(RVA_DATA, "rva-data", "loader");
	(RVA_CODE, "rva-code", "loader");
	(RVA_CODE_END, "rva-code-end", "loader");
	(RVA_ENTRYPOINT, "rva-entrypoint", "loader");
	(FORMAT, "format", "binary");
	(PHYS_TEXTSECTION, "phys-textsection", "binary");
	(FILEPATH, "filepath", "binary");
      ];;	
      List.iter (fun (k, kname, sname) -> Hashtbl.add mandatory_keys k (kname, sname, false)) mandatory_items;;

      let update_mandatory key =
	let kname, sname, _ = Hashtbl.find mandatory_keys key in
	Hashtbl.replace mandatory_keys key (kname, sname, true);;
	
      (** footer function *)
      let check_context () =
	(* check whether all mandatory items are provided *)
	Hashtbl.iter (fun _ (pname, sname, b) -> if not b then missing_item pname sname) mandatory_keys;
	(* open the binary to pick up the text section *)
	let fid  = open_in !filename					                                           in
	let o 	 = !phys_textsection_start			                                                   in
	let len  = Int64.sub (Int64.of_string !Context.code_addr_start) (Int64.of_string !Context.code_addr_start) in
	let len' = Int64.of_int (input fid !Context.text o (Int64.to_int len))                                     in
	if Int64.compare len' len <> 0 then failwith "Text section extraction has failed";
	(* fill the table of tainting rules for each provided library *)
	let add_tainting_rules l (c, funs) =
	  let c' =
	    match c with
	      None    -> !Context.call_conv
	    | Some c' -> c'
	  in
	  let add (fname, c, r, args) =
	    let c' =
	      match c with
		None 	-> c'
	      | Some c' -> c'
	    in
	    Context.add_tainting_rules l (fname, c', r, args)
	  in
	  List.iter add (List.rev funs)
	in
	Hashtbl.iter add_tainting_rules libraries;;
	
	%}
%token EOF LEFT_SQ_BRACKET RIGHT_SQ_BRACKET EQUAL REG MEM STAR AT TAINT
%token CALL_CONV CDECL FASTCALL STDCALL MEM_MODEL MEM_SZ OP_SZ STACK_WIDTH
%token ANALYZER UNROLL RVA_DATA RVA_CODE RVA_CODE_END RVA_STACK FLAT SEGMENTED BINARY STATE
%token FORMAT PE ELF PHYS_TEXTSECTION RVA_ENTRYPOINT FILEPATH
%token LANGLE_BRACKET RANGLE_BRACKET LPAREN RPAREN COMMA SETTINGS UNDERSCORE LOADER
%token <string> STRING
%token <string> INT
%start <unit> process
%%
(* in every below rule a later rule in the file ordre may inhibit a previous rule *) 
  process:
      | s=sections EOF { s; check_context () }
	
      
    sections:
    | s=section 	       { s }
    | ss=sections s=section    { ss; s }
    
      section:
    | LEFT_SQ_BRACKET SETTINGS RIGHT_SQ_BRACKET s=settings  { section_name := "settings"; s }
    | LEFT_SQ_BRACKET LOADER RIGHT_SQ_BRACKET 	l=loader    { section_name := "loader"; l }
    | LEFT_SQ_BRACKET BINARY RIGHT_SQ_BRACKET 	b=binary    { section_name := "binary"; b }
    | LEFT_SQ_BRACKET STATE RIGHT_SQ_BRACKET  st=state      { section_name := "state"; st }
    | LEFT_SQ_BRACKET ANALYZER RIGHT_SQ_BRACKET a=analyzer  { section_name := "analyzer"; a }
    | LEFT_SQ_BRACKET l=STRING RIGHT_SQ_BRACKET lib=library { section_name := l; Hashtbl.add libraries l (None, []) ; lib }
    

      settings:
    | MEM_MODEL EQUAL m=memmodel { update_mandatory MEM_MODEL; Context.memory_model := m }
    | CALL_CONV EQUAL c=callconv { update_mandatory CALL_CONV; Context.call_conv := c }
    | OP_SZ EQUAL i=INT          { update_mandatory OP_SZ; Context.operand_sz := int_of_string i }
    | MEM_SZ EQUAL i=INT         { update_mandatory MEM_SZ; Context.address_sz := int_of_string i }
    | STACK_WIDTH EQUAL i=INT    { update_mandatory STACK_WIDTH; Context.stack_width := int_of_string i }
    |                            { illegal_item $startpos.Lexing.pos_lnum "key" "settings" }
    

      memmodel:
    | FLAT 	{ Context.Flat }
    | SEGMENTED { Context.Segmented }
    |   	{ illegal_item $startpos.Lexing.pos_lnum "memory model" !section_name }
    
      
      callconv:
    | CDECL    { Context.Cdecl } 
    | FASTCALL { Context.Fastcall }
    | STDCALL  { Context.Stdcall }
    |          { illegal_item $startpos.Lexing.pos_lnum "calling convention" !section_name }
    

      loader:
    | RVA_CODE EQUAL i=INT       { update_mandatory RVA_CODE; Context.code_addr_start := i }
    | RVA_CODE_END EQUAL i=INT   { update_mandatory RVA_CODE_END; Context.code_addr_end := i }
    | RVA_DATA EQUAL i=INT       { update_mandatory RVA_DATA; Context.data_addr := i }
    | RVA_STACK EQUAL i=INT      { update_mandatory RVA_STACK; Context.stack_addr := i }
    | RVA_ENTRYPOINT EQUAL i=INT { update_mandatory RVA_ENTRYPOINT; Context.ep := i }
    |   		         { illegal_item $startpos.Lexing.pos_lnum "key" "loader" }
    
      
      binary:
    | FILEPATH EQUAL f=STRING 	        { update_mandatory FILEPATH; filename := f }
    | FORMAT EQUAL f=format 		{ update_mandatory FORMAT; Context.format := f }
    | PHYS_TEXTSECTION EQUAL i=INT 	{ update_mandatory PHYS_TEXTSECTION; phys_textsection_start := int_of_string i }
    |   				{ illegal_item $startpos.Lexing.pos_lnum "key" "binary" }
					
      format:
    | PE  { Context.Pe }
    | ELF { Context.Elf }
    |     { illegal_item $startpos.Lexing.pos_lnum "file format" "binary" }
    

      analyzer:
    | UNROLL EQUAL i=INT { Context.unroll := int_of_string i }
    |   		 { illegal_item $startpos.Lexing.pos_lnum "item" "analyzer" }
    
    
      state:
    | REG LEFT_SQ_BRACKET r=STRING RIGHT_SQ_BRACKET EQUAL v=init { Context.init_register r (fst v) (snd v) }
    | MEM LEFT_SQ_BRACKET m=INT RIGHT_SQ_BRACKET EQUAL v=init 	 { Context.init_memory m (fst v) (snd v) }
    		      
      library:
    | CALL_CONV EQUAL c=callconv  { let _c', funs = Hashtbl.find libraries !section_name in Hashtbl.replace libraries !section_name (Some c, funs)  }
    | v=fun_rule 		  { let f, c, a = v in let cl, funs = Hashtbl.find libraries !section_name in Hashtbl.replace libraries !section_name (cl, (f, c, None, List.rev a)::funs) }
    | r=argument EQUAL v=fun_rule { let f, c, a = v in let cl, funs = Hashtbl.find libraries !section_name in Hashtbl.replace libraries !section_name (cl, (f, c, Some r, List.rev a)::funs) }
  			     
      fun_rule:
    | f=STRING LANGLE_BRACKET c=callconv RANGLE_BRACKET a=arguments { f, Some c, a }
    | f=STRING 	a=arguments 			     		    { f, None, a }
				   
      arguments:
    | arg_list = delimited(LPAREN, separated_list(COMMA, argument), RPAREN) { arg_list }

     argument:
    | UNDERSCORE { Context.No_taint }
    | AT 	 { Context.Addr_taint }
    | STAR 	 { Context.Buf_taint }
	   
     init:
    | TAINT t=INT 	{ None, Some t }
    | i=INT 		{ Some i, None }
    | i=INT TAINT t=INT { Some i, Some t }
