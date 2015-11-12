%{
   
    let missing_item item section =
      (* error message printing *)
      Printf.eprintf "missing %s in section %s\n" item section;
      exit (-1);;

    (* physical address (offset in the binary file) of the code *)
    let phys_textsection_start = ref 0
				     
    (* current library name *)
    let libname = ref "";;
		      
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
	(PHYS_CODE, "phys-code", "binary");
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
	let fid  = open_in_bin !filename					                                                in
	let o 	 = !phys_textsection_start			                                                                in
	let len  = Int64.to_int (Int64.sub (Int64.of_string !Context.code_addr_end) (Int64.of_string !Context.code_addr_start)) in
	Context.text := String.make len '\x00';
	let len' = Int64.of_int (input fid !Context.text o len)                                                                 in
	if Int64.compare len' (Int64.of_int len) <> 0 then failwith "code extraction has failed";
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
%token FORMAT PE ELF PHYS_CODE RVA_ENTRYPOINT FILEPATH MASK
%token LANGLE_BRACKET RANGLE_BRACKET LPAREN RPAREN COMMA SETTINGS UNDERSCORE LOADER
%token <string> STRING
%token <string> INT
%start <unit> process
%%
(* in every below rule a later rule in the file order may inhibit a previous rule *) 
  process:
      | s=sections EOF { s; check_context () }
	
      
    sections:
    | s=section 	       { s }
    | ss=sections s=section    { ss; s }
    
      section:
    | LEFT_SQ_BRACKET SETTINGS RIGHT_SQ_BRACKET s=settings  { s }
    | LEFT_SQ_BRACKET LOADER RIGHT_SQ_BRACKET 	l=loader    { l }
    | LEFT_SQ_BRACKET BINARY RIGHT_SQ_BRACKET 	b=binary    { b }
    | LEFT_SQ_BRACKET STATE RIGHT_SQ_BRACKET  st=state      { st }
    | LEFT_SQ_BRACKET ANALYZER RIGHT_SQ_BRACKET a=analyzer  { a }
    | LEFT_SQ_BRACKET l=libname RIGHT_SQ_BRACKET lib=library { l; lib }

      libname:
    | l=STRING { libname := l; Hashtbl.add libraries l (None, []) }
    

      settings:
    | s=setting_item 		 { s }
    | s=setting_item ss=settings { s; ss }
    
      setting_item:
    | MEM_MODEL EQUAL m=memmodel { update_mandatory MEM_MODEL; Context.memory_model := m}
    | CALL_CONV EQUAL c=callconv { update_mandatory CALL_CONV; Context.call_conv := c }
    | OP_SZ EQUAL i=INT          { update_mandatory OP_SZ; try Context.operand_sz := int_of_string i with _ -> Printf.eprintf "illegal operand size"; exit (-1) }
    | MEM_SZ EQUAL i=INT         { update_mandatory MEM_SZ; try Context.address_sz := int_of_string i with _ -> Printf.eprintf "illegal address size"; exit (-1) }
    | STACK_WIDTH EQUAL i=INT    { update_mandatory STACK_WIDTH; try Context.stack_width := int_of_string i with _ -> Printf.eprintf "illegal stack width"; exit (-1) }
    

      memmodel:
    | FLAT 	{ Context.Flat }
    | SEGMENTED { Context.Segmented }
    
      
      callconv:
    | CDECL    { Context.Cdecl } 
    | FASTCALL { Context.Fastcall }
    | STDCALL  { Context.Stdcall }
    

      loader:
    | l=loader_item 	      { l }
    | l=loader_item ll=loader { l; ll }

      loader_item:
    | RVA_CODE EQUAL i=INT       { update_mandatory RVA_CODE; Context.code_addr_start := i }
    | RVA_CODE_END EQUAL i=INT   { update_mandatory RVA_CODE_END; Context.code_addr_end := i }
    | RVA_DATA EQUAL i=INT       { update_mandatory RVA_DATA; Context.data_addr := i }
    | RVA_STACK EQUAL i=INT      { update_mandatory RVA_STACK; Context.stack_addr := i }
    | RVA_ENTRYPOINT EQUAL i=INT { update_mandatory RVA_ENTRYPOINT; Context.ep := i }
    
      
      binary:
    | b=binary_item 	      { b }
    | b=binary_item bb=binary { b; bb }
	
      binary_item:
    | FILEPATH EQUAL f=STRING 	{ update_mandatory FILEPATH; filename := f }
    | FORMAT EQUAL f=format 	{ update_mandatory FORMAT; Context.format := f }
    | PHYS_CODE EQUAL i=INT 	{ update_mandatory PHYS_CODE; phys_textsection_start := int_of_string i }
					
      format:
    | PE  { Context.Pe }
    | ELF { Context.Elf }
    

      analyzer:
    | a=analyzer_item 		  { a }
    | a=analyzer_item aa=analyzer { a; aa }
				    
      analyzer_item:
    | UNROLL EQUAL i=INT { Context.unroll := int_of_string i }
    
    
      state:
    | s=state_item 	    { s }
    | s=state_item ss=state { s; ss }

      state_item:
    | REG LEFT_SQ_BRACKET r=STRING RIGHT_SQ_BRACKET EQUAL v=init { Context.init_register r (fst v) (snd v) }
    | MEM LEFT_SQ_BRACKET m=INT RIGHT_SQ_BRACKET EQUAL v=init 	 { Context.init_memory m (fst v) (snd v) }
    		      
      library:
    | l=library_item 		{ l }
    | l=library_item ll=library { l; ll }

      library_item:
    | CALL_CONV EQUAL c=callconv  { let funs = snd (Hashtbl.find libraries !libname) in Hashtbl.replace libraries !libname (Some c, funs)  }
    | v=fun_rule 		  { let f, c, a = v in let cl, funs = Hashtbl.find libraries !libname in Hashtbl.replace libraries !libname (cl, (f, c, None, List.rev a)::funs) }
    | r=argument EQUAL v=fun_rule { let f, c, a = v in let cl, funs = Hashtbl.find libraries !libname in Hashtbl.replace libraries !libname (cl, (f, c, Some r, List.rev a)::funs) }
  			     
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
    | TAINT c=content 		  { None, Some c }
    | c=content 		  { Some c, None }
    | c1=content TAINT c2=content { Some c1, Some c2 }

     content:
    | t=INT 		{ Context.make_value t }
    | t=INT MASK t2=INT { Context.make_value_from_mask t t2 }
			
