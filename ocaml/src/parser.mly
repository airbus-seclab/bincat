%{
   
    let missing_item item section =
      (* error message printing *)
      Log.error (Printf.sprintf "missing %s in section %s\n" item section);;
       
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
	(MODE, "mode", "settings");
	(CALL_CONV, "call-conv", "settings");
	(MEM_SZ, "mem-sz", "settings");
	(OP_SZ, "op-sz", "settings");
	(STACK_WIDTH, "stack-width", "settings");
	(SS, "ss", "loader");
	(DS, "ds", "loader");
	(CS, "cs", "loader");
	(ES, "es", "loader");
	(FS, "fs", "loader");
	(GS, "gs", "loader");
	(ENTRYPOINT, "entrypoint", "loader");
	(CODE_LENGTH, "code-length", "loader");
	(FORMAT, "format", "binary");
	(FILEPATH, "filepath", "binary");
	(PHYS_CODE_ADDR, "phys-code-addr", "loader");
	(DOTFILE, "dotfile", "analyzer");
	(GDT, "gdt", "gdt");
      ];;	
      List.iter (fun (k, kname, sname) -> Hashtbl.add mandatory_keys k (kname, sname, false)) mandatory_items;;

      (** fills the table of initial values for the given register *)
      let init_register r (c, t) =
	let r' = Register.of_name r in
	begin
	  match c with
	  None    -> ()
	| Some c' -> Hashtbl.add Config.initial_register_content r' c'
	end;
	match t with
	  None    -> ()
	| Some t' -> Hashtbl.add Config.initial_register_tainting r' t'


      (** fills the table of initial values for the given memory address *)
      let init_memory a ((c: Config.cvalue option), t) =
	begin
	  match c with
	  None    -> ()
	| Some c' -> Hashtbl.add Config.initial_memory_content a c'
	end;
	match t with
	  None    -> ()
	| Some t' -> Hashtbl.add Config.initial_memory_tainting a t'
				 
      let update_mandatory key =
	let kname, sname, _ = Hashtbl.find mandatory_keys key in
	Hashtbl.replace mandatory_keys key (kname, sname, true);;
	
      (** footer function *)
      let check_context () =
	(* check whether all mandatory items are provided *)
	Hashtbl.iter (fun _ (pname, sname, b) -> if not b then missing_item pname sname) mandatory_keys;
	(* open the binary to pick up the text section *)
	let fid  = open_in_bin !filename in
	Config.text := String.make !Config.code_length '\x00';
	let len = input fid !Config.text 0 !Config.code_length in
	if len <> !Config.code_length then failwith "code extraction has failed";
	(* fill the table of tainting rules for each provided library *)
	let add_tainting_rules l (c, funs) =
	  let c' =
	    match c with
	      None    -> !Config.call_conv
	    | Some c' -> c'
	  in
	  let add (fname, c, r, args) =
	    let c' =
	      match c with
		None 	-> c'
	      | Some c' -> c'
	    in
	    Config.add_tainting_rules l (fname, c', r, args)
	  in
	  List.iter add (List.rev funs)
	in
	Hashtbl.iter add_tainting_rules libraries
	;;
	
	%}
%token EOF LEFT_SQ_BRACKET RIGHT_SQ_BRACKET EQUAL REG MEM STAR AT TAINT
%token CALL_CONV CDECL FASTCALL STDCALL MEM_MODEL MEM_SZ OP_SZ STACK_WIDTH
%token ANALYZER UNROLL DS CS SS ES FS GS FLAT SEGMENTED BINARY STATE CODE_LENGTH
%token FORMAT PE ELF ENTRYPOINT FILEPATH MASK MODE REAL PROTECTED PHYS_CODE_ADDR
%token LANGLE_BRACKET RANGLE_BRACKET LPAREN RPAREN COMMA SETTINGS UNDERSCORE LOADER DOTFILE
%token GDT 
%token <string> STRING
%token <Z.t> INT
%start <unit> process
%%
(* in every below rule a later rule in the file order may inhibit a previous rule *) 
  process:
      | s=sections EOF { s; check_context () }
	
      
    sections:
    | s=section 	       { s }
    | ss=sections s=section    { ss; s }
    
      section:
    | LEFT_SQ_BRACKET SETTINGS RIGHT_SQ_BRACKET s=settings   { s }
    | LEFT_SQ_BRACKET LOADER RIGHT_SQ_BRACKET 	l=loader     { l }
    | LEFT_SQ_BRACKET BINARY RIGHT_SQ_BRACKET 	b=binary     { b }
    | LEFT_SQ_BRACKET STATE RIGHT_SQ_BRACKET  st=state       { st }
    | LEFT_SQ_BRACKET ANALYZER RIGHT_SQ_BRACKET a=analyzer   { a }
    | LEFT_SQ_BRACKET GDT RIGHT_SQ_BRACKET gdt=gdt 	     { gdt }
    | LEFT_SQ_BRACKET l=libname RIGHT_SQ_BRACKET lib=library { l; lib }

      libname:
    | l=STRING { libname := l; Hashtbl.add libraries l (None, []) }
    

      settings:
    | s=setting_item 		 { s }
    | s=setting_item ss=settings { s; ss }
    
      setting_item:
    | MEM_MODEL EQUAL m=memmodel { update_mandatory MEM_MODEL; Config.memory_model := m }
    | CALL_CONV EQUAL c=callconv { update_mandatory CALL_CONV; Config.call_conv := c }
    | OP_SZ EQUAL i=INT          { update_mandatory OP_SZ; try Config.operand_sz := Z.to_int i with _ -> Log.error "illegal operand size" }
    | MEM_SZ EQUAL i=INT         { update_mandatory MEM_SZ; try Config.address_sz := Z.to_int i with _ -> Log.error "illegal address size" }
    | STACK_WIDTH EQUAL i=INT    { update_mandatory STACK_WIDTH; try Config.stack_width := Z.to_int i with _ -> Log.error "illegal stack width" }
    | MODE EQUAL m=mmode         { update_mandatory MODE ; Config.mode := m }
				 	
      memmodel:
    | FLAT 	{ Config.Flat }
    | SEGMENTED { Config.Segmented }

      callconv:
    | CDECL    { Config.Cdecl } 
    | FASTCALL { Config.Fastcall }
    | STDCALL  { Config.Stdcall }
    

      mmode:
    | PROTECTED { Config.Protected }
    | REAL 	{ Config.Real }

	
      loader:
    | l=loader_item 	      { l }
    | l=loader_item ll=loader { l; ll }

      loader_item:
    | CS EQUAL i=INT          	 { update_mandatory CS; Config.cs := i }
    | DS EQUAL i=INT          	 { update_mandatory DS; Config.ds := i }
    | SS EQUAL i=INT          	 { update_mandatory SS; Config.ss := i }
    | ES EQUAL i=INT 	      	 { update_mandatory ES; Config.es := i }
    | FS EQUAL i=INT 	      	 { update_mandatory FS; Config.fs := i }
    | GS EQUAL i=INT 	      	 { update_mandatory GS; Config.gs := i }
    | CODE_LENGTH EQUAL i=INT 	 { update_mandatory CODE_LENGTH; Config.code_length := Z.to_int i }
    | ENTRYPOINT EQUAL i=INT  	 { update_mandatory ENTRYPOINT; Config.ep := i }
    | PHYS_CODE_ADDR EQUAL i=INT { update_mandatory PHYS_CODE_ADDR; Config.phys_code_addr := Z.to_int i }
    
      
      binary:
    | b=binary_item 	      { b }
    | b=binary_item bb=binary { b; bb }
	
      binary_item:
    | FILEPATH EQUAL f=STRING 	{ update_mandatory FILEPATH; filename := f }
    | FORMAT EQUAL f=format 	{ update_mandatory FORMAT; Config.format := f }


		
      format:
    | PE  { Config.Pe }
    | ELF { Config.Elf }
    
      gdt:
    | g=gdt_item 	{ g }
    | g=gdt_item gg=gdt { g; gg }

      gdt_item:
    | GDT LEFT_SQ_BRACKET i=INT RIGHT_SQ_BRACKET EQUAL v=INT { update_mandatory GDT; Hashtbl.replace Config.gdt i v }
		       
      
      analyzer:
    | a=analyzer_item 		  { a }
    | a=analyzer_item aa=analyzer { a; aa }
				    
      analyzer_item:
    | UNROLL EQUAL i=INT { Config.unroll := Z.to_int i }
    | DOTFILE EQUAL f=STRING { update_mandatory DOTFILE; Config.dotfile := f }
    
      state:
    | s=state_item 	    { s }
    | s=state_item ss=state { s; ss }

      state_item:
    | REG LEFT_SQ_BRACKET r=STRING RIGHT_SQ_BRACKET EQUAL v=init { init_register r v }
    | MEM LEFT_SQ_BRACKET m=INT RIGHT_SQ_BRACKET EQUAL v=init 	 { init_memory m v }
    		      
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
    | UNDERSCORE { Config.No_taint }
    | AT 	 { Config.Addr_taint }
    | STAR 	 { Config.Buf_taint }
	   
     init:
    | TAINT c=tcontent 	       { None, Some c }
    | c=INT 		       { Some c, None }
    | c1=INT TAINT c2=tcontent { Some c1, Some c2 }

     tcontent:
    | t=INT 		{ Config.Bits (Bits.z_to_bit_string t)  }
    | t=INT MASK t2=INT { Config.MBits (Bits.z_to_bit_string t, Bits.z_to_bit_string t2) }
			
