%{

    let missing_item item section =
      (* error message printing *)
      Log.error (Printf.sprintf "missing %s in section %s\n" item section);;

    (* current library name *)
    let libname = ref "";;

    (* temporary table to store tainting rules on functions of a given library *)
    let libraries: (string, Config.call_conv_t option * ((string * Config.call_conv_t option * Config.taint_t option * Config.taint_t list) list)) Hashtbl.t = Hashtbl.create 7;;

    (* name of the npk file containing function headers *)
    let npk_header = ref ""

    
    (* temporary table used to check that all mandatory elements are filled in the configuration file *)
    let mandatory_keys = Hashtbl.create 20;;

    let mandatory_items = [
	(MEM_MODEL, "mem_model", "settings");
	(MODE, "mode", "settings");
	(CALL_CONV, "call_conv", "settings");
	(MEM_SZ, "mem_sz", "settings");
	(OP_SZ, "op_sz", "settings");
	(STACK_WIDTH, "stack_width", "settings");
	(SS, "ss", "loader");
	(DS, "ds", "loader");
	(CS, "cs", "loader");
	(ES, "es", "loader");
	(FS, "fs", "loader");
	(GS, "gs", "loader");
	(ENTRYPOINT, "analyser_ep", "loader");
	(CODE_LENGTH, "code_length", "loader");
	(FORMAT, "format", "binary");
	(FILEPATH, "filepath", "binary");
	(CODE_PHYS_ADDR, "code_phys", "loader");
	(DOTFILE, "dotfile", "analyzer");
	(ANALYSIS, "analysis", "analyzer");
	(STORE_MCFA, "store_marshalled_cfa", "analyzer");
	(IN_MCFA_FILE, "in_marshalled_cfa_file", "analyzer");
	(OUT_MCFA_FILE, "out_marshalled_cfa_file", "analyzer");
	(GDT, "gdt", "gdt");
	(CODE_VA, "code_va", "loader");
      ];;
      List.iter (fun (k, kname, sname) -> Hashtbl.add mandatory_keys k (kname, sname, false)) mandatory_items;;

      (** set the corresponding option reference (ex. Config.verbose) *)
      let update_boolean optname opt v =
	match String.uppercase v with
	| "TRUE"  -> opt := true
	| "FALSE" -> opt := false
	| _ 	  -> Log.error (Printf.sprintf "Illegal boolean value for %s option (expected TRUE or FALSE)" optname)

      (** update the register table in configuration module *)
      let init_register rname v = Hashtbl.add Config.register_content (Register.of_name rname) v

      let update_mandatory key =
	let kname, sname, _ = Hashtbl.find mandatory_keys key in
	Hashtbl.replace mandatory_keys key (kname, sname, true);;

      (** footer function *)
      let check_context () =
	(* check whether all mandatory items are provided *)
	Hashtbl.iter (fun _ (pname, sname, b) -> if not b then missing_item pname sname) mandatory_keys;
	(* open the binary to pick up the text section *)
	let fid  =
	  try
	    let fid = open_in_bin !Config.binary in
	    seek_in fid !Config.phys_code_addr;
	    fid
	  with _ -> Log.error "failed to open the binary to analyze"

	in
	Config.text := String.make !Config.code_length '\x00';
    really_input fid !Config.text 0 !Config.code_length;
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
	    Config.add_tainting_rules l fname c' r args
	  in
	  List.iter add (List.rev funs)
	in
	Hashtbl.iter add_tainting_rules libraries;
	(* complete the table of function rules with type information *)
	if String.compare !npk_header "" <> 0 then
	    try
	      let p = Newspeak.read !npk_header in	  
	      Config.add_typing_rules p.Newspeak.fundecs
	    with _ -> Log.error "failed to load headers from npk file"
	;;

	%}
%token EOF LEFT_SQ_BRACKET RIGHT_SQ_BRACKET EQUAL REG MEM STAR PIPE AT TAINT
%token CALL_CONV CDECL FASTCALL STDCALL MEM_MODEL MEM_SZ OP_SZ STACK_WIDTH
%token ANALYZER UNROLL DS CS SS ES FS GS FLAT SEGMENTED BINARY STATE CODE_LENGTH
%token FORMAT PE ELF ENTRYPOINT FILEPATH MASK MODE REAL PROTECTED CODE_PHYS_ADDR
%token LANGLE_BRACKET RANGLE_BRACKET LPAREN RPAREN COMMA SETTINGS UNDERSCORE LOADER DOTFILE
%token GDT CODE_VA CUT ASSERT IMPORTS CALL U T STACK RANGE HEAP VERBOSE SEMI_COLON
%token ANALYSIS FORWARD_BIN FORWARD_CFA BACKWARD STORE_MCFA IN_MCFA_FILE OUT_MCFA_FILE HEADER
%token OVERRIDE NONE ALL SECTIONS ENTRY
%token <string> STRING 
%token <string> HEX_BYTES
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
    | LEFT_SQ_BRACKET SECTIONS RIGHT_SQ_BRACKET s=data_sections   { s }
    | LEFT_SQ_BRACKET GDT RIGHT_SQ_BRACKET gdt=gdt 	     { gdt }
    | LEFT_SQ_BRACKET l=libname RIGHT_SQ_BRACKET lib=library { l; lib }
    | LEFT_SQ_BRACKET ASSERT RIGHT_SQ_BRACKET r=assert_rules { r }
    | LEFT_SQ_BRACKET IMPORTS RIGHT_SQ_BRACKET i=imports     { i }
    | LEFT_SQ_BRACKET OVERRIDE RIGHT_SQ_BRACKET o=overrides     { o }

    overrides:
    |                     { () }
    | o=override l=overrides { o ; l }

    override:
    | a=INT EQUAL l = tainting_rules { Hashtbl.replace Config.override a l }

    tainting_rules:
    |                     { [] }
    | t=tainting SEMI_COLON l=tainting_rules { t::l }
    
    tainting:
    | r=STRING COMMA ALL { let reg = Register.of_name r in (reg, Config.Taint (Bits.ff ((Register.size reg)/8))) }
    | r=STRING COMMA NONE { (Register.of_name r, Config.Taint Z.zero) }
    | r=STRING COMMA s=tcontent { (Register.of_name r, s) }
    
      imports:
    |                     { () }
    | i=import l=imports  { i ; l }

      import:
    | a=INT EQUAL libname=STRING COMMA fname=STRING { Hashtbl.replace Config.import_tbl a (libname, fname) }
    | HEADER EQUAL npkname=STRING { npk_header := npkname }    

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
    | CS EQUAL i=init         	 { update_mandatory CS; init_register "cs" i }
    | DS EQUAL i=init          	 { update_mandatory DS; init_register "ds" i }
    | SS EQUAL i=init          	 { update_mandatory SS; init_register "ss" i }
    | ES EQUAL i=init 	      	 { update_mandatory ES; init_register "es" i }
    | FS EQUAL i=init 	      	 { update_mandatory FS; init_register "fs" i }
    | GS EQUAL i=init 	      	 { update_mandatory GS; init_register "gs" i }
    | CODE_LENGTH EQUAL i=INT 	 { update_mandatory CODE_LENGTH; Config.code_length := Z.to_int i }
    | ENTRYPOINT EQUAL i=INT  	 { update_mandatory ENTRYPOINT; Config.ep := i }
    | CODE_PHYS_ADDR EQUAL i=INT { update_mandatory CODE_PHYS_ADDR; Config.phys_code_addr := Z.to_int i }
    | CODE_VA EQUAL i=INT 	 { update_mandatory CODE_VA; Config.rva_code := i }


      binary:
    | b=binary_item 	      { b }
    | b=binary_item bb=binary { b; bb }

      binary_item:
    | FILEPATH EQUAL f=STRING 	{ update_mandatory FILEPATH; Config.binary := f }
    | FORMAT EQUAL f=format 	{ update_mandatory FORMAT; Config.format := f }



      format:
    | PE  { Config.Pe }
    | ELF { Config.Elf }
    | BINARY { Config.Binary }

      gdt:
    | g=gdt_item 	{ g }
    | g=gdt_item gg=gdt { g; gg }

      gdt_item:
    | GDT LEFT_SQ_BRACKET i=INT RIGHT_SQ_BRACKET EQUAL v=INT { update_mandatory GDT; Hashtbl.replace Config.gdt i v }


      analyzer:
    | a=analyzer_item 		  { a }
    | a=analyzer_item aa=analyzer { a; aa }

      analyzer_item:
    | UNROLL EQUAL i=INT 	     { Config.unroll := Z.to_int i }
    | DOTFILE EQUAL f=STRING 	     { update_mandatory DOTFILE; Config.dotfile := f }
    | CUT EQUAL l=addresses 	     { List.iter (fun a -> Config.blackAddresses := Config.SAddresses.add a !Config.blackAddresses) l }
    | VERBOSE EQUAL v=STRING 	     { update_boolean "verbose" Config.verbose v }
    | ANALYSIS EQUAL v=analysis_kind { update_mandatory ANALYSIS; Config.analysis := v }
    | IN_MCFA_FILE EQUAL f=STRING       { update_mandatory IN_MCFA_FILE; Config.in_mcfa_file := f }
    | OUT_MCFA_FILE EQUAL f=STRING       { update_mandatory OUT_MCFA_FILE; Config.out_mcfa_file := f }
    | STORE_MCFA EQUAL v=STRING      { update_mandatory STORE_MCFA; update_boolean "store_mcfa" Config.store_mcfa v }

      analysis_kind:
    | FORWARD_BIN  { Config.Forward Config.Bin }
    | FORWARD_CFA  { Config.Forward Config.Cfa }
    | BACKWARD { Config.Backward }

      data_sections:
    | ENTRY EQUAL virt_addr=INT COMMA virt_size=INT COMMA raw_addr=INT COMMA raw_size=INT COMMA name=STRING { Config.sections :=  (virt_addr, virt_size, raw_addr, raw_size, name)::(!Config.sections) }

     addresses:
    | i=INT { [ i ] }
    | i=INT COMMA l=addresses { i::l }

      state:
    | s=state_item 	    { s }
    | s=state_item ss=state { s; ss }

      state_item:
    | REG LEFT_SQ_BRACKET r=STRING RIGHT_SQ_BRACKET EQUAL v=init    { init_register r v }
    | MEM LEFT_SQ_BRACKET m=repeat RIGHT_SQ_BRACKET EQUAL v=init    { Hashtbl.add Config.memory_content m v }
    | STACK LEFT_SQ_BRACKET m=repeat RIGHT_SQ_BRACKET EQUAL v=init  { Hashtbl.add Config.stack_content m v }
    | HEAP LEFT_SQ_BRACKET m=repeat RIGHT_SQ_BRACKET EQUAL v=init   { Hashtbl.add Config.heap_content m v }

      repeat:
    | i=INT { i, 1 }
    | i=INT STAR n=INT { i, Z.to_int n }

      library:
    | l=library_item 		{ l }
    | l=library_item ll=library { l; ll }

      library_item:
    | CALL_CONV EQUAL c=callconv  { let funs = snd (Hashtbl.find libraries !libname) in Hashtbl.replace libraries !libname (Some c, funs)  }
    | v=fun_rule 		  { let f, c, a = v in let cl, funs = Hashtbl.find libraries !libname in Hashtbl.replace libraries !libname (cl, (f, c, None, a)::funs) }
    | r=argument EQUAL v=fun_rule { let f, c, a = v in let cl, funs = Hashtbl.find libraries !libname in Hashtbl.replace libraries !libname (cl, (f, c, Some r, a)::funs) }

      fun_rule:
    | f=STRING LANGLE_BRACKET c=callconv RANGLE_BRACKET a=arguments { f, Some c, List.rev a }
    | f=STRING 	a=arguments 			     		    { f, None, List.rev a }

      arguments:
    | arg_list = delimited (LPAREN, separated_list (COMMA, argument), RPAREN) { arg_list }

     argument:
    | UNDERSCORE { Config.No_taint }
    | AT 	 { Config.Addr_taint }
    | STAR 	 { Config.Buf_taint }

      assert_rules:
    |                               { () }
    | a=assert_rule aa=assert_rules { a ; aa }

     assert_rule:
    | U EQUAL LPAREN CALL a=INT RPAREN arg=arguments { Hashtbl.replace Config.assert_untainted_functions a arg }
    | T EQUAL LPAREN CALL a=INT RPAREN arg=arguments { Hashtbl.replace Config.assert_tainted_functions a arg }

    (* memory and register init *)
     init:
    | TAINT tcontent 	            { Log.error "Parser: illegal initial content: undefined content with defined tainting value" }
    | c=mcontent 	            { c, None }
    | c1=mcontent TAINT c2=tcontent { c1, Some c2 }

      mcontent:
    | s=HEX_BYTES { Config.Bytes s }
    | s=HEX_BYTES MASK m=INT 	{ Config.Bytes_Mask (s, m) }
    | m=INT 		{ Config.Content m }
    | m=INT MASK m2=INT { Config.CMask (m, m2) }

     tcontent:
    | t=INT 		{ Config.Taint t }
    | t=INT MASK t2=INT { Config.TMask (t, t2) }

