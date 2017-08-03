(*
    This file is part of BinCAT.
    Copyright 2014-2017 - Airbus Group

    BinCAT is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or (at your
    option) any later version.

    BinCAT is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with BinCAT.  If not, see <http://www.gnu.org/licenses/>.
*)

%{
    module L = Log.Make(struct let name = "parser" end)
  
    let missing_item item section =
      (* error message printing *)
      L.abort (fun p -> p "missing %s in section %s\n" item section);;

    (* current library name *)
    let libname = ref "";;

    (* temporary table to store tainting rules on functions of a given library *)
    let libraries: (string, Config.call_conv_t option * ((string * Config.call_conv_t option * Config.taint_t option * Config.taint_t list) list)) Hashtbl.t = Hashtbl.create 7;;

    (* list of the npk filenames containing function headers *)
    let npk_headers = ref []

    (* current override address *)
    let override_addr = ref Z.zero
      
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

      (** set the corresponding option reference *)
      let update_boolean optname opt v =
	match String.uppercase v with
	| "TRUE"  -> opt := true
	| "FALSE" -> opt := false
	| _ 	  -> L.abort (fun p -> p "Illegal boolean value for %s option (expected TRUE or FALSE)" optname)

      (** update the register table in configuration module *)
      let init_register rname v = Hashtbl.add Config.register_content (Register.of_name rname) v

      let update_mandatory key =
	let kname, sname, _ = Hashtbl.find mandatory_keys key in
	Hashtbl.replace mandatory_keys key (kname, sname, true);;

      (** check that the version matches the one we support *)
      let check_ini_version input_version =
	let supported_version = 1 in
	if input_version != supported_version then
	  L.abort (fun p->p "Invalid configuration version: '%d', expected: '%d'" input_version supported_version);;

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
	  with _ -> L.abort (fun p -> p "failed to open the binary to analyze")

	in
	Config.text := String.make !Config.code_length '\x00';
	really_input fid !Config.text 0 !Config.code_length;
	close_in fid;
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
	    Hashtbl.replace Config.tainting_rules (l, fname) (c', r, args)
	  in
	  List.iter add (List.rev funs)
	in
	Hashtbl.iter add_tainting_rules libraries;
	(* complete the table of function rules with type information *)
	List.iter (fun header -> 
	    try
	      let p = TypedC.read header in	  
	      List.iter (fun (s, f) ->
		Hashtbl.add Config.typing_rules s f.TypedC.function_type) p.TypedC.function_declarations
	    with _ -> L.warn (fun p -> p "failed to load header %s" header)) !npk_headers
	;;

	%}
%token EOF LEFT_SQ_BRACKET RIGHT_SQ_BRACKET EQUAL REG MEM STAR AT TAINT
%token CALL_CONV CDECL FASTCALL STDCALL MEM_MODEL MEM_SZ OP_SZ STACK_WIDTH
%token ANALYZER INI_VERSION UNROLL FUN_UNROLL DS CS SS ES FS GS FLAT SEGMENTED BINARY STATE CODE_LENGTH
%token FORMAT PE ELF ENTRYPOINT FILEPATH MASK MODE REAL PROTECTED CODE_PHYS_ADDR
%token LANGLE_BRACKET RANGLE_BRACKET LPAREN RPAREN COMMA SETTINGS UNDERSCORE LOADER DOTFILE
%token GDT CODE_VA CUT ASSERT IMPORTS CALL U T STACK HEAP SEMI_COLON
%token ANALYSIS FORWARD_BIN FORWARD_CFA BACKWARD STORE_MCFA IN_MCFA_FILE OUT_MCFA_FILE HEADER
%token OVERRIDE TAINT_NONE TAINT_ALL SECTION SECTIONS LOGLEVEL
%token <string> STRING 
%token <string> HEX_BYTES
%token <string> QUOTED_STRING
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
    | a=override_addr EQUAL i = override_item { a ; i }

    override_addr:
    | a=INT  { override_addr := a } 

    override_item:
    |                     { () }
    | tainting_reg_item { () }
    | tainting_reg_item SEMI_COLON override_item { () }
    | tainting_addr_item { () }
    | tainting_addr_item SEMI_COLON override_item { () }

    tainting_reg_item:
    | t=tainting_reg {
      try
	let l = Hashtbl.find Config.reg_override !override_addr in
	Hashtbl.replace Config.reg_override !override_addr (t::l)
      with Not_found -> Hashtbl.add Config.reg_override !override_addr [t] }

    tainting_addr_item:
    | c=tainting_addr {
      let (tbl, a, o) = c in
      try
	let l' = Hashtbl.find tbl !override_addr in
	Hashtbl.replace tbl !override_addr ((a, o)::l')
      with Not_found -> Hashtbl.add tbl !override_addr [(a, o)]
    }
    
    tainting_reg:
    | REG LEFT_SQ_BRACKET r=STRING RIGHT_SQ_BRACKET COMMA TAINT_ALL {
      let reg = Register.of_name r in
      (reg, Config.Taint (Bits.ff ((Register.size reg )/8))) }
    | REG LEFT_SQ_BRACKET r=STRING RIGHT_SQ_BRACKET COMMA TAINT_NONE { (Register.of_name r, Config.Taint Z.zero) }
    | REG LEFT_SQ_BRACKET r=STRING RIGHT_SQ_BRACKET COMMA s=tcontent { (Register.of_name r, s) } 

    tainting_addr:
    | MEM LEFT_SQ_BRACKET a=INT RIGHT_SQ_BRACKET COMMA c = tainting_addr_content { Config.mem_override, a, c }
    | HEAP LEFT_SQ_BRACKET a=INT RIGHT_SQ_BRACKET COMMA c = tainting_addr_content { Config.heap_override, a, c }
    | STACK LEFT_SQ_BRACKET a=INT RIGHT_SQ_BRACKET COMMA c = tainting_addr_content { Config.stack_override, a, c }
    

    tainting_addr_content:
    | TAINT_ALL { Config.Taint (Z.of_string "ff") }
    | TAINT_NONE { Config.Taint Z.zero }
    | s=tcontent { s }
    
      imports:
    |                     { () }
    | i=import l=imports  { i ; l }

      import:
    | a=INT EQUAL libname=STRING COMMA fname=QUOTED_STRING { Hashtbl.replace Config.import_tbl a (libname, fname) }
    | HEADER EQUAL npk_list=npk { npk_headers := npk_list }    

      npk:
    | { [] }
    | s=STRING { [ s ] }
    | s=STRING COMMA l=npk { s::l }
    
      libname:
    | l=STRING { libname := l; Hashtbl.add libraries l (None, []) }

      settings:
    | s=setting_item 		 { s }
    | s=setting_item ss=settings { s; ss }

      setting_item:
    | MEM_MODEL EQUAL m=memmodel { update_mandatory MEM_MODEL; Config.memory_model := m }
    | CALL_CONV EQUAL c=callconv { update_mandatory CALL_CONV; Config.call_conv := c }
    | OP_SZ EQUAL i=INT          { update_mandatory OP_SZ; try Config.operand_sz := Z.to_int i with _ -> L.abort (fun p -> p "illegal operand size: [%s]" (Z.to_string i)) }
    | MEM_SZ EQUAL i=INT         { update_mandatory MEM_SZ; try Config.address_sz := Z.to_int i with _ -> L.abort (fun p -> p "illegal address size: [%s]" (Z.to_string i)) }
    | STACK_WIDTH EQUAL i=INT    { update_mandatory STACK_WIDTH; try Config.stack_width := Z.to_int i with _ -> L.abort (fun p -> p "illegal stack width: [%s]" (Z.to_string i)) }
    | MODE EQUAL m=mmode         { update_mandatory MODE ; Config.mode := m }

      memmodel:
    | FLAT 	{ Config.Flat }
    | SEGMENTED { Config.Segmented }

      callconv:
    | CDECL    { Config.CDECL }
    | FASTCALL { Config.FASTCALL }
    | STDCALL  { Config.STDCALL }


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
    | INI_VERSION EQUAL i=INT 	     { check_ini_version (Z.to_int i) }
    | UNROLL EQUAL i=INT 	     { Config.unroll := Z.to_int i }
    | FUN_UNROLL EQUAL i=INT 	     { Config.fun_unroll := Z.to_int i }
    | DOTFILE EQUAL f=STRING 	     { update_mandatory DOTFILE; Config.dotfile := f }
    | CUT EQUAL l=addresses 	     { List.iter (fun a -> Config.blackAddresses := Config.SAddresses.add a !Config.blackAddresses) l }
    | LOGLEVEL EQUAL i=INT           { Config.loglevel := Z.to_int i }
    | LOGLEVEL modname=STRING EQUAL i=INT
                                     { Hashtbl.add Config.module_loglevel modname (Z.to_int i) }
    | ANALYSIS EQUAL v=analysis_kind { update_mandatory ANALYSIS; Config.analysis := v }
    | IN_MCFA_FILE EQUAL f=STRING       { update_mandatory IN_MCFA_FILE; Config.in_mcfa_file := f }
    | OUT_MCFA_FILE EQUAL f=STRING       { update_mandatory OUT_MCFA_FILE; Config.out_mcfa_file := f }
    | STORE_MCFA EQUAL v=STRING      { update_mandatory STORE_MCFA; update_boolean "store_mcfa" Config.store_mcfa v }

      analysis_kind:
    | FORWARD_BIN  { Config.Forward Config.Bin }
    | FORWARD_CFA  { Config.Forward Config.Cfa }
    | BACKWARD { Config.Backward }

      data_sections:
    |  { () }
    | s=section_item ss = data_sections{ s ; ss }

      section_item:
    | SECTION LEFT_SQ_BRACKET name=STRING RIGHT_SQ_BRACKET EQUAL virt_addr=INT COMMA virt_size=INT COMMA raw_addr=INT COMMA raw_size=INT { Config.sections :=  (virt_addr, virt_size, raw_addr, raw_size, name)::(!Config.sections)  }

     addresses:
    | i=INT { [ i ] }
    | i=INT COMMA l=addresses { i::l }

      state:
    | s=state_item 	    { s }
    | s=state_item ss=state { s; ss }

      state_item:
    | REG LEFT_SQ_BRACKET r=STRING RIGHT_SQ_BRACKET EQUAL v=init    { init_register r v }
    | MEM LEFT_SQ_BRACKET m=repeat RIGHT_SQ_BRACKET EQUAL v=init    { Config.memory_content := (m, v) :: !Config.memory_content }
    | STACK LEFT_SQ_BRACKET m=repeat RIGHT_SQ_BRACKET EQUAL v=init  { Config.stack_content := (m, v)  :: !Config.stack_content }
    | HEAP LEFT_SQ_BRACKET m=repeat RIGHT_SQ_BRACKET EQUAL v=init   { Config.heap_content := (m, v) :: !Config.heap_content }

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
    | TAINT tcontent 	            { L.abort (fun p -> p "Parser: illegal initial content: undefined content with defined tainting value") }
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

