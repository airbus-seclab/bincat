%{
    let section_name = ref ""
    let settings     = Hashtbl.create 10;;
    let loader 	     = Hashtbl.create 10;;
    let binary 	     = Hashtbl.create 10;;
    let analyzer     = Hashtbl.create 10;;
    let states 	     = Hashtbl.create 10;;
    let libraries    = Hashtbl.create 10;;
      
    let fill_val k v =
      let add_state () =
	try
	  let h' = Hashtbl.find states !section_name in
	  Hashtbl.add h' k v
	with Not_found -> 
	  let h' = Hashtbl.create 10 in
	  Hashtbl.add h' k v;
	  Hashtbl.add states !section_name h'
      in
      let add_lib () = Hashtbl.add libraries !section_name (!Context.call_conv, [])
      in
      match !section_name with
      | "settings" -> Hashtbl.add settings k v
      | "loader"   -> Hashtbl.add loader k v
      | "binary"   -> Hashtbl.add binary k v
      | "analyzer" -> Hashtbl.add analyzer k v
      | _ 	   ->
	 try
	   let prefix = String.sub !section_name 0 6 in
	   if String.compare prefix "state-" = 0 then
	     add_state ()
	   else
	     add_lib ()
	 with _ -> add_lib ()
      
	    
    let check_settings k v =
      match k with
      | "mem-model" -> 
	 begin
	   match v with
	   | "flat"      -> Context.memory_model := Context.Flat
	   | "segmented" -> Context.memory_model := Context.Segmented
	   | _ 	      	 -> failwith "Parser: illegal memory model or memory model not provided"
	 end
      | "call-conv" ->
	 begin
	   match v with
	   | "cdecl"    -> Context.call_conv := Context.Cdecl
	   | "stdcall"  -> Context.call_conv := Context.Stdcall
	   | "fastcall" -> Context.call_conv := Context.Fastcall
	   | _ 	     	-> failwith "Parser: illegal calling convention or calling convention not provided"
	 end
      | "op-sz" ->
	 begin
	   try
	     Context.operand_sz := int_of_string v;
	     if !Context.operand_sz < 0 then raise Exit
	   with _ -> failwith "Parser: illegal operand size or operand size not provided"
	 end
      | "addr-sz" ->
	 begin
	   try
	     Context.address_sz := int_of_string v;
	     if !Context.address_sz < 0 then raise Exit
	   with _ -> failwith "Parser: illegal address size or address size not provided"
	 end
      | "stack-width"  ->
	 begin
	   try
	     Context.stack_width := int_of_string v;
	     if !Context.stack_width < 0 then raise Exit
	   with _ -> failwith "Parser: illegal address size"
	 end
      | _  -> failwith ("Parser: key "^k^" in section settings not recognized")
		       
    let check_loader k v =
      match k with
      | "rva-stack" -> Context.stack_addr := v
      | "rva-data"  -> Context.data_addr := v					     
      | "rva-code"  -> Context.text_addr := v
      | _ 	  -> failwith ("Parser: key "^k^" in section loader not recognized")
			      
			      
    let check_binary k _v =
      match k with
      | "filepath" | "format" | "rva-entrypoint"
      | "phys-textsection" | "rva-textsection-start" | "rva-textsection-end" -> ()
      | _ 									  -> failwith ("Parser: key "^k^" in section binary not parsed")
											      
    let check_analyzer k v =
      match k with
      |  "unroll" -> begin
	  try
	    Context.unroll := int_of_string v;
	    if !Context.unroll < 0 then raise Exit
	  with _ -> failwith "Parser: illegal unrolling value"
	end
      | _ -> failwith ("Parser: key "^k^" in section analyzer not parsed")
		      
    let fill_context () =
      let l =  [(settings, "settings", 5, check_settings) ; (loader, "loader", 3, check_loader) ; (binary, "binary", 6, check_binary) ; (analyzer, "analyzer", 1, check_analyzer)]  in
      List.iter (fun (h, hname, n, f) -> if Hashtbl.length h <> n then failwith ("incomplete section " ^ hname) else Hashtbl.iter f h) l;
      let fid =
	try
	  open_in_bin (Hashtbl.find binary "filepath")
	with _ -> failwith "Parser: file opening failed"
      in
      if String.compare (Hashtbl.find binary "format") "pe" <> 0 then failwith "Parser: file format not recognized";
      Context.ep := Hashtbl.find binary "rva-entrypoint";
      begin
	let n = int_of_string (Hashtbl.find binary "phys-textsection") in
	try
	  seek_in fid n
	with _ -> failwith ("Parser: seeking at " ^ (string_of_int n) ^" failed")
      end;
      let start = Hashtbl.find binary "rva-textsection-start" in
      Context.text_addr :=  start ;
      let code_length = (int_of_string (Hashtbl.find binary "rva-textsection-end" )) - (int_of_string start) in
      if code_length < 0 then
	failwith "Parser: physical address of the end of the texte section is lower than ist start";
      let len = input fid !Context.text 0 code_length in
      if len <> code_length then
	failwith "Parser: picking up text section is partial";;
  
      %}
%token EOF LEFT_SQ_BRACKET RIGHT_SQ_BRACKET EQUAL REG MEM STAR AT
%token <string> STRING
%start process
%type <unit> process

%%
  process:
    sections EOF { $1 ; fill_context ()}
    ;
      
      sections:
    | section { $1 }
    | sections section { $1 ; $2 }
    ;
      section:
    | section_name content { $1 ; $2 }
    ;
      section_name:
    | LEFT_SQ_BRACKET STRING RIGHT_SQ_BRACKET { section_name:=$2 ; print_endline !section_name}
    ;
      content:
    | item { $1 } 
    | content item { $1 ; $2 }
    ;
      item:
    | STRING EQUAL STRING { fill_val $1 $3 }
    | REG LEFT_SQ_BRACKET STRING RIGHT_SQ_BRACKET EQUAL STRING { fill_val $3 $6 }
    | MEM LEFT_SQ_BRACKET STRING RIGHT_SQ_BRACKET EQUAL STRING { fill_val $3 $6 }
;
