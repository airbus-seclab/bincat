%{
    let section_name = ref ""
    let _fid = ref ""
    let fill_val k v =
      match !section_name with
      | "settings" ->
	 print_endline k;
	 begin
	   match k with
	   | "memmodel"     ->
	      begin
		match v with
		| "flat"      -> Context.memory_model := Context.Flat
		| "segmented" -> Context.memory_model := Context.Segmented
		| _ 	      -> failwith "Parser: illegal memory model"
	      end
	   | "callconv"     ->
	      begin
		match v with
		| "cdecl"    -> Context.call_conv := Context.Cdecl
		| "stdcall"  -> Context.call_conv := Context.Stdcall
		| "fastcall" -> Context.call_conv := Context.Fastcall
		| _ 	     -> failwith "Parser: illegal memory model"
	      end
	   | "operand_size" ->
	      begin
		try
		  Context.operand_sz := int_of_string v;
		  if !Context.operand_sz < 0 then raise Exit
		with _ -> failwith "Parser: illegal operand size"
	      end
	   | "address_size" ->
	      begin
		try
		  Context.address_sz := int_of_string v;
		  if !Context.address_sz < 0 then raise Exit
		with _ -> failwith "Parser: illegal address size"
	      end
	   | "stack_width"  ->
	       begin
		try
		  Context.stack_width := int_of_string v;
		  if !Context.stack_width < 0 then raise Exit
		with _ -> failwith "Parser: illegal address size"
	      end
	   | _ 		    -> failwith ("Parser: key "^k^" in section "^(!section_name)^" not parsed")
	 end
      | "binary" -> begin
	  match k with
	  | "name" 		  -> print_endline "ok"
	     (* begin *)
	     (*   try *)
	     (* 	 fid := open(v, 'r') *)
	     (* 		    with _ -> failwith "Parser: file opening failed" *)
	     (* end *)
	  | "entrypoint_main" 	  -> print_endline "ok"
	  | "entrypoint_main_raw" -> print_endline "ok"
	  | "textsection_start"   -> print_endline "ok" 
	  | "textsection_end" 	  -> print_endline "ok"
	  | _ 			  -> failwith ("Parser: key "^k^" in section "^(!section_name)^" not parsed")
	end
      | "state" -> begin
	  match k with
	  | _ -> print_endline "ok" 
	end
      | "analyzer" -> begin
	  match k with
	  |  "kbound" -> print_endline "ok"
	  | _ -> failwith ("Parser: key "^k^" in section "^(!section_name)^" not parsed")
	end	  
      | _ -> failwith ("Parser: section "^(!section_name)^" not parsed")
%}
%token EOF LEFT_SQ_BRACKET RIGHT_SQ_BRACKET EQUAL REG
%token <string> STRING
%start process
%type <unit> process

%%
  process:
    sections EOF { $1 }
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
;
