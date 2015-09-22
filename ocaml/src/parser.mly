%{
    let section_name = ref ""
    let fill_val k _v =
      match !section_name with
      | "settings" ->
	 print_endline k;
	 begin
	   match k with
	   | "memmodel"     -> print_endline "ok"
	   | "callconv"     -> print_endline "ok"
	   | "operand_size" -> print_endline "ok"
	   | "address_size" -> print_endline "ok"
	   | "stack_width"  -> print_endline "ok"
	   | _ 		    -> failwith ("Parser: key "^k^" in section "^(!section_name)^" not parsed")
	 end
      | "binary" -> begin
	  match k with
	  | "name" 		  -> print_endline "ok"
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
