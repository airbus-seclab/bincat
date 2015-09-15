%token EOF SECTION_START SECTION_END
%token <string> STRING
		%start process
		%type <unit> process
%%
  process:
    process_section EOF { $1 }
;;
  process_sections:
    process_section process_section { $1 ; $2 }
| { () }
;;
  process_section:
    SECTION_START STRING SECTION_END { () }

/*		 
Abi.address_sz := addr_sz;
  Abi.operand_sz := op_sz;
  Abi.stack_width := stack_width;
  Abi.segments.Abi.cs <- cs
  Abi.segments.Abi.ds <- ds
  Abi.segments.Abi.ss <- ss
  Abi.segments.Abi.es <- es
  Abi.segments.Abi.fs <- fs
  Abi.segments.Abi.gs <- gs
 */
