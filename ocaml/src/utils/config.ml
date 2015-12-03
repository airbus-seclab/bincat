let unroll = ref 10;;

type memory_model_t =
  | Flat
  | Segmented
      
let memory_model = ref Flat

type format_t =
  | Pe
  | Elf
      
let format = ref Pe
		 
type call_conv_t =
  | Cdecl
  | Stdcall
  | Fastcall

let call_conv = ref Cdecl
		    
let text = ref ""
let ep = ref ""
let code_addr_start = ref ""
let code_addr_end = ref ""
let stack_addr = ref ""
let data_addr = ref ""
		    
let address_sz = ref 32
let operand_sz = ref 32
let stack_width = ref 32

let cs = ref "\x00"
let ds = ref "\x00"
let ss = ref "\x00"
let es = ref "\x00"
let fs = ref "\x00"
let gs = ref "\x00"


type tvalue =
  | Bits of string (* string of bits *)
  | MBits of string * string (* bit string with a mask as second element *)

type cvalue = string
		
(* initial state utilities *)
		    
let initial_register_content = Hashtbl.create 10
let initial_memory_content = Hashtbl.create 10
let initial_register_tainting = Hashtbl.create 10
let initial_memory_tainting = Hashtbl.create 10					   


(* tainting rules for functions *)
type taint =
  | No_taint
  | Buf_taint
  | Addr_taint

type tainting_fun = string * call_conv_t * taint option * taint list
let tainting_tbl = Hashtbl.create 7
let add_tainting_rules libname fun_rules =
  let cfuns =
    try
      Hashtbl.find tainting_tbl libname
    with
      Not_found -> Hashtbl.add tainting_tbl libname []; []
  in
  Hashtbl.replace tainting_tbl libname (fun_rules::cfuns)


