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


		 
(* initial state utilities *)
	     
type init = { content: string option; taint: string option }
let initial_register_values = Hashtbl.create 10
let initial_memory_values = Hashtbl.create 10
					   
let init_register r v t = Hashtbl.add initial_register_values r { content = v; taint = t }
				      
let init_memory a v t =
  let choose xprev x =
    match xprev, x with
	None, _ -> x
      | Some _, None -> xprev
      | Some _, Some _ -> x
  in
  try
    let prev = Hashtbl.find initial_memory_values a in
    let v'   = choose prev.content v                in
    let t'   = choose prev.taint t                  in
    Hashtbl.replace initial_memory_values a { content = v' ; taint = t' }
  with Not_found -> Hashtbl.add initial_memory_values a { content = v; taint = t }

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
