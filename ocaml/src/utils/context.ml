let unroll = ref 10;;

type memory_model_t =
  | Flat
  | Segmented
      
let memory_model = ref Flat

type call_conv_t =
  | Cdecl
  | Stdcall
  | Fastcall

let call_conv = ref Cdecl
		    
let text = ref ""
let ep = ref ""
let text_addr = ref ""
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
