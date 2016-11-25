let unroll = ref 10;;
let verbose = ref false;;
let refinements = ref 2;;
  
(* set of values that will not be explored as values of the instruction pointer *)
module SAddresses = Set.Make(Z)
let blackAddresses = ref SAddresses.empty

let dotfile = ref "";;

type memory_model_t =
  | Flat
  | Segmented

let memory_model = ref Flat

type format_t =
  | Pe
  | Elf
  | Binary

type mode_t =
  | Protected
  | Real

type analysis_src =
  | Bin
  | Cfa

type analysis_t =
  | Forward of analysis_src
  | Backward

let analysis = ref (Forward Bin);;

let mode = ref Protected

let in_mcfa_file = ref "";;
let out_mcfa_file = ref "";;
  
let load_mcfa = ref false;;
let store_mcfa = ref false;;

let format = ref Pe

type call_conv_t =
  | Cdecl
  | Stdcall
  | Fastcall

let call_conv = ref Cdecl

let text = ref ""
let code_length = ref 0
let ep = ref Z.zero
let phys_code_addr = ref 0
let rva_code = ref Z.zero

let address_sz = ref 32
let operand_sz = ref 32
let stack_width = ref 32

let gdt: (Z.t, Z.t) Hashtbl.t = Hashtbl.create 19

let cs = ref Z.zero
let ds = ref Z.zero
let ss = ref Z.zero
let es = ref Z.zero
let fs = ref Z.zero
let gs = ref Z.zero


type tvalue =
  | Taint of Z.t
  | TMask of Z.t * Z.t (* second element is a mask on the first one *)

type cvalue =
  | Content of Z.t
  | CMask of Z.t * Z.t
  | Bytes of string
  | Bytes_Mask of (string * Z.t)

let override: (Z.t, ((Register.t * tvalue) list)) Hashtbl.t = Hashtbl.create 5
    
(* tables for initialize global memory, stack and heap *)
(* first element in the key is the address ; second one is the number of repetition *)
type ctbl = (Z.t * int, cvalue * (tvalue option)) Hashtbl.t

let register_content: (Register.t, cvalue * tvalue option) Hashtbl.t = Hashtbl.create 10
let memory_content: ctbl = Hashtbl.create 10
let stack_content: ctbl = Hashtbl.create 10
let heap_content: ctbl = Hashtbl.create 10

type 
let sections = ref [] (* (Z.t * Z.t * Z.t * Z.t * string) list = ref [] *)

let import_tbl: (Z.t, (string * string)) Hashtbl.t = Hashtbl.create 5

(* tainting and typing rules for functions *)
type taint_t =
  | No_taint
  | Buf_taint
  | Addr_taint
      
type typ_t = Newspeak.typ option
  
(** rule for an argument of a function or its returned value *)
type arg_t = typ_t * taint_t
  
type fun_t = {
  call_conv: call_conv_t;
  ret: arg_t option;
  args: arg_t list;
}
  
type fid = int
let fid_cpt = ref 0	       
(** key is the address of the function code or import index *)
let fid_offset_tbl: (Z.t, fid) Hashtbl.t = Hashtbl.create 5
(** key is (function name, library name) *)
let fid_fname_tbl: ((string * string), fid) Hashtbl.t = Hashtbl.create 5 
let funs_tbl: (fid, fun_t) Hashtbl.t = Hashtbl.create 7 
  
let add_tainting_rules (libname: string) (fname: string) (callconv: call_conv_t) (taint_ret: taint_t option) (taint_args: taint_t list) =
 try
      let fid = Hashtbl.find fid_fname_tbl (fname, libname) in
      let f = Hashtbl.find funs_tbl fid in
      let ret' =
	match taint_ret, f.ret with
	| Some t, Some typ -> Some (fst typ, t)
	| None, None -> None
	|_, _ -> failwith (Printf.sprintf "Incompatible configuration for function %s (library %s)" fname libname)   
      in 
      Hashtbl.replace funs_tbl fid {
	f with ret = ret';
	  args = List.map2 (fun parg narg -> fst parg, narg) f.args taint_args
      }
 with
   Not_found ->
     Hashtbl.add fid_fname_tbl (fname, libname) !fid_cpt;
     let ret' =
       match taint_ret with
       | Some t -> Some (None, t)
       | None -> None 
      in
     Hashtbl.add funs_tbl !fid_cpt {
       call_conv = callconv;
       ret = ret';
       args = List.map (fun a -> None, a) taint_args
     };
     fid_cpt := !fid_cpt + 1

let add_typing_rules _ = failwith "Config.add_typing_rules: to implement"


(** data stuctures for the assertions *)
let assert_untainted_functions: (Z.t, taint_t list) Hashtbl.t = Hashtbl.create 5
let assert_tainted_functions: (Z.t, taint_t list) Hashtbl.t = Hashtbl.create 5



let clear_tables () =
  Hashtbl.clear assert_untainted_functions;
  Hashtbl.clear assert_tainted_functions;
  Hashtbl.clear funs_tbl;
  Hashtbl.clear fid_fname_tbl;
  Hashtbl.clear memory_content;
  Hashtbl.clear stack_content;
  Hashtbl.clear heap_content;
  Hashtbl.clear funs_tbl;
  Hashtbl.clear override
