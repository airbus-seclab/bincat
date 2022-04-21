(*
    This file is part of BinCAT.
    Copyright 2014-2022 - Airbus

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

let ignore_unknown_relocations = ref false;;

let unroll = ref 200;;
let fun_unroll = ref 200;;
let kset_bound = ref 50;;
let loglevel = ref 3;;
let module_loglevel: (string, int) Hashtbl.t = Hashtbl.create 5;;
let taint_input = ref false;; (* if true then automatically taint functions with external input like getc *)
let max_instruction_size = ref 16;;

(* set of values that will not be explored as values of the instruction pointer *)
module SAddresses = Set.Make(Z)
let blackAddresses = ref SAddresses.empty
let nopAddresses = ref SAddresses.empty


                  
type memory_model_t =
  | Flat
  | Segmented

let memory_model = ref Flat

type format_t =
  | RAW          (** no structure ; codes begins at phys_code_addr and is loader at rva_code *)
  | MANUAL       (** uses [sections] to map file in virtual mem *)
  | PE
  | ELF
  | ELFOBJ

type archi_t =
  | X86
  | X64
  | ARMv7
  | ARMv8 (* ARMv8-A *)
  | POWERPC
  | POWERPC64
  | RV32I (* risc-v integer 32 bits *)
  | RV64I (* risc-v integer 64 bits *)


let archi_to_string = function
  | X86 -> "x86"
  | X64 -> "x64"
  | ARMv7 -> "armv7"
  | ARMv8 -> "armv8"
  | POWERPC -> "powerpc"
  | POWERPC64 -> "powerpc64"
  | RV32I -> "RV32I"
  | RV64I -> "RV64I"

let architecture = ref X86;;

type endianness_t =
  | LITTLE
  | BIG

let endianness_to_string e =
  match e with
  | LITTLE -> "little endian"
  | BIG -> "big endian"

let endianness = ref LITTLE;;

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

(* name of binary file to analyze *)
let binary = ref "";;

let format = ref RAW

type call_conv_t =
  | CDECL
  | STDCALL
  | FASTCALL
  | AAPCS (* ARM *)
  | SVR (* PowerPC *)
  | SYSV (* x64 SystemV *)
  | MS (* x64 Microsoft *)
  | RISCVI (* risc v without floating point hardware *)

let call_conv_to_string cc =
  match cc with
  | CDECL -> "CDECL"
  | STDCALL -> "STDCALL"
  | FASTCALL -> "FASTCALL"
  | AAPCS -> "AAPCS"
  | SVR -> "SVR"
  | SYSV -> "SYSV"
  | MS -> "MS"
  | RISCVI -> "RISC V integer"

(* MPX extension *)
let mpx = ref false
        
let call_conv = ref CDECL

let ep = ref Z.zero

let address_sz = ref 32
let operand_sz = ref 32
let size_of_long () = !operand_sz
let stack_width = ref 32
let address_format = ref "%x"
let address_format0x = ref "%#x"

let gdt: (Z.t, Z.t) Hashtbl.t = Hashtbl.create 19

(* value of the NULL address *)
let null_cst = ref Z.zero
(* predicate to check whether the given Z.t is the NULL value *) 
let is_null_cst z = Z.compare z !null_cst = 0

let char_of_null_cst () = Char.chr (Z.to_int !null_cst)
  
(* used for powerpc mfspr *)
let processor_version = ref 0

type os_t =
  | Windows
  | Linux
  | Unknown_os

let os = ref Unknown_os
       
(* if true then an interleave of backward then forward analysis from a CFA will be processed *)
(** after the first forward analysis from binary has been performed *)
let interleave = ref false

type tvalue =
  | Taint_all of Taint.Src.id_t 
  | Taint of Z.t * Taint.Src.id_t
  | Taint_none   
  | TMask of Z.t * Z.t * Taint.Src.id_t (* second element is a mask on the first one *)
  | TBytes of string * Taint.Src.id_t
  | TBytes_Mask of (string * Z.t * Taint.Src.id_t)

type region =
  | G (* global *)
  | H (* heap *)

type content = region * Z.t
type bytes = region * string
           
type cvalue =
  | Content of content
  | CMask of content * Z.t
  | Bytes of bytes
  | Bytes_Mask of bytes * Z.t

(** returns size of content, rounded to the next multiple of Config.operand_sz *)
let round_sz sz =
  if sz < !operand_sz then
    !operand_sz
  else
    if sz mod !operand_sz <> 0 then
      !operand_sz * (sz / !operand_sz + 1)
    else
      sz
      
let size_of_content c =
  match c with
  | Content z | CMask (z, _) -> round_sz (Z.numbits (snd z))
  | Bytes (_, b) | Bytes_Mask ((_, b), _) -> (String.length b)*4
                                               
let size_of_taint (t: tvalue): int =
  match t with
  | Taint (z, _) | TMask (z, _, _) -> round_sz (Z.numbits z)
  | TBytes (b, _) | TBytes_Mask (b, _, _) -> (String.length b)*4
  | Taint_all _ | Taint_none -> 0

let size_of_taints (taints: tvalue list): int =
  let sz = ref 0 in
  List.iter (fun t ->
      let n = size_of_taint t in
      if !sz = 0 then sz := n
      else if n <> !sz then failwith "illegal taint list with different sizes"
    ) taints;
  !sz

let size_of_config (c, t) =
  let nt = size_of_taints t in
  match c with
  | None -> nt
  | Some c' -> max (size_of_content c') nt 

type fun_t =
  | Fun_name of string
  | Fun_addr of Z.t
              
(* List of functions to skip
 * (addr/name, nb_of_args_bytes * (ret value))
 *)
let funSkipTbl: (fun_t, Z.t * ((cvalue option * tvalue list) option)) Hashtbl.t  = Hashtbl.create 5
                                
let reg_override: (Z.t, ((string * (Register.t -> (cvalue option * tvalue list))) list)) Hashtbl.t = Hashtbl.create 5
let mem_override: (Z.t, ((Z.t * int) * (cvalue option * tvalue list)) list) Hashtbl.t = Hashtbl.create 5
let heap_override: (Z.t, (((Z.t * Z.t) * int) * (cvalue option * tvalue list)) list) Hashtbl.t = Hashtbl.create 5

(* lists for the initialisation of the global memory and heap *)
(* first element is the key is the address ; second one is the number of repetition *)
type mem_init_t = ((Z.t * int) * (cvalue option * tvalue list)) list
type reg_init_t = (string * (cvalue option * tvalue list)) list

let register_content: reg_init_t ref = ref []
let registers_from_dump: reg_init_t ref = ref []
let memory_content: mem_init_t ref = ref []
let heap_content: mem_init_t ref = ref []

let dumps : string list ref = ref []

type sec_t = (Z.t * Z.t * Z.t * Z.t * string) list ref
let sections: sec_t = ref []

let import_tbl: (Z.t, (string * string)) Hashtbl.t = Hashtbl.create 5
let import_tbl_rev: (string, Z.t) Hashtbl.t = Hashtbl.create 5

(* tainting and typing rules for functions *)
type taint_t =
  | No_taint
  | Buf_taint
  | Addr_taint

(** data stuctures for the assertions *)
let assert_untainted_functions: (Z.t, taint_t list) Hashtbl.t = Hashtbl.create 5
let assert_tainted_functions: (Z.t, taint_t list) Hashtbl.t = Hashtbl.create 5

(** data structure for the tainting rules of import functions *)
let tainting_rules : ((string * string), (call_conv_t * taint_t option * taint_t list)) Hashtbl.t = Hashtbl.create 5


(** data structure for the typing rules of import functions *)
let typing_rules : (string, TypedC.ftyp) Hashtbl.t = Hashtbl.create 5

(** default size of the initial heap *)
(* 1 Go in bits *)
let default_heap_size = ref (Z.mul (Z.shift_left Z.one 30) (Z.of_int 8))


(* argv ooptions *)
type argv_config_t = {
    ignore_unknown_relocations : bool option ref ;
    no_state : bool option ref ;
    filepath : string option ref;
    entrypoint : Z.t option ref ;
    loglevel : int option ref;
    dumps : string list ref;
  }

let argv_options : argv_config_t = {
    ignore_unknown_relocations = ref None ;
    no_state = ref None ;
    filepath = ref None ;
    entrypoint = ref None ;
    loglevel = ref None ;
    dumps = ref [];
  }


let apply_option (opt:'a ref) (optval:'a option ref) =
  match !optval with
  | None -> ()
  | Some x -> opt := x;;

let apply_arg_options () =
  apply_option ignore_unknown_relocations argv_options.ignore_unknown_relocations;
  apply_option binary argv_options.filepath;
  apply_option ep argv_options.entrypoint;
  apply_option loglevel argv_options.loglevel;
  dumps := !(argv_options.dumps) @ !dumps


let clear_tables () =
  Hashtbl.clear assert_untainted_functions;
  Hashtbl.clear assert_tainted_functions;
  Hashtbl.clear import_tbl;
  Hashtbl.clear reg_override;
  Hashtbl.clear mem_override;
  Hashtbl.clear heap_override;
  memory_content := [];
  heap_content := []

let reset () =
  blackAddresses := SAddresses.empty;
  loglevel := 3;
  unroll := 20;
  fun_unroll := 50;
  kset_bound := 10;
  loglevel := 3;
  max_instruction_size := 16;
  nopAddresses := SAddresses.empty;
  memory_model := Flat;
  architecture := X86;
  endianness := LITTLE;
  analysis := (Forward Bin);
  mode := Protected;
  in_mcfa_file := "";
  out_mcfa_file := "";
  load_mcfa := false;
  store_mcfa := false;
  binary := "";
  format := RAW;
  call_conv := CDECL;
  ep := Z.zero;
  address_sz := 32;
  operand_sz := 32;
  stack_width := 32;
  sections:= [];
  interleave := false;
  memory_content := [];
  heap_content := [];
  register_content := [];
  Hashtbl.reset funSkipTbl;
  Hashtbl.reset module_loglevel;
  Hashtbl.reset reg_override;
  Hashtbl.reset mem_override;
  Hashtbl.reset heap_override;
  Hashtbl.reset gdt;
  Hashtbl.reset import_tbl;
  Hashtbl.reset assert_untainted_functions;
  Hashtbl.reset assert_tainted_functions;
  Hashtbl.reset tainting_rules;
  Hashtbl.reset typing_rules;;

(** returns size of content, rounded to the next multiple of operand_sz *)
let size_of_content c =
  let round_sz sz =
    if sz < !operand_sz then
      !operand_sz
    else
      if sz mod !operand_sz <> 0 then
        !operand_sz * (sz / !operand_sz + 1)
      else
        sz
  in
  match c with
  | Content z | CMask (z, _) -> round_sz (Z.numbits (snd z))
  | Bytes b | Bytes_Mask (b, _) -> (String.length (snd b))*4
