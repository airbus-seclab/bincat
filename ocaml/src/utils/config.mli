(** useful information provided by main essentially *)

(** the bound used to know whether a widening has to be set *)
val unroll: int ref

(** memory model *)
type memory_model_t =
  | Flat
  | Segmented

val memory_model: memory_model_t ref

(** file format *)
type format_t =
  | Pe
  | Elf

val format: format_t ref
		     
(** calling convention *)
type call_conv_t =
  | Cdecl
  | Stdcall
  | Fastcall
      
val call_conv: call_conv_t ref
			   
(** content of the text section *)
val text: string ref

(** address of the entry point of the code *)
val ep: string ref

(** starting address of the code *)
val code_addr_start: string ref

(** end address of the code *)
val code_addr_end: string ref

(** address of the beginning of the data *)
val data_addr: string ref

(** address of the beginning of the stack *)
val stack_addr: string ref
		      
(** default address size in bits *)
val address_sz: int ref

(** default operand size in bits *)
val operand_sz: int ref

(** default stack width in bits *)
val stack_width: int ref

(** address of the cs segment *)
val cs: string ref 

(** address of the ds segment *)
val ds: string ref

(** address of the ss segment *)
val ss: string ref

(** address of the es segment *)
val es: string ref 

(** address of the fs segment *)
val fs: string ref 

(** address of the gs segment *)
val gs: string ref


(** tainting kind for function arguments *)
type taint =
  | No_taint
  | Buf_taint
  | Addr_taint

(** type used to store information provided by the configuration file about the tainting rules of a function *)
(** the string is the name of the function *)
(** the calling convention is set either to a specific value or the default one *)
(** the first taint type in the tuple is for the return type (None is for function without return value) ; the second one is for the list of arguments *)
type tainting_fun = string * call_conv_t * taint option * taint list
				   
(** adds the tainting rules of the given function of the given libname *)
val add_tainting_rules: string -> tainting_fun -> unit 

(** type for definition of a mask on values or tainting *)
type value

(** converts a string into a value for register/memory content or taint *)
val make_value: string -> value
			    
(** make_mask v1 v2 returns a value based on the mask of v1 and v2. *)
(** that is returns the value representing the hexadecimal value v1 for which bits given by the hexadecimal value v2 are unknown *)
val make_value_from_mask: string -> string -> value

(** table of initial values for the registers. This table is filled with respect to of the configuration file *)
val initial_register_content: (Register.t, value) Hashtbl.t

(** table of initial tainting for the registers. This table is filled with respect to of the configuration file *)
val initial_register_tainting: (Register.t, value) Hashtbl.t

(** table of initial values for the memory. This table is filled with respect to the configuration file *)
(** the memory address is given as a string *)
val initial_memory_content: (string, value) Hashtbl.t

(** table of initial taintings for the memory. This table is filled with respect to the configuration file *)
(** the memory address is given as a string *)
val initial_memory_tainting: (string, value) Hashtbl.t
