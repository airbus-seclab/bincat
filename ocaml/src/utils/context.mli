(** useful information provided by main essentially *)

(** the bound used to know whether a widening has to be set *)
val unroll: int ref

(** memory model *)
type memory_model_t =
  | Flat
  | Segmented

val memory_model: memory_model_t ref

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

(** address of the beginning of the code *)
val text_addr: string ref

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
