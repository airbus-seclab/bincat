

type mode_t =
    Protected 

type format_t =
    Pe
  | Elf 

  val operand_sz : int ref
  val address_sz : int ref
  val stack_width: int ref
 
(** Module to set up the model of execution environment *)

module Flat: Data.T
module Segmented: Data.T
