type mode_t =
    Protected 

type format_t =
    Pe
  | Elf 

  type segment_t = {
    mutable cs: int;
    mutable ds: int;
    mutable ss: int;
    mutable es: int;
    mutable fs: int;
    mutable gs: int;
  }

  val operand_sz : int ref
  val address_sz : int ref
  val stack_width: int ref
  val segments	 : segment_t

(** Module to set up the model of execution environment *)

module Flat: Data.T
module Segmented: Data.T
