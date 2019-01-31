type stack_frame =
  { start_address: Z.t;
    current_address: Z.t
  }

type t = stack_frame list (* stack of stack frames *)

let add_stack_frame d dst src =
  
  
