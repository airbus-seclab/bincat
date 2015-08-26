(* test 1 : 
   - flat memory model
   - elf
   - segments = 0
   - text = nop
   - address of the entry point = 0
   - offset from the entry point to start decoding with *)


let identity v = 
;;

  OUnit2.assert_equal ~:cmp:identity (Cfa.current_state i_cfa) (Cfa.current_state f_cfa);;
  
