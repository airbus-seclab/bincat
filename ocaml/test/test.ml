open OUnit2;;

(* test 1 : 
   - flat memory model
   - elf
   - segments = 0
   - text = nop
   - address of the entry point = 0
   - offset from the entry point to start decoding with *)
let snop =
  Main.process_elf true (Array.make 6 0) 32 (String.make 1 '\x90') (String.make 1 '\x00') (String.make 1 '\x00')
    in
  Ounit2.assert_equal cmp=equal_state (State.make()) snop
