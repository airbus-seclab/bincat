(* creation of the initial Control Flow Automaton *)
let icfa = Main.FlatFixpoint.Cfa.make();;
			
(* nop code at entry point  0x01, offset 0 of the text section from the entry point, size of addresses is 32 bits *)
  print_endline "********************************************************";;
    print_endline "\t\t unit test 1";;
  print_endline "********************************************************";;
let c1 = Main.FlatFixpoint.Code.make "0x90" "0x01" "0x00" 32;;
  print_endline "code generated..........................................";;
  let is1 = Main.FlatFixpoint.Cfa.dummy_state "0x01";;
    print_endline "corresponding initial state generated...................";;

    let check _ _ = true;;
   
    let g1, s1 = Main.FlatFixpoint.process c1 icfa is1;;
         print_endline "fixpoint reached.................................";;
  if List.length s1 <> 1 then
    failwith "test 1 has failed"
  else
    OUnit2.assert_equal ~cmp:check is1 (List.hd s1);;
print_endline "SUCCEEDEED...............";;
