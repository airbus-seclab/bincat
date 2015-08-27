(* nop code at entry point  0x01, offset 0 of the text section from the entry point, size of addresses is 32 bits *)
print_endline "********************************************************";;
  print_endline "\t\t unit test 1";;
    print_endline "********************************************************";;
    let c1 = Main.FlatFixpoint.Code.make "0x90" "0x01" "0x00" 32;;
      print_endline "data structure for the code generated";;
      let icfa, is1 = Main.FlatFixpoint.Cfa.make "0x01";;
	Main.FlatFixpoint.Cfa.print icfa;
    print_endline "\ninitial CFA and state generated";;

    let check _ _ = failwith "Test.check: check the new ip is one byte further and state content before and after are equal";;
   
    let g1, s1 = Main.FlatFixpoint.process c1 icfa is1;;
         print_endline "fixpoint reached";;
  if List.length s1 <> 1 then
    failwith "test 1 has failed"
  else
    OUnit2.assert_equal ~cmp:check is1 (List.hd s1);;
print_endline "SUCCEEDEED";;
