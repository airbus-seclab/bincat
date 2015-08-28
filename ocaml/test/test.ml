(* nop code at entry point  0x01, offset 0 of the text section from the entry point, size of addresses is 32 bits *)
print_endline "********************************************************";;
  print_endline "\t\t unit test 1";;
    print_endline "********************************************************";;
      print_endline "-> data generation";;
    let c1 = Main.FlatFixpoint.Code.make "\x90" "\x23" "\x00" 32 in
	let icfa, is1 = Main.FlatFixpoint.Cfa.make "\x23" in
	let check_test1 s s' =
	  (* first check that the new ip is one byte further *)
	  let o = Main.FlatFixpoint.Address.sub (Main.FlatFixpoint.Cfa.State.ip s') (Main.FlatFixpoint.Cfa.State.ip s) in
	  if Main.FlatFixpoint.Offset.compare o Main.FlatFixpoint.Offset.one = 0 then 
	      (* check that domain fields are equal *)
	      failwith "Domain.equal s.v s'.v"
	  else
	    false
	in
	print_endline "-> fixpoint computation";
	let g1, s1 = Main.FlatFixpoint.process c1 icfa is1 in
	Main.FlatFixpoint.Cfa.print g1 "test1.dot";
	print_endline "-> unit test launching";
	if List.length s1 <> 1 then
	  failwith "test 1 has failed"
	else
	  OUnit2.assert_equal ~cmp:check_test1 is1 (List.hd s1);
	print_endline "SUCCEEDEED";;
