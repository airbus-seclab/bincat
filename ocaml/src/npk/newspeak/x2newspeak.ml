let set_config () =
  let fname = !Npkcontext.abi_file in
  if fname <> "" then
    begin
      let cin = open_in fname in
      let lexbuf = Lexing.from_channel cin in
      Abilexer.init fname lexbuf;
      try Abiparser.parse Abilexer.token lexbuf
      with Parsing.Parse_error -> 
        let src_file = "Abiparser.parse" in
        let lexeme   = Lexing.lexeme lexbuf in
        let msg      = "syntax error: unexpected token: "^lexeme in
        let pos      = Lexing.lexeme_start_p lexbuf in
        let loc      = 
          (pos.Lexing.pos_fname, pos.Lexing.pos_lnum, 
           pos.Lexing.pos_cnum-pos.Lexing.pos_bol) 
        in
          Npkcontext.set_loc loc;
          Npkcontext.report_error src_file msg

    end

(* TODO: should have a structure with the version and comment string 
   instead *)
let process version_string comment_string execute =
  try
    Npkcontext.handle_cmdline_options version_string comment_string;
    set_config ();
    execute () ()
  with Invalid_argument msg ->
    prerr_endline ("Fatal error: "^msg);
    exit 1
