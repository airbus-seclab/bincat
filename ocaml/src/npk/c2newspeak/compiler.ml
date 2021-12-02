(*
  C2Newspeak: compiles C code into Newspeak. Newspeak is a minimal language 
  well-suited for static analysis.
  Copyright (C) 2007, 2011  Charles Hymans, Olivier Levillain, Sarah Zennou
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.
  
  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.
  
  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

  Sarah Zennou
  sarah(dot)zennou(at)eads(dot)net
*)

let process lexer_name lexbuf =
  NpkLexer.init lexer_name lexbuf;
  Synthack.init_tbls ();
  try NpkParser.parse NpkLexer.token lexbuf
  with NpkParser.Error ->
    let src_file = "Compiler.parse" in
    let lexeme 	 = Lexing.lexeme lexbuf in
    let msg 	 = "syntax error: unexpected token: "^lexeme in
    let advice 	 = ", please check code validity" in
    let pos 	 = Lexing.lexeme_start_p lexbuf in
    let loc 	 = 
      (pos.Lexing.pos_fname, pos.Lexing.pos_lnum, 
       pos.Lexing.pos_cnum-pos.Lexing.pos_bol) 
    in
      Npkcontext.set_loc loc;
      if (not !Npkcontext.accept_gnuc)
      then Npkcontext.report_accept_warning src_file msg Npkcontext.GnuC;
      Npkcontext.report_error src_file (msg^advice)

let parse_file fname =
  let cin = open_in fname in
  let lexbuf = Lexing.from_channel cin in
  let prog = process fname lexbuf in
    close_in cin;
    prog

let append_gnu_symbols globals =
  if not !Npkcontext.accept_gnuc then globals
  else begin
    let lexbuf = Lexing.from_string Gnuc.builtins in
    let gnuc_symbols = process "__gnuc_builtin_symbols" lexbuf in
      gnuc_symbols@globals
  end

let parse fname = 
  Npkcontext.print_debug ("Parsing "^fname^"...");
  let prog = parse_file fname in
  let prog = append_gnu_symbols prog in
    Npkcontext.forget_loc ();
    (fname, prog)

let bare2C (fname, prog) = 
  let prog = Bare2C.process prog in
    Npkcontext.forget_loc ();
    Npkcontext.print_size (Csyntax.size_of prog);
    Npkcontext.forget_loc ();
    Npkcontext.print_debug "Parsing done.";
    if !Npkcontext.verb_ast then Csyntax.print prog;
    (fname, prog)

let remove_gotos (fname, prog) = 
  if not !Npkcontext.accept_goto then (fname, prog)
  else begin
    Npkcontext.print_debug "Running goto elimination...";
    let prog = GotoElimination.run prog in
      Npkcontext.print_debug "Goto elimination done.";
      Npkcontext.print_size (Csyntax.size_of prog);
      (fname, prog)
  end

let add_types prog = 
  Npkcontext.print_debug "Typing...";
  Csyntax2TypedC.process prog

let translate_typedC2cir prog =
  Npkcontext.print_debug "Running first pass...";
  let prog = TypedC2Cir.translate prog in
    Npkcontext.forget_loc ();
    Npkcontext.print_debug "First pass done.";
    Npkcontext.print_size (Cir.size_of prog);
    if !Npkcontext.verb_cir then Cir.print prog;
    prog

let translate_cir2npkil prog =
  Npkcontext.print_debug ("Translating...");
  let prog = Cir2npkil.translate Newspeak.C prog in
    Npkcontext.forget_loc ();
    Npkcontext.print_debug ("Translation done.");
    prog

let compile fname =
  let prog = parse fname	       in
  let prog = bare2C prog	       in
  let prog = remove_gotos prog	       in
  let prog = add_types prog	       in
  let prog = translate_typedC2cir prog in
    translate_cir2npkil prog

let to_typedC fname =
  let prog = parse fname in
  let prog = bare2C prog in
  add_types prog
