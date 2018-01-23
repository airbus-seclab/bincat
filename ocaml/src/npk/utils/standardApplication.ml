(*
  C2Newspeak: compiles C code into Newspeak. Newspeak is a minimal language 
  well-suited for static analysis.
  Copyright (C) 2007  Charles Hymans, Olivier Levillain
  
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

  Charles Hymans
  EADS Innovation Works - SE/CS
  12, rue Pasteur - BP 76 - 92152 Suresnes Cedex - France
  email: charles.hymans@penjili.org
*)

let report_error error_message =
  invalid_arg error_message

let launch speclist anon_fun usage_msg f =
  try 
    Arg.parse speclist anon_fun usage_msg;
    f()
  with Invalid_argument s -> 
    print_endline ("Fatal error: "^s);
    exit 0

let launch_process_with_npk_argument name speclist process =
  let usage_msg = name^" [options] [-help|--help] file.npk" in
  let input = ref "" in
  let anon_fun file = 
    if !input <> "" then invalid_arg "you can only analyse one file at a time";
    input := file
  in
  let process () = 
    if !input = "" 
  (* TODO: rather than giving this advice => should directly dump help *)
    then report_error ("no file specified. Try "^Sys.argv.(0)^" --help");
    process !input
  in
    launch speclist anon_fun usage_msg process
