(*
  C2Newspeak: compiles C code into Newspeak. Newspeak is a minimal language 
  well-suited for static analysis.
  Copyright (C) 2007  Charles Hymans, Olivier Levillain, Sarah Zennou
  
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

  Olivier Levillain
  email: olivier.levillain@penjili.org

  Sarah Zennou
  EADS Innovation Works - SE/IS
  12, rue Pasteur - BP 76 - 92152 Suresnes Cedex - France
  email: sarah (dot) zennou (at) eads (dot) net
*)

(* TODO: 
   instead of having all parameters here and having all files depend
   on it, 
   Should have npkcontex at the end that sets the parameters of each file.
   Not necessarily better ! Since some options are the same across several
   different files.
*)

(*----------------------*)
(* Command line options *)
(*----------------------*)

(* Translation options *)
let ignores_asm 	  = ref false
let ignores_extern_fundef = ref false
let ignores_pack 	  = ref false
let ignores_volatile 	  = ref false
let accept_gnuc 	  = ref true
let accept_signed_index   = ref true
let opt_checks 		  = ref true
let accept_forward_goto   = ref true
let accept_goto 	  = ref true
let accept_dirty_syntax   = ref true
let use_strict_syntax 	  = ref false
let accept_dirty_cast 	  = ref true
let ignores_pragmas 	  = ref false
let remove_temp 	  = ref true
let accept_extern 	  = ref true
let accept_flex_array 	  = ref true
let no_opt 		  = ref false
let accept_mult_def 	  = ref true
let typed_npk = ref false
(* TODO: Handle assumptions correctly *)
(* let assumptions = ref [] *)


(* Verbose options *)
let verb_debug 		     = ref false
let verb_ast 		     = ref false
let verb_cir 		     = ref false
let verb_npko 		     = ref false
let verb_newspeak 	     = ref false
let verb_lowspeak 	     = ref false
let accept_transparent_union = ref true

let verbose boolean () =
  verb_ast := boolean;
  verb_debug := boolean;
  verb_newspeak := boolean

let input_files = ref []
let anon_fun file = input_files := file::!input_files
let compile_only = ref false
let output_file = ref ""
let accept_partial_fdecl = ref true
let accept_missing_fdecl = ref true
let xml_output = ref ""
let abi_file = ref ""

type error =
    Asm
  | Pragma
  | Pack
  | Volatile
  | DirtyCast
  | DirtySyntax
  | PartialFunDecl
  | MissingFunDecl
  | ForwardGoto
  | BackwardGoto
  | StrictSyntax
  | ExternGlobal
  | FlexArray
  | MultipleDef
  | GnuC
  | DisableOpt
  | DisableCheckOpt
  | TransparentUnion
  | ExternFunDef
  | SignedIndex

let flag_of_error err =
  match err with
      Asm 	       -> ignores_asm
    | Pragma 	       -> ignores_pragmas
    | Pack 	       -> ignores_pack
    | Volatile 	       -> ignores_volatile
    | DirtyCast        -> accept_dirty_cast
    | DirtySyntax      -> accept_dirty_syntax
    | PartialFunDecl   -> accept_partial_fdecl
    | MissingFunDecl   -> accept_missing_fdecl
    | ForwardGoto      -> accept_forward_goto
    | BackwardGoto     -> accept_goto
    | StrictSyntax     -> use_strict_syntax
    | ExternGlobal     -> accept_extern
    | FlexArray        -> accept_flex_array
    | MultipleDef      -> accept_mult_def
    | GnuC 	       -> accept_gnuc
    | DisableOpt       -> no_opt
    | DisableCheckOpt  -> opt_checks
    | TransparentUnion -> accept_transparent_union
    | ExternFunDef     -> ignores_extern_fundef
    | SignedIndex      -> accept_signed_index
 
let opt_of_flag err =
  match err with
      Asm 	       -> "--ignore-asm"
    | Pragma 	       -> "--ignore-pragma"
    | Pack 	       -> "--ignore-pack"
    | Volatile 	       -> "--ignore-volatile"
    | DirtyCast        -> "--reject-dirty-cast"
    | DirtySyntax      -> "--reject-dirty-syntax"
    | PartialFunDecl   -> "--reject-incomplete-fundecl"
    | MissingFunDecl   -> "--reject-missing-fundecl"
    | ForwardGoto      -> "--reject-goto"
    | BackwardGoto     -> "--reject-backward-goto"
    | StrictSyntax     -> "--use-strict-syntax"
    | ExternGlobal     -> "--reject-extern"
    | FlexArray        -> "--reject-flexible-array"
    | MultipleDef      -> "--reject-mult-def"
    | GnuC 	       -> "--reject-gnuc"
    | DisableOpt       -> "--disable-opt"
    | DisableCheckOpt  -> "--disable-checks-opt"
    | TransparentUnion -> "--reject-transparent-union"
    | ExternFunDef     -> "--ignore-extern-definition"
    | SignedIndex      -> "--reject-signed-index"

(* Version *)

let version = ref false

let clear_gotos () =
  accept_forward_goto := false;
  accept_goto 	      := false

let set_ansi () =
  accept_dirty_cast 	   := false;
  accept_dirty_syntax 	   := false;
  accept_partial_fdecl 	   := false;
  accept_missing_fdecl 	   := false;
  accept_extern 	   := false;
  accept_flex_array 	   := false;
  accept_mult_def 	   := false;
  accept_gnuc 		   := false;
  accept_transparent_union := false;
  accept_signed_index 	   := false

let argslist = [
  ("-c", Arg.Set compile_only,
   "compiles only into a .no file");
  
  ("-o", Arg.Set_string output_file,
   "gives the name of Newspeak output\n");

  ("--typed-npk", Arg.Set typed_npk,
   "compiles to typed npk rather than classical newspeak\n");
  
  (opt_of_flag DirtyCast, Arg.Clear (flag_of_error DirtyCast),
   "rejects casts");

  (opt_of_flag DirtySyntax, Arg.Clear (flag_of_error DirtySyntax),
   "rejects dirty syntax");

  (opt_of_flag PartialFunDecl, Arg.Clear (flag_of_error PartialFunDecl),
   "rejects call to function whose argument type is unknown");

  (opt_of_flag MissingFunDecl, Arg.Clear (flag_of_error MissingFunDecl),
   "rejects call to function whose prototype is not declared");

  (opt_of_flag ForwardGoto, Arg.Unit clear_gotos,
   "rejects goto statements");

  (opt_of_flag BackwardGoto, Arg.Clear  (flag_of_error BackwardGoto), 
   "rejects backward goto statements ");

  (opt_of_flag TransparentUnion, Arg.Clear (flag_of_error TransparentUnion),
   "rejects transparent unions");

  (opt_of_flag ExternGlobal, Arg.Clear (flag_of_error ExternGlobal),
   "accepts variables that are only declared as extern but still used");

  (opt_of_flag FlexArray, Arg.Clear (flag_of_error FlexArray),
   "rejects flexible array members");

  (opt_of_flag MultipleDef, Arg.Clear (flag_of_error MultipleDef),
   "rejects multiple definitions of the same variables");

  (opt_of_flag SignedIndex, Arg.Clear (flag_of_error SignedIndex),
   "rejects signed integer expressions to be used as array indices");

  (opt_of_flag GnuC, Arg.Clear (flag_of_error GnuC),
   "rejects GNU C extensions\n");
  
  (opt_of_flag DisableOpt, Arg.Set (flag_of_error DisableOpt),
   "turn all code simplifications off");

  (opt_of_flag DisableCheckOpt, Arg.Clear (flag_of_error DisableCheckOpt),
   "turn code simplifications that remove checks off");

  ("--disable-vars-elimination", Arg.Clear remove_temp,
   "does not remove unused variables\n");

  (opt_of_flag Pragma, Arg.Set (flag_of_error Pragma),
   "ignores any #pragma directive");

  (opt_of_flag Asm, Arg.Set (flag_of_error Asm),
   "ignores any asm directive");

  (opt_of_flag Pack, Arg.Set (flag_of_error Pack),
   "ignores any packed attribute");

  (opt_of_flag ExternFunDef, Arg.Set (flag_of_error ExternFunDef),
   "ignores the body of extern function definitions");

  (opt_of_flag Volatile, Arg.Set (flag_of_error Volatile),
   "ignores 'volatile' type qualifier\n");
  
  (opt_of_flag StrictSyntax, Arg.Set (flag_of_error StrictSyntax),
   "sets strict syntax");
  
  ("--version", Arg.Set version,
   "prints the version of the software");

  ("-v", Arg.Unit (verbose true),
   "verbose mode: turn all verbose options on");
    
  ("--debug", Arg.Set verb_debug,
   "verbose options: displays more debugging info");

  ("--print-ast", Arg.Set verb_ast,
   "verbose option: displays Abstract Syntax Tree output");

  ("--print-cir", Arg.Set verb_cir,
   "verbose option: displays C Intermediate Representation output");

  ("--print-npko", Arg.Set verb_npko,
   "verbose option: displays Newspeak Object output");

  ("--print-newspeak", Arg.Set verb_newspeak,
   "verbose option: displays Newspeak output");
  
  ("--print-lowspeak", Arg.Set verb_lowspeak,
   "verbose option: displays Lowspeak output");

  ("--xml", Arg.Set_string xml_output,
   "gives the name of XML output file\n");

  ("--ansi", Arg.Unit set_ansi,
   "accept only ANSI C + some common rules in embedded software");

  ("--abi", Arg.Set_string abi_file,
   "gives the name of ABI description file\n");

]

(*-------------------*)
(* Location handling *)
(*-------------------*)

let cur_loc = ref Newspeak.unknown_loc

let set_loc loc = cur_loc := loc
  
let forget_loc () = cur_loc := Newspeak.unknown_loc

let string_of_loc loc = 
  if loc = Newspeak.unknown_loc then "" else (Newspeak.string_of_loc loc)^": "

let get_fname () =
  let (file, _, _) = !cur_loc in 
    file

let get_loc () = !cur_loc



(*----------------------------------------*)
(* Warnings/errors generation and display *)
(*----------------------------------------*)
let xml_warns = ref []

let string_of_err kind where msg =
  let warn = kind^(string_of_loc !cur_loc)^msg in
    if (!verb_debug && where <> "") then warn^" ("^where^")" else warn

let xml_string_of_err msg =
  let regexp = Str.regexp "\"" in
    let msg' = Str.global_replace regexp "&quot;" msg in
  "<warn where=\""^(string_of_loc !cur_loc)^"\" msg=\""^msg'^"\">"^"</warn>\n"

let report_warning where msg =
  if String.compare !xml_output "" <> 0 then
    xml_warns := (xml_string_of_err msg)::!xml_warns;
  prerr_endline (string_of_err "Warning: " where msg)

let string_of_error = string_of_err ""

let print_debug msg =
  if !verb_debug then 
    prerr_endline ("Debug: "^(string_of_loc !cur_loc)^msg)

let print_size sz = print_debug ("Current size: "^(string_of_int sz))

let report_error where msg = 
  StandardApplication.report_error (string_of_error where msg)

let handle_cmdline_options version_string comment_string = 
  let usage_msg =
    version_string ^ "\nUsage: "^
      Sys.argv.(0)^" [options] [-help|--help] [file...]\n" 
  in
    
    Arg.parse argslist anon_fun usage_msg;

    if (not !(flag_of_error PartialFunDecl)) 
    then (flag_of_error MissingFunDecl) := false;

    if !version then begin
      print_endline version_string;
      print_endline comment_string;
      exit 0
    end;
    
    if !input_files = [] then begin
      report_error "C2Newspeak.handle_cmdline_options"
	("no file specified. Try "^Sys.argv.(0)^" --help")
    end;
    
    if (List.length !input_files > 1) && !compile_only 
      && (!output_file <> "") then begin
	report_error "C2Newspeak.handle_cmdline_options" 
	  ("You cannot specify the output filename (-o) for multiple "
	   ^"files when only compiling (-c)")
      end;
    
    if (not !compile_only) && (!output_file = "") then output_file := "a.npk"
      
let report_ignore_warning loc msg err_typ =
  if not !(flag_of_error err_typ) then begin
    let advice = ", rewrite your code or try option "^(opt_of_flag err_typ) in
      report_error loc (msg^" not supported yet"^advice)
  end;
  report_warning loc (msg^" ignored")
    
let report_accept_warning loc msg err_typ =
  if not !(flag_of_error err_typ) then begin
    let advice = 
      ", rewrite your code or remove option "^(opt_of_flag err_typ) 
    in
      report_error loc (msg^advice)
  end;
  report_warning loc (msg^" accepted")

let report_strict_warning msg err =
  if !use_strict_syntax then report_warning msg err

let string_of_options () =
  let add s (c, v) =
    s ^ "<option name=\""^c^"\" val=\""^v^"\"></option>\n"
  in
  let options = ref [("-o", !output_file)] in
  let add_option flag =
    if !(flag_of_error flag) then options := (opt_of_flag flag, "")::!options
  in
    if !compile_only then options := ("-c", "")::!options;
    add_option DirtyCast;
    add_option DirtySyntax;
    add_option PartialFunDecl;
    add_option MissingFunDecl;
    add_option ForwardGoto;
    add_option BackwardGoto;
    add_option TransparentUnion;
    add_option ExternGlobal;
    add_option MultipleDef;
    add_option SignedIndex;
    add_option GnuC;
    add_option DisableOpt;
    add_option DisableCheckOpt;
    if not !remove_temp then options := ("--disable-vars-elimination", "")::!options;
    add_option Pragma;
    add_option Asm;
    add_option Pack;
    add_option ExternFunDef;
    add_option Volatile;
    add_option StrictSyntax;
    if !version then options := ("--version", "")::!options;
    if !verb_ast && !verb_debug && !verb_newspeak then options := ("-v", "")::!options;
    if !verb_debug then options := ("--debug", "")::!options;
    if !verb_ast then options := ("--print-ast", "")::!options;
    if !verb_cir then options := ("--print-cir", "")::!options;
    if !verb_npko then options := ("--print-npko", "")::!options;
    if !verb_newspeak then options := ("--print-newspeak", "")::!options;
    if String.compare !xml_output "" <> 0 then options := ("--xml", !xml_output)::!options;
    List.fold_left add "" !options

let dump_xml_warns () =
  if String.compare !xml_output "" <> 0 then 
    begin
      let xml_cout = 
	open_out_gen [Open_wronly;Open_creat] 0o644 !xml_output
      in
      let header = "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n" in
	output_string xml_cout header;
	output_string xml_cout "<c2newspeak>\n<options>\n";
	output_string xml_cout (string_of_options ());
	output_string xml_cout "</options>\n<warns>\n";
	List.iter (output_string xml_cout) !xml_warns;
	output_string xml_cout "</warns>\n</c2newspeak>\n";
	close_out xml_cout
    end
