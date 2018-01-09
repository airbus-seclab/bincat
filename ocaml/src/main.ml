(*
    This file is part of BinCAT.
    Copyright 2014-2017 - Airbus Group

    BinCAT is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or (at your
    option) any later version.

    BinCAT is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with BinCAT.  If not, see <http://www.gnu.org/licenses/>.
*)

module L = Log.Make(struct let name = "main" end)

(** Entry points of the library *)

(** [process cfile rfile lfile] launches an analysis run such that:
    - [configfile] is the name of the configuration file
    - [resultfile] is the name of the result file
    - [logfile] is the name of the log file *)
let process (configfile:string) (resultfile:string) (logfile:string): unit =
  (* cleaning global data structures *)
  Config.clear_tables();
  Register.clear();
  Taint.clear();
  Dump.clear();
  (* setting the log file *)
  Log.init logfile;
  L.info (fun m -> m "BinCAT version %s" Bincat_ver.version_string);
  try
    (* setting the backtrace parameters for debugging purpose *)
    Printexc.record_backtrace true;
    let print_exc exc raw_bt =
      Printf.fprintf stdout "%s" (Printexc.to_string exc);
      Printexc.print_raw_backtrace stdout raw_bt
    in
    Printexc.set_uncaught_exception_handler print_exc;

    (* opening the configuration file *)
    let cin =
      try open_in configfile
      with Sys_error _ -> L.abort (fun p -> p "Failed to open the configuration file")
    in
    (* parsing the configuration file to fill configuration information *)
    let lexbuf = Lexing.from_channel cin in
    let string_of_position pos =
      let n = pos.Lexing.lex_curr_p.Lexing.pos_cnum - pos.Lexing.lex_curr_p.Lexing.pos_bol in
      Printf.sprintf "(%d, %d)" pos.Lexing.lex_curr_p.Lexing.pos_lnum n
    in
    begin
      try
        Config.reset ();
        lexbuf.Lexing.lex_curr_p <- { lexbuf.Lexing.lex_curr_p with Lexing.pos_fname = configfile; };
        Parser.process Lexer.token lexbuf
      with
      | Parser.Error ->
         close_in cin;
        L.abort (fun p -> p "Syntax error near location %s of %s" (string_of_position lexbuf) configfile)

      | Failure msg ->
         close_in cin;
        L.abort (fun p -> p "Parse error (%s) near location %s of %s" msg (string_of_position lexbuf) configfile)
    end;
    close_in cin;
  (* generating modules needed for the analysis wrt to the provided configuration *)
    let do_map_file =
      match !Config.format with
      | Config.PE -> L.abort (fun p -> p "PE file format not implemented yet")
      | Config.ELF -> Elf.make_mapped_mem
      | Config.RAW -> Raw.make_mapped_mem
      | Config.MANUAL -> Manual.make_mapped_mem
    in
    Mapped_mem.current_mapping := Some (do_map_file ());
    let module Vector    = Vector.Make(Reduced_bit_tainting) in
    let module Pointer   = Pointer.Make(Vector) in
    let module Domain    = Reduced_unrel_typenv.Make(Pointer) in
    let decoder =
      match !Config.architecture with
      | Config.X86 -> (module X86.Make: Decoder.Make)
      | Config.ARMv7 -> (module Armv7.Make: Decoder.Make)
      | Config.ARMv8 -> (module Armv8A.Make: Decoder.Make)
    in
    let module Decoder = (val decoder: Decoder.Make) in
    let module Interpreter = Interpreter.Make(Domain)(Decoder) in

    (* defining the dump function to provide to the fixpoint engine *)
    let dump cfa = Interpreter.Cfa.print resultfile cfa in

    (* internal function to launch backward/forward analysis from a previous CFA and config *)
    let from_cfa fixpoint =
      let fid = open_in_bin !Config.in_mcfa_file in
      let orig_cfa = Interpreter.Cfa.unmarshal fid in
      Dump.unmarshal fid;
      close_in fid;
      let ep'      = Data.Address.of_int Data.Address.Global !Config.ep !Config.address_sz in
      try
        let prev_s = Interpreter.Cfa.last_addr orig_cfa ep' in
        let d, taint = Interpreter.Cfa.update_abstract_value prev_s.Interpreter.Cfa.State.v in
        prev_s.Interpreter.Cfa.State.back_v <- Some (Domain.meet prev_s.Interpreter.Cfa.State.v d);
        prev_s.Interpreter.Cfa.State.back_taint_sources <- Some taint;
        fixpoint orig_cfa prev_s dump
    with
    | Not_found -> L.abort (fun p -> p "entry point of the analysis not in the given CFA")
    in
    (* launching the right analysis depending on the value of !Config.analysis *)
    let cfa =
      match !Config.analysis with

      (* forward analysis from a binary *)
      | Config.Forward Config.Bin ->
          (* 6: generate code *)
          (* 7: generate the initial cfa with only an initial state *)
         let ep' = Data.Address.of_int Data.Address.Global !Config.ep !Config.address_sz in
         let s = Interpreter.Cfa.init_state ep' in
         let g = Interpreter.Cfa.create () in
         Interpreter.Cfa.add_state g s;
         let cfa =
           match !Mapped_mem.current_mapping with
            | Some mm -> Interpreter.forward_bin mm g s dump
            | None -> L.abort(fun p -> p "File to be analysed not mapped")
          in
          (* launch an interleaving of backward/forward if an inferred property can be backward propagated *)
          if !Config.interleave then
            Interpreter.interleave_from_cfa cfa dump
          else
            cfa

      (* forward analysis from a CFA *)
      | Config.Forward Config.Cfa -> from_cfa Interpreter.forward_cfa

      (* backward analysis from a CFA *)
      | Config.Backward -> from_cfa Interpreter.backward
    in

    (* dumping results *)
    if !Config.store_mcfa = true then
      begin
        let fid = open_out_bin !Config.out_mcfa_file in
        Interpreter.Cfa.marshal fid cfa;
        Dump.marshal fid;
        close_out fid
      end;
    dump cfa;
    Log.close();
  with e ->
    L.exc e (fun p -> p "Exception caught in main loop");
    Log.close ();
    raise e;;

(* enables the process function to be callable from the .so *)
Callback.register "process" process;;
