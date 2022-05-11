(*
    This file is part of BinCAT.
    Copyright 2014-2022 - Airbus

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

(** internal auxilliary functor to setup the environment before lauching the interpreter itself *) 
module IEnv(Stubs: Stubs.T) = struct

  type import_attrib_t = {
      mutable ia_name: string;
      mutable ia_addr: Z.t option;
      mutable ia_typing_rule: bool;
      mutable ia_tainting_rule: bool;
      mutable ia_stub: bool;
    }

  let dump () =
    let empty_desc = {
        ia_name = "n/a";
        ia_addr = None;
        ia_typing_rule = false;
        ia_tainting_rule = false;
        ia_stub = false;
      }
    in
    let yesno b = if b then "YES" else "no" in
    let itbl = Hashtbl.create 5 in
    Hashtbl.iter (fun a (libname, fname) ->
        let func_desc = { empty_desc with
                          ia_name = libname ^ "." ^ fname;
                          ia_addr = Some a;
                        }
        in
        Hashtbl.add itbl fname func_desc) Config.import_tbl;
    Hashtbl.iter (fun name _typing_rule ->
        let func_desc =
          try
            Hashtbl.find itbl name
          with Not_found -> { empty_desc with ia_name = "?." ^ name } in
        Hashtbl.replace itbl name { func_desc with ia_typing_rule=true })  Config.typing_rules;
    Hashtbl.iter (fun  (libname, name) (_callconv, _taint_ret, _taint_args) ->
        let func_desc =
          try
            Hashtbl.find itbl name
          with Not_found -> { empty_desc with ia_name = libname ^ "." ^ name } in
        Hashtbl.replace itbl name { func_desc with ia_tainting_rule=true })  Config.tainting_rules;
    Hashtbl.iter (fun name _ ->
        let func_desc =
          try
            Hashtbl.find itbl name
          with Not_found -> { empty_desc with ia_name = "?." ^ name } in
        Hashtbl.replace itbl name { func_desc with ia_stub=true })  Stubs.stubs;
    
    let addr_to_str x = match x with
      | Some a ->
         begin (* too bad we can't format "%%0%ix" to make a new format *)
           match !Config.address_sz with
           | 16 -> Printf.sprintf "%04x" (Z.to_int a)
           | 32 -> Printf.sprintf "%08x" (Z.to_int a)
           | 64 -> Printf.sprintf "%016x" (Z.to_int a)
           | _ ->  Printf.sprintf "%x" (Z.to_int a)
         end
      | None -> "?"
    in
    L.info (fun p -> p "Dumping state of imports");
    Hashtbl.iter (fun _name func_desc ->
        L.info (fun p -> p "| IMPORT %-30s addr=%-16s typing=%-3s tainting=%-3s stub=%-3s"
                           func_desc.ia_name (addr_to_str func_desc.ia_addr)
                           (yesno func_desc.ia_typing_rule) (yesno func_desc.ia_tainting_rule) (yesno func_desc.ia_stub)))
      itbl;
      L.info (fun p -> p "End of dump")
      
  let mapped_infos () =
    let do_map_file =
      match !Config.format with
      | Config.PE -> L.abort (fun p -> p "PE file format not implemented yet")
      | Config.ELF | Config.ELFOBJ -> Elf.make_mapped_mem
      | Config.RAW -> Raw.make_mapped_mem
      | Config.MANUAL -> Manual.make_mapped_mem
    in
    let exe_map = do_map_file !Config.binary (Data.Address.global_of_int !Config.ep) in
    let complete_map = Elf_coredump.add_coredumps exe_map !Config.dumps in
    Mapped_mem.current_mapping := Some complete_map;
    if L.log_info2 () then
      begin
        L.info2(fun p -> p "-- Dump of mapped sections");
        List.iter
          (fun sec ->
            L.info2 (
                fun p -> p "Mapped section vaddr=%s-%s (0x%s bytes) paddr=%s->%s (0x%s bytes) %-15s %s"
                           (Log.zaddr_to_string (Data.Address.to_int sec.Mapped_mem.virt_addr))
                           (Log.zaddr_to_string (Data.Address.to_int sec.Mapped_mem.virt_addr_end))
                           (Log.zaddr_to_string sec.Mapped_mem.virt_size)
                           (Log.zaddr_to_string sec.Mapped_mem.raw_addr)
                           (Log.zaddr_to_string sec.Mapped_mem.raw_addr_end)
                           (Log.zaddr_to_string sec.Mapped_mem.raw_size)
                           sec.Mapped_mem.name
                           sec.Mapped_mem.mapped_file_name))
          complete_map.Mapped_mem.sections;
        L.info2(fun p -> p "-- End of mapped sections dump")
        end
    
end
                           

                           
(** [process cfile rfile lfile] launches an analysis run such that:
    - [configfile] is the name of the configuration file
    - [resultfile] is the name of the result file
    - [logfile] is the name of the log file *)
let process (configfile:string) (resultfile:string) (logfile:string): unit =
  (* cleaning global data structures *)
  Config.clear_tables();
  Taint.clear();
  Dump.clear();
  Register.clear();
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
    L._loglvl := None; (* reset log level to use the one from configuration file *)

    (* override config with arguments from command line *)
    Config.apply_arg_options();

    

    (* generating modules needed for the analysis wrt to the provided configuration *)
    
    let module Vector    = Vector.Make(Reduced_bit_tainting) in
    let module Pointer   = Pointer.Make(Vector) in
    let module Domain   = Reduced_unrel_typenv_heap.Make(Pointer) in
   
    let decoder =
      match !Config.architecture with
      | Config.X86 -> (module Core_x86.Make(Core_x86.X86): Decoder.Make)
      | Config.X64 -> (module Core_x86.Make(Core_x86.X64): Decoder.Make)
      | Config.ARMv7 -> (module Armv7.Make: Decoder.Make)
      | Config.ARMv8 -> (module Armv8A.Make: Decoder.Make)
      | Config.POWERPC -> (module Powerpc.Make(Powerpc.PPC): Decoder.Make)
      | Config.POWERPC64 -> (module Powerpc.Make(Powerpc.PPC64): Decoder.Make)
      | Config.RV32I -> (module Risc_v.Make(Risc_v.I32): Decoder.Make)
      | Config.RV64I -> (module Risc_v.Make(Risc_v.I64): Decoder.Make) 
    in
    let module Decoder = (val decoder: Decoder.Make) in
    let module Stubs = Stubs.Make(Domain) in
    let module Interpreter = Interpreter.Make(Domain)(Decoder)(Stubs) in
    let module IEnv = IEnv(Stubs) in

    IEnv.mapped_infos();
    IEnv.dump();
    (* defining the dump function to provide to the fixpoint engine *)
    let dump cfa = Interpreter.Cfa.print resultfile cfa in

    (* internal function to launch backward/forward analysis from a previous CFA and config *)
    let from_cfa fixpoint =
      let fid = open_in_bin !Config.in_mcfa_file in
      let orig_cfa = Interpreter.Cfa.unmarshal fid in
      Dump.unmarshal fid;
      close_in fid;
      let ep' = Data.Address.of_int Data.Address.Global !Config.ep !Config.address_sz in
      try
        let prev_s = Interpreter.Cfa.last_addr orig_cfa ep' in
        let d, taint = Interpreter.Cfa.update_abstract_value ep' prev_s.Interpreter.Cfa.State.v in
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
         let init_reg = Interpreter.make_registers() in
         let s = Interpreter.Cfa.init_state ep' init_reg Stubs.default_handler in
         let g = Interpreter.Cfa.create () in
         Interpreter.Cfa.add_state g s;
         let cfa =
           match !Mapped_mem.current_mapping with
            | Some mm -> Interpreter.Forward.from_bin mm g s dump
            | None -> L.abort(fun p -> p "File to be analysed not mapped")
          in
          (* launch an interleaving of backward/forward if an inferred property can be backward propagated *)
          if !Config.interleave then
            Interpreter.interleave_from_cfa cfa dump
          else
            cfa

      (* forward analysis from a CFA *)
      | Config.Forward Config.Cfa -> from_cfa Interpreter.Forward.from_cfa

      (* backward analysis from a CFA *)
      | Config.Backward -> from_cfa Interpreter.Backward.from_cfa
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
