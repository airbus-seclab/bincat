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

Printf.printf "BinCAT %s\n" Bincat_ver.version_string;
flush stdout;

let anon_args = ref [] in

(* parse command line arguments *)
let speclist = [
    "--ignore-unknown-relocations", Arg.Unit (fun () -> Config.argv_options.Config.ignore_unknown_relocations := Some true),
    "Ignore unknown relocations when loading binary instead of aborting" ;
    "--no-state", Arg.Unit (fun () -> Config.argv_options.Config.no_state := Some true),
    "Do not output state in output .ini" ;
    "--filepath", Arg.String (fun arg -> Config.argv_options.Config.filepath := Some arg),
    "Path to file to be analyzed" ;
    "--load-elf-coredump", Arg.String (fun arg -> Config.(argv_options.dumps := arg :: !(argv_options.dumps))),
    "Coredump file to be loaded" ;
    "--entrypoint", Arg.String (fun arg -> Config.argv_options.Config.entrypoint := Some (Z.of_string arg)),
    "Entry point";
    "--loglevel", Arg.Int (fun arg -> Config.argv_options.Config.loglevel := Some arg),
    "Entry point";
  ] in
let usage = "usage: bincat init.ini output.ini outlog" in
Arg.parse speclist (fun x -> anon_args := x :: !anon_args) usage;

match !anon_args with
| logfile::outputfile::configfile::[] ->
   begin
     try
       Main.process configfile outputfile logfile
     with e ->
           Printf.fprintf stderr "EXCEPTION: %s\nCheck log file for details [%s]\n" (Printexc.to_string e) logfile;
           raise e
   end
| _ ->  raise (Arg.Bad (Printf.sprintf "expected 3 arguments. Found %i." (List.length !anon_args)))
