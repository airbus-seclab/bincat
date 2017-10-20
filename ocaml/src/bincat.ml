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
if (Array.length Sys.argv < 4) then
        print_endline "Usage: bincat init.ini output.ini outlog"
else
  try
    Main.process Sys.argv.(1) Sys.argv.(2) Sys.argv.(3)
  with e ->
      Printf.fprintf stderr "EXCEPTION: %s\nCheck log file for details [%s]\n" (Printexc.to_string e) Sys.argv.(3);
      raise e

