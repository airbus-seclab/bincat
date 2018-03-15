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

(* loader for raw executables without structure *)

module L = Log.Make(struct let name = "raw" end)

open Mapped_mem


let make_mapped_mem filepath entrypoint =
  let mapped_file = map_file filepath in
  let stat = Unix.stat !Config.binary in
  let file_length = Z.of_int stat.Unix.st_size in
  let zero = Z.of_int 0 in
  let section = {
    mapped_file = mapped_file ;
    mapped_file_name = filepath ;
    virt_addr = Data.Address.of_int Data.Address.Global zero !Config.address_sz ;
    virt_addr_end = Data.Address.of_int Data.Address.Global file_length !Config.address_sz ;
    virt_size = file_length ;
    raw_addr = zero ;
    raw_addr_end = file_length ;
    raw_size = file_length ;
    name = Filename.basename filepath
  } in
  {
    sections  = [ section ] ;
    entrypoint = entrypoint ;
  }
