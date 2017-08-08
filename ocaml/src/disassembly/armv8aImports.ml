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

(* TODO: move parts depending on x86 architecture (eax for instance in result) into a subdirectory x86 *)
module Make(D: Domain.T) =
struct
  type fun_type = {
        name: string;
        libname: string;
        prologue: Asm.stmt list;
        stub: Asm.stmt list;
        epilogue: Asm.stmt list;
        ret_addr: Asm.exp;
  }

  let tbl: (Data.Address.t, fun_type) Hashtbl.t = Hashtbl.create 5

  let available_stubs: (string, unit) Hashtbl.t = Hashtbl.create 5

  exception Found of (Data.Address.t * fun_type)
  let search_by_name (_fun_name: string): (Data.Address.t * fun_type) = raise Not_found
end
