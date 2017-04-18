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

(** Abstract Data Type for the code *)
    type t
	   
    (** constructor:
	- code is the byte sequence of instructions to decode
	- rva is the virtual address of the start of the code
	- ep is the virtual address of the entry point *)
    val make: code:string -> rva:Z.t -> ep:Z.t -> t
									      
				     
    (** returns the sub sequence starting at the given address.
    May raise an exception if the given address is out of range *)
    val sub: t -> Data.Address.t -> string
				   

    (** string conversion *)
    val to_string: t -> string
