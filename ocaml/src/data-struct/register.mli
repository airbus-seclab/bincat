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

(** Module for registers *)

(** type of a register *)
type t

(** returns the set of current used registers *)
val used: unit -> t list

(** creates a register from the given string and size
May raise Invalid_argument if a register with that name already exists
or is a reserved name f *)
val make: name:string -> size:int -> t

(** creates a stack pointer register from the given string and size *)
val make_sp: name:string -> size:int -> t

(** returns a fresh register name *)
val fresh_name: unit -> string

(** remove the given register from the set of used registers *)
val remove: t -> unit

(** returns the name of the given register *)
val name: t -> string

(** equality *)
val equal: t -> t -> bool

(** comparison *)
val compare: t -> t -> int

(** returns the size in bits of the register *)
val size: t -> int

(** returns the register corresponding to the given name *)
val of_name: string -> t

(** returns true whenever the given register is the stack pointer
  false otherwise *)
val is_stack_pointer: t -> bool

(** returns the stack pointer
  may raise Not found
    randomly chosen if several registers have been taged as stack pointer *)
val stack_pointer: unit -> t

(** empty global references *)
val clear: unit -> unit
