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

module type T =
sig
  type domain_t

  (** [process d fun args] applies to the abstract value [d] the tranfer function corresponding to the call to the function library named [fun] with arguments [args].
It returns also a boolean true whenever the result is tainted. *)
  val process : domain_t -> string -> Asm.calling_convention_t ->
    domain_t * Taint.t * Asm.stmt list

  val init : unit -> unit

  val stubs : (string, (domain_t -> Asm.lval -> (int -> Asm.lval) ->
                         domain_t * Taint.t) * int) Hashtbl.t
end

(** functor to generate transfer functions on the given abstract value that simulates the behavior of common library functions *)

module Make: functor (D: Domain.T) -> (T with type domain_t := D.t)
