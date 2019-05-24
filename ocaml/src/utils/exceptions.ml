(*
    This file is part of BinCAT.
    Copyright 2014-2018 - Airbus 

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

(** raised when the address to compute has an unexpected format *)
exception Illegal_address

(** raised when an abstract operation produces an empty value *)
exception Empty of string

(** raised when a concretization computes a too large result *)
exception Too_many_concrete_elements of string

(** raised when an unexpected behavior happens (undefined decoding, etc.) *)
exception Error of string

(** raised when an undefine dereference occurs *)
exception Bot_deref

(** the string is the address on which the use after free occurs *)
exception Use_after_free of string

(** the string is the address on which the out of bound in heap occurs *)
exception Heap_out_of_bounds of string

(** call to a deallocator is undefined (pointer does not point on the heap, or the pointed address is not the basis of an allocation, etc. *)
exception Undefined_free of string

(** double free exception *)
exception Double_free

(** NULL dereference *)
exception Null_deref of string

(** stop the analysis for the current context *)
exception Stop of string
