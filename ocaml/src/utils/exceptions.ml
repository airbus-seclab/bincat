(*
    This file is part of BinCAT.
    Copyright 2014-2019 - Airbus 

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

(** any kind of alarm raised by any domain *)
type analysis_kind =
  | Illegal_address (** the address to compute has an unexpected format *)
  | Empty of string (** an abstract operation produces an empty value *)
  | Too_many_concrete_elements of string (** raised when a concretization computes a too large result *)
  | Bot_deref (** raised when an undefine dereference occurs *)
  | Use_after_free of string (** the string is the address on which the use after free occurs *)
  | Heap_out_of_bounds of string (** the string is the address on which the out of bound in heap occurs *)
  | Undefined_free of string (** call to a deallocator is undefined (pointer does not point on the heap, or the pointed address is not the basis of an allocation, etc. *)
  | Double_free (** double free exception *)
  | Null_deref of string (** NULL dereference *)
  | Stack of string (** Stack errors *)
  | Stop of string (** stops analysis *)
  | DivByZero (** division by zero *)

exception Analysis of analysis_kind

let string_of_analysis a =
  match a with
  | Illegal_address -> "use of illegal address"
  | Empty msg -> "empty concretization: "^msg
  | Too_many_concrete_elements msg -> "concretization is too large: "^msg
  | Bot_deref -> "tried to dereference a bottom value"
  | Use_after_free msg -> "use after free detected: "^msg
  | Heap_out_of_bounds msg ->"heap out of bound detected: "^msg
  | Undefined_free msg -> "undefined free detected: "^msg
  | Double_free -> "double free detected"
  | Null_deref msg -> "tried to dereference a NULL value: "^msg
  | Stack msg -> "stack manipulation error: "^msg
  | Stop msg -> "analysis stops for the current context: "^msg
  | DivByZero -> "division by zero"
              
(** raised when an unexpected behavior happens (undefined decoding, etc.) *)
exception Error of string
