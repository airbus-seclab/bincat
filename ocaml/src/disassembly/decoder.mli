(*
    This file is part of BinCAT.
    Copyright 2014-2021 - Airbus

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

(***************************************************************************************)
(* common signatures of decoders *)
(***************************************************************************************)


module type T =


sig
  (** control flow graph *)
  module Cfa: Cfa.T
    
  (** data struct for external functions management *)
  module Imports:
  sig


  (** mapping from code addresses to library functions *)
    val tbl: (Data.Address.t, Asm.import_desc_t * Asm.calling_convention_t) Hashtbl.t

    (** returns a function modeling a skip of the given import function wrt to the given calling convention *)
      val skip: (Asm.import_desc_t * Asm.calling_convention_t) option -> Data.Address.t -> Asm.import_desc_t
  end

    (** decoding context *)
    type ctx_t


    (**  [parse text cfg ctx state addr oracle] *)
    val parse: string -> Cfa.t -> ctx_t -> Cfa.State.t -> Data.Address.t -> Cfa.oracle -> (Cfa.State.t * Data.Address.t * ctx_t) option
  (** extract the opcode at address _addr_ in _text_ and translate it as a list of statements.
      This list of statement is added to the list of possible successor of the state _state_ in the control flow graph _cfg_.
      All needed context for the decoder is passed through the context parameter _ctx_ *)

  (** initialize the decoder and returns its initial context *)
    val init: unit -> ctx_t

    (** returns the expression to check whether an overflow occurs *)
    val overflow_expression: unit -> Asm.exp

                                       (** creates registers if not done by default (see x86 and x64 mechanisms) *)
    val init_registers: unit -> (Register.t * Data.Word.t) list 

end


module type Make = functor (D: Domain.T)(Stubs: Stubs.T with type domain_t := D.t)-> 

sig
  (** control flow graph *)
  module Cfa: (Cfa.T with type domain = D.t)
  module Imports:
  sig


  (** mapping from code addresses to library functions *)
    val tbl: (Data.Address.t, Asm.import_desc_t * Asm.calling_convention_t) Hashtbl.t

    (** returns a function modeling a skip of the given import function wrt to the given calling convention *)
      val skip: (Asm.import_desc_t * Asm.calling_convention_t) option -> Data.Address.t -> Asm.import_desc_t
  end

    (** decoding context *)
    type ctx_t


    (**  [parse text cfg ctx state addr oracle] *)
    val parse: string -> Cfa.t -> ctx_t -> Cfa.State.t -> Data.Address.t -> Cfa.oracle -> (Cfa.State.t * Data.Address.t * ctx_t) option
  (** extract the opcode at address _addr_ in _text_ and translate it as a list of statements.
      This list of statement is added to the list of possible successor of the state _state_ in the control flow graph _cfg_.
      All needed context for the decoder is passed through the context parameter _ctx_ *)

  (** initialize the decoder and returns its initial context *)
    val init: unit -> ctx_t

    (** returns the expression to check whether an overflow occurs *)
    val overflow_expression: unit -> Asm.exp

                                       (** creates registers if not done by default (see x86 and x64 mechanisms) *)
    val init_registers: unit -> (Register.t * Data.Word.t) list 

end
