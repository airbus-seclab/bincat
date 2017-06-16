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

(***************************************************************************************)
(* common signatures of decoders *)
(***************************************************************************************)
  
module type Make = functor (D: Domain.T) ->
sig
  module Cfa: (Cfa.T with type Dom.t = D.t)
    (**  [parse text cfg is state addr ctx] *)
    val parse: string -> Cfa.t -> Cfa.State.t -> Data.Address.t -> Cfa.State.t list
  (** extract the opcode at address _addr_ in _text_ and translate it as a list of statements. 
      This list of statement is added to the list of possible successor of the state _state_ in the control flow graph _cfg_. 
      All needed context for the decoder is passed through the context parameter _ctx_ *)
  end
