(*
    This file is part of BinCAT.
    Copyright 2014-2018 - Airbus Group

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
(* core functionalities of the x86 decoders *)
(***************************************************************************************)

module Lcore = Log.Make(struct let name = "core_x86" end)
open Asm
          

(*************************************************************************)
(* Creation of the general flag registers *)
(*************************************************************************)
let fcf    = Register.make ~name:"cf" ~size:1;;
let fpf    = Register.make ~name:"pf" ~size:1;;
let faf    = Register.make ~name:"af" ~size:1;;
let fzf    = Register.make ~name:"zf" ~size:1;;
let fsf    = Register.make ~name:"sf" ~size:1;;
let _ftf   = Register.make ~name:"tf" ~size:1;;
let fif    = Register.make ~name:"if" ~size:1;;
let fdf    = Register.make ~name:"df" ~size:1;;
let fof    = Register.make ~name:"of" ~size:1;;
let _fiopl = Register.make ~name:"iopl" ~size:2;;
let _fnt   = Register.make ~name:"nt" ~size:1;;
let _frf   = Register.make ~name:"rf" ~size:1;;
let _fvm   = Register.make ~name:"vm" ~size:1;;
let _fac   = Register.make ~name:"ac" ~size:1;;
let _fvif  = Register.make ~name:"vif" ~size:1;;
let _fvip  = Register.make ~name:"vip" ~size:1;;
let _fid   = Register.make ~name:"id" ~size:1;;

let overflow_expression () = Lval (V (T fcf))
