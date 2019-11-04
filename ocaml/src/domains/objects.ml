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

type offset = int
   
type class_t =  {
    allocator: Data.Address.t;
    constructor: Data.Address.t option;
    destructor: Data.Address.t option;
    members: (offset * Types.t) list;
  }
