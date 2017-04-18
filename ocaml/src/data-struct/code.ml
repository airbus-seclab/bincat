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

(**************************************************************************************************************************)
(* Code module *)
(**************************************************************************************************************************)
type t = {
    rva: Z.t;   (** virtual address of the beginning of the code *)
    e: Z.t;    (** entry point, i.e. offset from the rva *)
    c: string; (** the byte sequence containing the code *)	       
  }
			   
let make ~code ~rva ~ep =
  {
    rva = rva;
    e 	= ep;
    c 	= code;
  }
    
    
let sub v a =
  try
    let o   = Z.to_int (Z.sub (Data.Address.to_int a) v.rva) in
    let len = (String.length v.c) - o         		     in
    String.sub v.c o len 
  with _ ->  raise (Exceptions.Error (Printf.sprintf "Illegal address of code %s" (Data.Address.to_string a)))
		   
let to_string c =
  let s = ref "" in
  for i = ((String.length c.c) -1) downto 0 do
    s := (Printf.sprintf "\\x%X" (Char.code (String.get c.c i))) ^ !s
  done;
  Printf.sprintf "entry point:\t %s\ntext:\t        %s" (Data.Word.to_string (Data.Word.of_int c.e !Config.address_sz)) !s
