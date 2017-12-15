(*
  C2Newspeak: compiles C code into Newspeak. Newspeak is a minimal language 
  well-suited for static analysis.
  Copyright (C) 2007  Charles Hymans, Olivier Levillain
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.
  
  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.
  
  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

  Charles Hymans
  EADS Innovation Works - SE/CS
  12, rue Pasteur - BP 76 - 92152 Suresnes Cedex - France
  email: charles.hymans@penjili.org
*)

open BareSyntax

module Set = Set.Make(String)

(** TODO: remove these globals, by putting them as argument of the lexer ??
    and then passing them through the tokens *)
(* TODO: try to remove this syntactic hack by rewriting the parser,
   but is it even possible? *)
let typedefs = ref Set.empty

let add_type x = typedefs := Set.add x !typedefs

(* TODO: not nice, try to remove this init_tbl!!! and the global typedefs *)
let init_tbls () =
  typedefs := Set.empty;
(* initialize table of predefined types *)
(* GNU C predefined types *)
(* TODO: clean up put in gnuc.ml and think about architecture *)
  if !Npkcontext.accept_gnuc then add_type "_Bool"

let is_type x = Set.mem x !typedefs

let rec normalize_var_modifier (_, v) =
  match v with
      Abstract -> None
    | Variable (x, _) -> Some x
    | Function (v, _) | Array (v, _) -> normalize_var_modifier v

and normalize_decl (_, v) = normalize_var_modifier v

let declare_new_type x = 
  let x = normalize_var_modifier x in
    match x with
	None -> ()
      | Some x -> add_type x
