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

(** abstract domain to model an abstract environment for type reconstruction
    ie a Map from Memory -> Types.t *)


 type t =
   | BOT (** bottom *)
   | Val of Types.t Env.t (** a map from Memory/Reg to a type. Be careful: a key not in the Env map means a TOP value ! *)

 let init () = Val (Env.empty)

 let is_bot m = m = BOT
     
 let top = Val (Env.empty)

 let join env1 env2 =
   match env1, env2 with
   | BOT, env | env, BOT -> env
   | Val env1', Val env2' -> Val (Env.join Types.join env1' env2')

 let widen = join

 let meet env1 env2 =
   match env1, env2 with
   | BOT, env | env, BOT -> env
   | Val env1', Val env2' -> try Val (Env.join Types.meet env1' env2') with _ -> BOT


 let forget env =
   match env with
   | BOT -> BOT
   | Val _ -> Val (Env.empty)

 let is_subset env1 env2 =
   match env1, env2 with
   | BOT, _ -> true
   | _, BOT -> false
   | Val env1', Val env2' ->
      try
        Env.iteri (fun k v2 ->
      try
        let v1 = Env.find k env1' in
       if not (Types.is_subset v1 v2) then
         raise Exit
      with Not_found -> if v2 = Types.UNKNOWN then () else raise Exit
        ) env2';
    true
      with Exit -> false

let add_register _r env = env

let remove_register r env =
  match env with
  | BOT -> BOT
  | Val env' -> try Val (Env.remove (Env.Key.Reg r) env') with Not_found -> env

let remove_addresses addrs env =
  match env with
  | BOT -> BOT
  | Val env' ->
     Val (List.fold_left (fun env a -> try Env.remove (Env.Key.Mem a) env with Not_found -> env) env' (Data.Address.Set.elements addrs))

let to_string env =
  match env with
  | BOT -> ["_"]
  | Val env' ->
     Env.fold (
       fun key typ acc ->
     let styp = Types.to_string typ in
     ("T-"^(Env.Key.to_string key)^"="^styp)::acc
     ) env' []

let string_of_register env r =
  match env with
    | BOT -> raise (Exceptions.Empty (Printf.sprintf "typenv.string_of_register: environment is empty ; can't look up register %s" (Register.name r)))
    | Val env' -> try Types.to_string (Env.find (Env.Key.Reg r) env') with Not_found -> ""

let set_register reg typ env =
  match env with
  | BOT -> BOT
  | Val env' -> Val (Env.add (Env.Key.Reg reg) typ env')

let set_address a typ env =
  match env with
  | BOT -> BOT
  | Val env' -> Val (Env.add (Env.Key.Mem a) typ env')

let forget_register r env =
  match env with
  | BOT -> BOT
  | Val env' -> Val (Env.remove (Env.Key.Reg r) env')

let forget_address (a: Data.Address.t) env =
   match env with
  | BOT -> BOT
  | Val env' -> Val (Env.remove (Env.Key.Mem a) env')


let of_key (k: Env.Key.t) (env: t): Types.t =
  match env with
  | BOT -> raise (Exceptions.Empty "typenv.of_key: environment is empty")
  | Val env' ->
     try Env.find k env'
     with Not_found -> Types.UNKNOWN




