(** abstract domain to model an abstract environment for type reconstruction
    ie a Map from Memory -> Typing.t *)


type t = 
  | BOT (** bottom *)
  | Val of Typing.t Env.t (** a map from Memory/Reg to a type *)

let init () = Val (Env.empty)

let bot = BOT

let join env1 env2 =
  match env1, env2 with
  | BOT, env | env, BOT -> env
  | Val _env1', Val _env2' -> Val (Env.empty)

let widen = join
  
let meet  env1 env2 =
  match env1, env2 with
  | BOT, _ | _, BOT -> BOT
  | Val _env1', Val _env2' -> Val (Env.empty)
      
let forget env =
  match env with
  | BOT -> BOT
  | Val env' -> Val (Env.map (fun _ -> Typing.TUnknown) env')

  
     
let subset env1 env2 =
  match env1, env2 with
  | BOT, _ -> true
  | _, BOT -> false
  | Val env1', Val env2' ->
     try
       Env.iteri (fun k v2 ->
	 try
	   let v1 = Env.find k env1' in
	   if not (Typing.leq v1 v2) then
	     raise Exit
	 with Not_found -> if v2 = Typing.TUnknown then () else raise Exit
       ) env2';
       true
     with Exit -> false

let add_register r env =
  match env with
  | BOT -> BOT
  | Val env' -> Val (Env.add (Env.Key.Reg r) Typing.TUnknown env')
     
let remove_register r env =
  match env with
  | BOT -> BOT
  | Val env' -> Val (Env.remove (Env.Key.Reg r) env')

let remove_addresses addrs env =
  match env with
  | BOT -> BOT
  | Val env' ->
     Val (List.fold_left (fun env a -> Env.remove (Env.Key.Mem a) env) env' (Data.Address.Set.elements addrs))

(*let set_register_type r env =*)
