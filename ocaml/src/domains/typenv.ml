(** abstract domain to model an abstract environment for type reconstruction
    ie a Map from Memory -> Types.t *)


type t = 
  | BOT (** bottom *)
  | Val of Types.t Env.t (** a map from Memory/Reg to a type *)

let init () = Val (Env.empty)

let bot = BOT

let join env1 env2 =
  match env1, env2 with
  | BOT, env | env, BOT -> env
  | Val env1', Val env2' -> Val (Env.join Types.join env1' env2')

let widen = join
  
let meet  env1 env2 =
  match env1, env2 with
  | BOT, _ | _, BOT -> BOT
  | Val _env1', Val _env2' -> Val (Env.empty)
      
let forget env =
  match env with
  | BOT -> BOT
  | Val env' -> Val (Env.map (fun _ -> Types.TUnknown) env')
  
let subset env1 env2 =
  match env1, env2 with
  | BOT, _ -> true
  | _, BOT -> false
  | Val env1', Val env2' ->
     try
       Env.iteri (fun k v2 ->
	 try
	   let v1 = Env.find k env1' in
	   if not (Types.leq v1 v2) then
	     raise Exit
	 with Not_found -> if v2 = Types.TUnknown then () else raise Exit
       ) env2';
       true
     with Exit -> false

let add_register _r env = env

let remove_register r env =
  match env with
  | BOT -> BOT
  | Val env' -> Val (Env.remove (Env.Key.Reg r) env')

let remove_addresses addrs env =
  match env with
  | BOT -> BOT
  | Val env' ->
     Val (List.fold_left (fun env a -> Env.remove (Env.Key.Mem a) env) env' (Data.Address.Set.elements addrs))

let to_string env =
  match env with
  | BOT -> ["_"]
  | Val env' ->
     Env.fold (
       fun key typ acc ->
	 let styp = Types.to_string typ in
	 ("T-"^(Env.Key.to_string key)^"="^styp)::acc
     ) env' []

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
  

let of_exp (e: Asm.exp) (env: t): Types.t =
  match env with
  | BOT -> raise Exceptions.Empty
  | Val env' ->
     match e with
     | Asm.Lval (Asm.V (Asm.T r)) ->
	begin
	  try Env.find (Env.Key.Reg r) env'
	  with Not_found -> Types.TUnknown
	end
  | _ -> Types.TUnknown
     
