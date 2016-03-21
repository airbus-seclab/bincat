(******************************************************************************)
(* abstract domain of concrete pointer                                        *)
(******************************************************************************)

open Asm
module Address = Data.Address

       
type t =
  | Val of Address.t
  | BOT (* bottom *)
  | TOP (* top *)
      
let name = "Pointer"

let bot _sz = BOT
	    
let equal p1 p2 =
  match p1, p2 with
  | BOT, BOT | TOP, TOP -> true
  | Val a1, Val a2 		-> Address.equal a1 a2
  | _, _ 		-> false   
	      
let subset = equal

let to_value v =
  match v with
  | BOT | TOP -> raise Exceptions.Concretization
  | Val a     -> Address.to_int a

let string_of_offset o =
  let s   = String.escaped "0x%"   in
  let fmt = Printf.sprintf "%sx" s in
  Printf.sprintf "0x%s" (Z.format fmt o)
		 
let to_string p =
  match p with
  | Val a -> Address.to_string a
  | TOP -> "?"
  | BOT -> "_"
		      
let of_config r c sz = Val (Address.of_string r c sz)
		       
let eval_exp e _sz _dom_ctx c =
  let rec eval e =
    match e with
    | Asm.Const c        -> Val (Address.of_word c)
				
    | Asm.Lval (V (T r)) -> c#get_val_from_register r
						    
    | Asm.BinOp (op, Asm.Const c, e') | Asm.BinOp (op, e', Asm.Const c) ->
       begin
	 match eval e' with
	 | BOT -> BOT
	 | TOP -> TOP
	 | Val a  ->
	    begin
	      let c' = Data.Word.to_int c in
	      match op with
	      | Asm.Add -> begin try Val (Address.add_offset a c') with _ -> TOP end
	      | Asm.Sub -> begin try Val (Address.add_offset a (Z.neg c')) with _ -> TOP end
	      | _ -> TOP
	    end
	      
       end
       
    | _ 		-> TOP
  in
  eval e
			
let mem_to_addresses (m: Asm.exp) sz (ctx: t Unrel.ctx_t) =
  match m with
  | Asm.Lval (Asm.V (Asm.T r)) when sz = Register.size r ->
     begin
       match ctx#get_val_from_register r with
       | BOT | TOP -> raise (Exceptions.Enum_failure (name, "mem_to_addresses"))
       | Val a     -> Address.Set.singleton a
     end
  | _ 						         -> raise (Exceptions.Enum_failure (name, "mem_to_addresses"))
				     
let taint_of_config _c = BOT
			   
let join p1 p2 =
  if equal p1 p2 then p1
  else
    TOP
      
let combine _ _ _ _ = TOP
			
let enter_fun _fun _ctx = [], []
let leave_fun _ctx = [], []
			   
			   


