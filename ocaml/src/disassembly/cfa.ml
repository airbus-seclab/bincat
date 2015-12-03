(** the control flow automaton module *)
module Make(Domain: Domain.T) =
    struct			
	  (** Abstract data type of nodes of the CFA *)
	  module State =
	    struct

	  (** data type for the decoding context *)
	  type ctx_t = {
	      addr_sz: int; (** size in bits of the addresses *)
	      op_sz  : int; (** size in bits of operands *)
	    }
	   
	  (** abstract data type of a state *)
	  type t = {
	      id: int; 	     (** unique identificator of the state *)
	      mutable ip: Domain.Asm.Address.t;  (** instruction pointer *)
	      mutable v: Domain.t; 		  (** abstract value *)
	      mutable ctx: ctx_t ; 		  (** context of decoding *)
	      mutable stmts: Domain.Asm.stmt list; (** list of statements thas has lead to this state *)
	      internal: bool 	     (** whenever this node has been added for technical reasons and not because it is a real basic blocks *)
	    }

	  let ip s = s.ip
	  let abstract_value s = s.v
				   
	  (** the state identificator counter *)
	  let state_cpt = ref 0
			      
	  (** returns a fresh state identificator *)
	  let new_state_id () = state_cpt := !state_cpt + 1; !state_cpt
							      
	  (** state equality returns true whenever they are the physically the same (do not compare the content) *)
	  let equal s1 s2   = s1.id = s2.id
					
	  (** state comparison: returns 0 whenever they are the physically the same (do not compare the content) *)
	  let compare s1 s2 = s1.id - s2.id
	  (** otherwise return a negative integer if the first state has been created before the second one; *)
	  (** a positive integer if it has been created later *)
					
	  (** hashes a state *)
	  let hash b 	= b.id
			 
	  (* (\** oracle providing information to domains *\) *)
	  (* class context d = *)
	  (* object *)
	  (*   method mem_to_addresses m sz = Domain.mem_to_addresses m sz d *)
	  (* end *)
	    
	end
	  
      (** Abstract data type of edge labels *)
      module Label = 
	struct

	  (** None means no label ; true is used for a if-branch link between states ; false for a else-branch link between states *)
	  type t = bool option
			
	  let default = None
			  
	  let compare l1 l2 = 
	    match l1, l2 with
	      None, None 	   -> 0
	    | None, _ 	   -> -1
	    | Some b1, Some b2 -> compare b1 b2
	    | Some _, None 	   -> 1
					
	end
      (** *)    
	  
      module G = Graph.Imperative.Digraph.ConcreteBidirectionalLabeled(State)(Label)
      open State 
	     
      (** type of a CFA *)
      type t = G.t

      (** return the given domain updated byt the initial values and tainting for memory as provided by the Config module *)
      let init_registers tbl =
	let pad b sz =
	  let n = String.length b in
	  if n = sz then b
	  else
	    if n > sz then
	      raise (Invalid_argument (Printf.sprintf "Illegal initial tainting for register %s" (Register.name r)))
	    else
	      let s = String.make sz '0' in
	      let o = sz - n + 1 in
	      for i = 0 to n-1 do
		String.set s (i+o) (String.get b i)
	      done;
	      s
	in
	
	let pad_tainting_register v r =
	  let sz = Register.size r in
	  match v with
	  | Config.Bits b       -> Config.Bits (pad b sz)
	  | Config.Mbits (b, m) -> Config.MBits (pad b sz, pad m sz)
	in						     

	  let tbl' =  Hashtbl.fold (fun r v tbl -> Domain.taint_register_from_config tbl r (pad_tainting_register v r)) Config.initial_register_tainting tbl in
	  Hashtbl.fold (fun r v tbl -> Domain.set_register_from_config tbl r (pad v (Register.size r))) Config.inital_register_content tbl'

      	
      (** return the given domain updated by the initial values and tainting for memory as provided by the Config module *)

      let extended_memory_pad a b =
	let split_and_pad s sz =
	  let len = String.length s in
	  let sz = !Config.operand_sz in
	  let l = ref [] in
	  for i = 0 to len-1 do
	    try
	      l := (String.sub s sz*i (sz*(i+1)-1))::!l
	    with
	      _ -> l := pad (String.sub s i (len-(sz*i)))::!l
	  done;
	  List.rev !l
			     
	in
	let a' = Domain.Asm.Address.of_string a !Config.address_sz in
	try
	  [a', pad b !Config.operand_sz]
	with _ ->
	  let l = split_and_pad b in
	  List.mapi (fun i v -> Domain.Asm.Address.add_const a' i, v) l 

      let extended_tainting_memory_pad a t =
	let a' = Domain.Asm.Address.of_string a !Config.address_sz in
	match t with
	| Config.Bits b -> List.map (fun (a', v') -> a', Config.Bits v') (split_and_pad b)
	| Config.MBits (b, m) -> 
	   let b' = split_and_pad b in
	   let m' = split_abd_pad m in
	   let nb' = List.length b' in
	   let nm' = List.length m' in
	   if nb' = nm' then
	     List.map2 (fun (a, t) (_, m) -> a, Config.MBits (t, m)) b' m'
	   else
	     if nb' > nm' then
	       List.mapi (fun i (a, t) -> if i < nm' then a, Config.Mbits (t, snd (List.nth i m)) else a, Config.Bits t) b'
	     else
	       (* filling with '0' means that we suppose by default that memory is untainted *)
	       List.mapi (fun i (a, m) -> if i < nb' then a, Config.Mbits (snd (List.nth i b'), m) else a, Config.MBits (String.make !Config.operand_sz '0', m)) m' 
	     
      let init_memory tbl =
	
	let dc' = Hashtbl.fold (fun a c d ->
		      let l = extended_memory_pad a c in
		      List.fold_left (fun d (a', c') -> Domain.set_memory_from_config a' c' d) d l) Config.initial_memory_content tbl
	in
	Hashtbl.fold (fun a t d ->
	    let l = extended_tainting_memory_pad a b t in
	    List.fold_left (fun d (a', c') -> Domain.taint_memory_from_config a' c' d) d l) Config.initial_memory_tainting dc'
	
		     
      (** CFA creation *)
      (** returned CFA has only one node : the state whose ip is given by the parameter and whose domain field is generated from the Config module *)
      let init ip =
	let init_value () =
	  (* add every register to domains with bottom value *)
	  let bot = Domain.from_registers Domain.bot in	
	  (* update tainting value and contents for registers *)
	  let dc  = init_registers bot in
	  (* update tainting value and contents for memory locations *)
	  init_memory dc								       

	in  
	  
	let s = {
	    id = 0;
	    ip = Domain.Asm.Address.of_string ip !Config.address_sz;
	    v = init_value(); 
	    stmts = [];
	    ctx = {
		op_sz = !Config.operand_sz;
		addr_sz = !Config.address_sz;
	      };
	    internal = false
	}
	in
	let g = G.create () in
	G.add_vertex g s;
	g, s
 			       
      
			     
      (** returns true whenever the two given contexts are equal *)
      let ctx_equal c1 c2 = c1.addr_sz = c2.addr_sz && c1.op_sz = c2.op_sz
								    
      (** [add_state g pred ip s stmts ctx i] creates a new state in _g_ with
    - ip as instruction pointer;
    - stmts as list of statements;
    - v as abstract value (if already in the CFA ; then previous value is joined with s)
    - pred as ancestor;
    - ctx as decoding context
    - i is the boolean true for internal states ; false otherwise *)
      let add_state g pred ip v stmts ctx i =
	let add () =
	  let v = {
	      id = new_state_id();
	      v 	= v;
	      ip 	= ip;
	      stmts = stmts ;
	      ctx 	= ctx;
	      internal = i
	    }
	  in
	  G.add_vertex g v;
	  v
	in
	let rec find succs =
	  match succs with
	    s::succs' ->
	    if Domain.Asm.Address.compare s.ip ip = 0 && ctx_equal s.ctx ctx && s.internal = i then
	      begin
		s.v <- Domain.join s.v v;
		s
	      end
	    else find succs'
	  | _ -> raise Not_found
	in
	try
	  find (G.succ g pred), false
	with Not_found -> add (), true
				    
      (** [add_edge g src dst l] adds in _g_ an edge _src_ -> _dst_ with label _l_ *)
      let add_edge g src dst l = G.add_edge_e g (G.E.create src l dst)
					      
      (** updates the abstract value field of the given state *)
      let update_state s v'=
      	s.v <- Domain.join v' s.v;
      	Domain.contains v' s.v
			  
      (** updates the context and statement fields of the given state *)
      let update_stmts s stmts op_sz addr_sz =
      	s.stmts <- stmts;
      	s.ctx   <- {addr_sz = addr_sz; op_sz = op_sz}
		     
      let succs g v  = G.succ g v
      let pred g v   = G.pred g v
      let remove g v = G.remove_vertex g v

      let print g dumpfile =
	let f = open_out dumpfile in
	let print_ip s =
	  let abstract_values = List.fold_left (fun s v -> v ^ "\n" ^ s) "" (Domain.to_string s.v) in 
	  Printf.fprintf f "[ address = 0x%s ]\n%s\n\n\n" (Domain.Asm.Address.to_string s.ip) abstract_values
	in
	G.iter_vertex print_ip g;
	close_out f
	
	
    end
  (** module Cfa *)
