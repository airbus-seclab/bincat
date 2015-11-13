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
	      mutable ip: Domain.Asm.Address.t ;  (** instruction pointer *)
	      mutable v: Domain.t; 		  (** abstract value *)
	      mutable ctx: ctx_t ; 		  (** context of decoding *)
	      mutable stmts: Domain.Asm.stmt list; (** list of statements thas has lead to this state *)
	      internal     : bool 	     (** whenever this node has been added for technical reasons and not because it is a real basic blocks *)
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
		 
      (** CFA creation *)
      let make ip =
	let init_value () =
	  (* set every dimension (register and memory) either to bottom if non initialized or to a value provided by Context *)
	  let bot = Domain.from_registers ()															       in
	  let dc  = Hashtbl.fold Domain.set_register_from_config Config.initial_register_content bot								       in
	  let dt  = Hashtbl.fold Domain.taint_register Config.initial_register_tainting dc									       in
	  let dc' = Hashtbl.fold (fun a c d -> Domain.set_memory_from_config (Domain.Asm.Address.of_string a !Config.address_sz) c d) Config.initial_memory_content dt in
	  Hashtbl.fold (fun a t d -> Domain.taint_memory (Domain.Asm.Address.of_string a !Config.address_sz) t d) Config.initial_memory_tainting dc'
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
