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
	      ip: Domain.Asm.Address.t ;  (** instruction pointer *)
	      mutable v: Domain.t; 		  (** abstract value *)
	      mutable ctx: ctx_t ; 		  (** context of decoding *)
	      mutable stmts: Domain.Asm.stmt list; (** list of statements thas has lead to this state *)
	      internal     : bool 	     (** whenever this node has been added for technical reasons and not because it is a real basic blocks *)
	    }

	     	     
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
	let s = {
	    id = 0;
	    ip = Domain.Asm.Address.of_string ip (Domain.Asm.Address.default_size());
	    v = Domain.from_registers (); (* initialize every registers to bottom *)
	    stmts = [];
	    ctx = {
		op_sz = Domain.Asm.Word.default_size();
		addr_sz = Domain.Asm.Address.default_size()
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
      (*let succ_e g v = G.succ_e g v
      let dst e      = G.E.dst e
      let label e    = G.E.label e*)
      let remove g v = G.remove_vertex g v

      module DotAttr =
	struct
	  include G
	  let graph_attributes _g = []
	  let edge_attributes _g = []
	  let default_edge_attributes _g = []
	  let get_subgraph _g = None
	  let vertex_attributes _g = []
	  let vertex_name v = Domain.Asm.Address.to_string v.ip
	  let default_vertex_attributes _v = []
	end
      module Dot = Graph.Graphviz.Dot(DotAttr)
				     
      let print g dotfile =
	let f = open_out_bin dotfile in
	Dot.output_graph f g;
	close_out f
	
	
    end
  (** module Cfa *)
