(******************************************************************************)
(* Functor generating the fixpoint iterator on abstract states                *)
(******************************************************************************)

module Make(D: Domain.T) =
struct

  (** the decoder module *)
  module Decoder = Decoder.Make(D)

  (** the control flow automaton module *)
  module Cfa = Decoder.Cfa 

  class oracle s =
  (object
    (* Be careful : never call this method to implement a function of signature D.mem_to_adresses (stack overflow) *)
      method mem_to_addresses e sz = D.mem_to_addresses e sz s
    end: Domain.oracle)
    
  open Data
  open Asm
	 
  module Vertices = Set.Make(Cfa.State)
			    
  (** computes the list of function targets (their addresses) from a value of type fct *)
  let ft_to_addresses s sz f =
    match f with
      I r -> Address.Set.elements (D.mem_to_addresses (Lval (V r)) sz s)
    | D a -> [a]

  (** computes the list of jump targets (their addresses) from a value of type jmp_target *)
  let jmp_to_addresses _s j _sz =
    match j with
      A a -> [a]
    | R (_n, _r) -> failwith "the following commented code shows a confusion between what an offset and an address are supposed to represent "
  (*let n' = Segment.shift_left n 4 in
		  let offsets = Address.Set.elements (D.mem_to_addresses s (Lval (V r))) in
		  List.map (fun a -> Address.of_string (n'^":"^a) sz) offsets*)
						   
  let default_ctx () = {
      Cfa.State.op_sz = !Config.operand_sz; 
      Cfa.State.addr_sz = !Config.address_sz;
    }
			 
  let process_stmt _g (_v: Cfa.State.t) d stmt =
    match stmt with							   
    (*| Jcc (None, Some e)  ->
       let addr_sz = (* v.Cfa.State.ctx.addr_sz in *) failwith "Fixpoint.process_stmt, case Jcc: addr_sz field of v to compute" in
    let addrs = jmp_to_addresses s e addr_sz in
    List.fold_left (fun vertices a -> 
      let v', b = Cfa.add_state g v a s [] (default_ctx()) false in
      Cfa.add_edge g v v' None; 
      if b then v'::vertices 
      else vertices) [] addrs

    | Call f ->
       let ctx = (v.Cfa.State.ctx: Cfa.State.ctx_t) in
       let sz = ctx.Cfa.State.addr_sz in
    let addrs = ft_to_addresses s sz f in
    List.fold_left (fun vertices a -> 
      let v', b = Cfa.add_state g v a s [] (default_ctx()) false in
      Cfa.add_edge g v v' None; 
      if b then v'::vertices 
      else vertices) [] addrs*)

    | Nop -> d
	       
    | Set (dst, src) -> D.set dst src (new oracle d) d
		  
    | _       -> failwith ("Interpreter.process_stmt: "^ (string_of_stmt stmt) ^" not managed")

  (* update the abstract value field of the given vertices wrt to their list of statements and the abstract value of their predecessor *)
  (* vertices are supposed to be sorted in topological order *)
  (* update the abstract value field of each vertex *)
  let update_abstract_values g vertices =
    List.map (fun v ->
	let p = Cfa.pred g v in
	let d' = List.fold_left (fun d stmt -> process_stmt g v d stmt) p.Cfa.State.v v.Cfa.State.stmts in
	v.Cfa.State.v <- d';
	v
      ) vertices

  
  let n = ref 0;;
    
  (** [filter_vertices _g_ vertices] returns vertices in _vertices_ that are already in _g_ (same address and same decoding context and subsuming abstract value) *)
  let filter_vertices g vertices =
    let same v v' =
      Data.Address.equal v.Cfa.State.ip v'.Cfa.State.ip
      && v.Cfa.State.ctx.Cfa.State.addr_sz = v'.Cfa.State.ctx.Cfa.State.addr_sz
      && v.Cfa.State.ctx.Cfa.State.op_sz = v'.Cfa.State.ctx.Cfa.State.op_sz
      && v.Cfa.State.internal = v'.Cfa.State.internal
      && D.subset v'.Cfa.State.v v.Cfa.State.v
    in
    List.fold_left (fun l v ->
	if not v.Cfa.State.internal then
	  try
	    Cfa.iter_vertex (fun v' ->
		if v'.Cfa.State.internal || same v' v then raise Exit) g;
	    v::l
	  with
	    Exit -> l
	else
	  l
      ) [] vertices
      
    


  (** fixpoint iterator to build the CFA corresponding to the provided code starting from the initial vertex s *)
  (** g is the initial CFA reduced to the singleton s *) 
  let process code g s =
    (* boolean variable used as condition for exploration of the CFA *)
    let continue = ref true		      in
    (* set of waiting nodes in the CFA waiting to be processed *)
    let waiting  = ref (Vertices.singleton s) in
    while !continue do
      (* a waiting node is randomly chosen to be explored *)
      let v = Vertices.choose !waiting in
      waiting := Vertices.remove v !waiting;
      begin
	try
	  (* the subsequence of instruction bytes starting at the offset provided the field ip of v is extracted *)
	  let text'        = Code.sub code v.Cfa.State.ip						         in
	  (* the corresponding instruction is decoded and the successor vertices of v are computed and added to  *)
	  (* the CFA                                                                                             *)
	  (* except the abstract value field which is set to v.Cfa.State.value. The right value will be          *)
	  (* computed next step                                                                                  *)
	  (* the new instruction pointer (offset variable) is also returned                                      *)
	  (* Decoder.parse is supposed to return the vertices in a topological order                             *)
	  let vertices     = Decoder.parse text' g v v.Cfa.State.ip      		     		         in
	  (* these vertices are updated by their right abstract values and the new ip                            *)
	  let new_vertices = update_abstract_values g vertices                                                   in
	  (* among these computed vertices only new are added to the waiting set of vertices to compute          *)
	  let vertices'    = filter_vertices g new_vertices				     		         in
	  List.iter (fun v -> waiting := Vertices.add v !waiting) vertices';
	with
	| Exceptions.Enum_failure (m, msg) -> Log.from_analysis (m^"."^msg) "analysis stopped in that branch"
      end;
      (* boolean condition of loop iteration is updated                                                          *)
      continue := not (Vertices.is_empty !waiting);
    done;
    g


end

