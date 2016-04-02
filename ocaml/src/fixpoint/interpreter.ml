(******************************************************************************)
(* Functor generating the fixpoint iterator on abstract states                *)
(******************************************************************************)

module Make(D: Domain.T) =
struct

  (** the decoder module *)
  module Decoder = Decoder.Make(D)

  (** the control flow automaton module *)
  module Cfa = Decoder.Cfa 

  class domain_oracle s =
  (object
    (* Be careful : never call this method to implement a function of signature D.mem_to_adresses (stack overflow) *)
      method mem_to_addresses e = D.mem_to_addresses s e
    end: Domain.oracle)
    
  open Asm
	 
  module Vertices = Set.Make(Cfa.State)
			    
  
						   
  let default_ctx () = {
      Cfa.State.op_sz = !Config.operand_sz; 
      Cfa.State.addr_sz = !Config.address_sz;
    }

  let inv_cmp cmp =
    match cmp with
    | EQ  -> NEQ
    | NEQ -> EQ
    | LT  -> GEQ
    | GEQ -> LT
    | LEQ -> GT
    | GT  -> LEQ

  let restrict d e b =
    let rec process e b =
      match e with
      | BConst b' 	      -> if b = b' then d else D.bot
      | BUnOp (Not, e) 	      -> process e (not b)
					 
      | BBinOp (LogOr, e1, e2)  ->
	 let v1 = process e1 b in
	 let v2 = process e2 b in
	 if b then D.join v1 v2
	 else D.meet v1 v2
		     
      | BBinOp (LogAnd, e1, e2) ->
	 let v1 = process e1 b in
	 let v2 = process e2 b in
	 if b then D.meet v1 v2
	 else D.join v1 v2
		     
      | Asm.Cmp (cmp, e1, e2)    -> 
	 let cmp' = if b then cmp else inv_cmp cmp in
	 D.compare d e1 cmp' e2
    in
    process e b
    
  let process_stmt _g (_v: Cfa.State.t) d stmt =
    let rec process d s =
      match s with							   
    | Nop -> d

    | If (e, then_stmts, else_stmts) ->
       let then' = List.fold_left (fun d s -> process d s) (restrict d e true) then_stmts in
       let else' = List.fold_left (fun d s -> process d s) (restrict d e false) else_stmts in
       D.join then' else'
	      
    | Set (dst, src) -> D.set dst src (new domain_oracle d) d

    | Directive (Remove r) -> let d' = D.remove_register r d in Register.remove r; d'
				       
    | _       -> raise (Exceptions.Error (Printf.sprintf "Interpreter.process_stmt: %s statement" (string_of_stmt stmt)))
    in
    process d stmt
	    
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
	try
	  Cfa.iter_vertex (fun v' ->
	      if v.Cfa.State.id = v'.Cfa.State.id then
		()
	      else
		if same v v' then raise Exit
	    ) g;
	  v::l
	with
	  Exit -> l
	) [] vertices
      
  (** oracle used by the decoder to know the current value of a register *)
  class decoder_oracle s =
  object
    method value_of_register r = D.value_of_register s r
  end

  (** fixpoint iterator to build the CFA corresponding to the provided code starting from the initial vertex s *)
  (** g is the initial CFA reduced to the singleton s *) 
  let process code g s (dump: Cfa.t -> unit) =
    (* boolean variable used as condition for exploration of the CFA *)
    let continue = ref true		      in
    (* set of waiting nodes in the CFA waiting to be processed *)
    let waiting  = ref (Vertices.singleton s) in
    (* set d to the initial internal state of the decoder *)
    let d = ref (Decoder.init ()) in
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
	  let vertices, d' = Decoder.parse text' g !d v v.Cfa.State.ip (new decoder_oracle v.Cfa.State.v)        in
	  (* these vertices are updated by their right abstract values and the new ip                            *)
	  let new_vertices = update_abstract_values g vertices                                                   in
	  (* among these computed vertices only new are added to the waiting set of vertices to compute          *)
	  let vertices'    = filter_vertices g new_vertices				     		         in
	  List.iter (fun v -> waiting := Vertices.add v !waiting) vertices';
	  (* udpate the internal state of the decoder *)
	  d := d'
	with
	| Exceptions.Error msg 	  -> dump g; Log.error msg
	| Exceptions.Enum_failure -> dump g; Log.error "analysis stopped in that branch (too imprecise value computed)"
	| _ 			  -> dump g; Log.error "Interpreter error"
      end;
      (* boolean condition of loop iteration is updated                                                          *)
      continue := not (Vertices.is_empty !waiting);
    done;
    g
    

end

