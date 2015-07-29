(******************************************************************************)
(* Functor generating the fixpoint iterator on abstract states                *)
(******************************************************************************)

module Make(Domain: Domain.T) =
struct

  (** the decoder module *)
  module Decoder = Decoder.Make(Domain.Asm)

  (** the control flow automaton module *)
  module Cfa = Cfa.Make(Domain)
      
  let ft_to_addresses s f =
    match f with
      Asm.I r -> State.exp_to_addresses s (Asm.Lval (Asm.V r))
    | Asm.D a -> [a]
		   
  let jmp_to_addresses s j =
    match j with
      Asm.A a -> [a]
    | Asm.R (n, r) -> let n' = n lsl 4 in List.map (fun a -> Data.Address.add_offset a n') (State.exp_to_addresses s (Asm.Lval (Asm.V r)))
						   
  let default_ctx () = {Cfa.Vertex.op_sz = Data.Word.default_size() ; Cfa.Vertex.addr_sz = Data.Address.default_size()}
			 
  let process_stmt g v a o stmt = 
    (* TODO factorize the two Jcc case and the CALL case *)
    let s = match v.Cfa.Vertex.s with None -> State.make() | Some s -> s in
    match stmt with
      Asm.Set (lv, e) 	     -> 
      let _ = Cfa.update_state v (State.set a lv e s) in []
							   
    | Asm.Jcc (None, Some e)  ->
    let addrs = jmp_to_addresses s e in
    List.fold_left (fun vertices a -> 
      let v', b = Cfa.add_vertex g v a (Some s) [] (default_ctx()) false in
      Cfa.add_edge g v v' None; 
      if b then v'::vertices 
      else vertices) [] addrs

  | Asm.Call f -> 
    let addrs = ft_to_addresses s f in
    List.fold_left (fun vertices a -> 
      let v', b = Cfa.add_vertex g v a (Some s) [] (default_ctx()) false in
      Cfa.add_edge g v v' None; 
      if b then v'::vertices 
      else vertices) [] addrs
  | Asm.Jcc (_, None) 	     -> []
  
  | Asm.Jcc(Some e, Some a') -> 
    let s' = State.guard s e in
    let ns' = State.guard s (Asm.UnOp(Asm.Not, e)) in
    let addrs = jmp_to_addresses s a' in
    let vertices = 
    List.fold_left (fun vertices a ->
      let v', b = Cfa.add_vertex g v a (Some s') [] (default_ctx()) false in
      Cfa.add_edge g v v' (Some true); 
      if b then v'::vertices 
      else vertices
    ) [] addrs
    in
    let nv, b = Cfa.add_vertex g v (Data.Address.add_offset a o) (Some ns') [] (default_ctx()) false in 
    if b then begin Cfa.add_edge g v nv (Some false); nv::vertices end
    else vertices
 

  | Asm.Unknown     	     -> let _ = Cfa.update_state v (State.forget s) in []
  | Asm.Undef       	     -> raise Exit
  | Asm.Nop         	     -> []
  | Asm.Directive _ 	     -> let _ = Cfa.update_state v (State.forget s) in []

let update g a o v =
  List.fold_left (fun l stmt -> (process_stmt g v a o stmt)@l) [] v.Cfa.Vertex.stmts

  module Vertices = Set.Make(Cfa.Vertex)

  let filter_vertices g vertices =
(** [filter_vertices _g_ vertices] removes vertices in _vertices_ that are already in _g_ (same address and same decoding context) *)
    let equal_ctx ctx1 ctx2 = ctx1.Cfa.Vertex.addr_sz = ctx2.Cfa.Vertex.addr_sz && ctx1.Cfa.Vertex.op_sz = ctx2.Cfa.Vertex.op_sz
    in
    let rec filter_succs succs v =
      match succs with
	[] -> v
      | s::succs' -> 
	 if Data.Address.compare s.Cfa.Vertex.a v.Cfa.Vertex.a = 0
	    && equal_ctx s.Cfa.Vertex.ctx v.Cfa.Vertex.ctx
	    && v.Cfa.Vertex.internal = s.Cfa.Vertex.internal then 
	  begin
	    let edges = Cfa.succ_e g v in
	    List.iter (fun e -> Cfa.add_edge g s (Cfa.dst e) (Cfa.label e)) edges;
	    Cfa.remove g v;
	    s
	  end
	else filter_succs succs' v
    in
    let filter v = 
      try
	let succs = Cfa.succs g (List.hd (Cfa.pred g v)) in
	filter_succs succs v
      with Invalid_argument _ -> v (* raised as initial node corresponding to the entry point has no predecessor in the CFG *)
    in
    List.map filter vertices

  let process text o e =
    let g     	 = Cfa.create()			      in
    let ctx   	 = { 
      Decoder.cs 	 = Data.Segment.cs() ; Decoder.ds = Data.Segment.ds() ; Decoder.ss = Data.Segment.ss() ; 
      Decoder.es 	 = Data.Segment.es() ; Decoder.fs = Data.Segment.fs() ; Decoder.gs = Data.Segment.gs() } 
    in
    let continue = ref true				     in
    let waiting = ref (Vertices.singleton (Cfa.dummy_vertex e)) in
    let o' = Int64.to_int o in
    while !continue do
      let v = Vertices.choose !waiting in
      waiting := Vertices.remove v !waiting;
      let n 		   = Int64.to_int (Data.Address.sub v.Cfa.Vertex.a e)			      in
      let text' 	   = String.sub text (o'+n) ((String.length text) - n) in
      let vertices, offset = Decoder.parse text' g v v.Cfa.Vertex.a ctx		      in
      let vertices' 	   = filter_vertices g vertices				      in
      let new_vertices 	   = List.fold_left (fun l v' -> (update g v.Cfa.Vertex.a offset v')@l) [] vertices'   in
      List.iter (fun v -> if not v.Cfa.Vertex.internal then waiting := Vertices.add v !waiting) new_vertices;
      continue := not (Vertices.is_empty !waiting) 
    done;
    g
end

