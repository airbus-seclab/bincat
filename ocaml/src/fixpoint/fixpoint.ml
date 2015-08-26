(******************************************************************************)
(* Functor generating the fixpoint iterator on abstract states                *)
(******************************************************************************)

module Make(Domain: Domain.T) =
struct

  (** the decoder module *)
  module Decoder = Decoder.Make(Domain)

  (** the control flow automaton module *)
  module Cfa = Decoder.Cfa 

  (** the code module *)
  module Code = Code.Make(Domain.Asm)
			 
  (** the assembly language *)
  open Domain.Asm

  (** computes the list of function targets (their addresses) from a value of type fct *)
  let ft_to_addresses s f =
    match f with
      I r -> Address.Set.elements (Domain.exp_to_addresses s (Lval (V r)))
    | D a -> [a]

  (** computes the list of jump targets (their addresses) from a value of type jmp_target *)
  let jmp_to_addresses _s j _sz =
    match j with
      A a -> [a]
    | R (_n, _r) -> failwith "the following commented code shows a confusion between what an offset and an address are supposed to represent "
  (*let n' = Segment.shift_left n 4 in
		  let offsets = Address.Set.elements (Domain.exp_to_addresses s (Lval (V r))) in
		  List.map (fun a -> Address.make n' a sz) offsets*)
						   
  let default_ctx () = {
      Cfa.State.op_sz = Word.default_size() ;
      Cfa.State.addr_sz = Address.default_size()
    }
			 
  let process_stmt g (v: Cfa.State.t) _a _o stmt = 
    (* TODO factorize the two Jcc case and the CALL case *)
    let s = match v.Cfa.State.v with
      | None -> failwith "Fixpoint.process_stmt: None case not implemented"
      | Some s -> s
    in
    match stmt with
      Store (_lv, _e) 	     -> failwith "Fixpoint.process_stmt, case Store: not implemented"
							   
    | Jcc (None, Some e)  ->
       let addr_sz = (* v.Cfa.State.ctx.addr_sz in *) failwith "Fixpoint.process_stmt, case Jcc: addr_sz field of v to compute" in
    let addrs = jmp_to_addresses s e addr_sz in
    List.fold_left (fun vertices a -> 
      let v', b = Cfa.add_state g v a (Some s) [] (default_ctx()) false in
      Cfa.add_edge g v v' None; 
      if b then v'::vertices 
      else vertices) [] addrs

  | Call f -> 
    let addrs = ft_to_addresses s f in
    List.fold_left (fun vertices a -> 
      let v', b = Cfa.add_state g v a (Some s) [] (default_ctx()) false in
      Cfa.add_edge g v v' None; 
      if b then v'::vertices 
      else vertices) [] addrs
  | Jcc (_, None) 	     -> []

				  (*
  | Jcc(Some e, Some a') -> 
     let s' = Cfa.State.guard s e in
     let ns' = Cfa.State.guard s (UnOp(Not, e)) in
    let addrs = jmp_to_addresses s a' in
    let vertices = 
    List.fold_left (fun vertices a ->
      let v', b = Cfa.add_state g v a (Some s') [] (default_ctx()) false in
      Cfa.add_edge g v v' (Some true); 
      if b then v'::vertices 
      else vertices
    ) [] addrs
    in
    let nv, b = Cfa.add_vertex g v (Data.Address.add_offset a o) (Some ns') [] (default_ctx()) false in 
    if b then begin Cfa.add_edge g v nv (Some false); nv::vertices end
    else vertices
				   

  | Unknown     	     -> let _ = Cfa.update_state v (Cfa.State.forget s) in []
  | Undef       	     -> raise Exit
  | Nop         	     -> []
  | Directive _ 	     -> let _ = Cfa.update_state v (Cfa.State.forget s) in []*)
  | _ -> failwith "Fixpoint.process_stmt, default case: to implement (use above commented code)"

let update g a o v =
  List.fold_left (fun l stmt -> (process_stmt g v a o stmt)@l) [] v.Cfa.State.stmts

  module Vertices = Set.Make(Cfa.State)

  let filter_vertices g vertices =
(** [filter_vertices _g_ vertices] removes vertices in _vertices_ that are already in _g_ (same address and same decoding context) *)
    let equal_ctx ctx1 ctx2 = ctx1.Cfa.State.addr_sz = ctx2.Cfa.State.addr_sz && ctx1.Cfa.State.op_sz = ctx2.Cfa.State.op_sz
    in
    let rec filter_succs succs v =
      match succs with
	[] -> v
      | s::succs' -> 
	 if Address.compare s.Cfa.State.ip v.Cfa.State.ip = 0
	    && equal_ctx s.Cfa.State.ctx v.Cfa.State.ctx
	    && v.Cfa.State.internal = s.Cfa.State.internal then 
	  begin
	    let _edges = (*Cfa.succ_e g v in*) failwith "Fixpoint.update: computation of successors not implemented" in
	    if true then failwith "Fixpoint.filter: List.iter (fun e -> Cfa.add_edge g s (Cfa.dst e) (Cfa.label e)) edges";
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

  let process code g s =
    let ctx   	 = { 
	Decoder.cs = Segment.cs;
	Decoder.ds = Segment.ds;
	Decoder.ss = Segment.ss; 
	Decoder.es = Segment.es;
	Decoder.fs = Segment.fs;
	Decoder.gs = Segment.gs
      } 
    in
    let continue = ref true in
    let waiting = ref (Vertices.singleton s) in
    let vl = ref [] in
    while !continue do
      let v = Vertices.choose !waiting in
      waiting := Vertices.remove v !waiting;
      let text' 	   = Code.sub code v.Cfa.State.ip in
      let vertices, offset = Decoder.parse text' g v v.Cfa.State.ip ctx		      in
      let vertices' 	   = filter_vertices g vertices				      in
      let new_vertices 	   = List.fold_left (fun l v' -> (update g v.Cfa.State.ip offset v')@l) [] vertices'   in
      vl := [];
      List.iter (fun v -> if not v.Cfa.State.internal then begin vl := v::!vl;  waiting := Vertices.add v !waiting end) new_vertices;
      continue := not (Vertices.is_empty !waiting) 
    done;
    g, !vl


end

