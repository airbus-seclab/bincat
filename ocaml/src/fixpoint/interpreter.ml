(******************************************************************************)
(* Functor generating the fixpoint iterator on abstract states                *)
(******************************************************************************)

module Make(D: Domain.T) =
struct

  (** the decoder module *)
  module Decoder = Decoder.Make(D)

  (** the control flow automaton module *)
  module Cfa = Decoder.Cfa 

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
      | BConst b' 	        -> if b = b' then d else D.bot
      | BUnOp (LogNot, e) 	-> process e (not b)
					 
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

  let apply_tainting _rules d = d (* TODO apply rules of type Config.tainting_fun *)
  let check_tainting _f _a _d = () (* TODO check both in Config.assert_untainted_functions and Config.assert_tainted_functions *)
			   
  let process_stmt _g (v: Cfa.State.t) d stmt fun_stack =
    let rec process d s =
      match s with							   
    | Nop -> d

    | If (e, then_stmts, else_stmts) ->
       let then' = List.fold_left (fun d s -> process d s) (restrict d e true) then_stmts in
       let else' = List.fold_left (fun d s -> process d s) (restrict d e false) else_stmts in
       D.join then' else'
	      
    | Set (dst, src) -> D.set dst src d

    | Directive (Remove r) -> let d' = D.remove_register r d in Register.remove r; d'

    | Directive (Undef r) -> D.undefine r d

    | Jmp None -> d

    | Jmp (Some (A a)) -> v.Cfa.State.ip <- a; d
       
    | Jmp (Some (R target)) ->
       begin
	 try
	   let addresses = Data.Address.Set.elements (D.mem_to_addresses d target) in
	   match addresses with
	   | [a] -> v.Cfa.State.ip <- a; d
	   | [ ] -> Log.error (Printf.sprintf "Unreachable jump target from ip = %s\n" (Data.Address.to_string v.Cfa.State.ip))
	   | l -> Log.error (Printf.sprintf "Interpreter: please select between the addresses %s for jump target from %s\n"
					    (List.fold_left (fun s a -> s^(Data.Address.to_string a)) "" l) (Data.Address.to_string v.Cfa.State.ip))
	 with
	 | Exceptions.Enum_failure -> Log.error (Printf.sprintf "Interpreter: uncomputable set of address targets for jump at ip = %s\n" (Data.Address.to_string v.Cfa.State.ip))
       end

    | Call (A a) ->
       let f =
	 try
	   Some (Hashtbl.find Config.imports (Data.Address.to_int a))
	with Not_found -> None
       in
       fun_stack := (f, v.Cfa.State.ip)::!fun_stack;
       v.Cfa.State.ip <- a;
       d
	   
    | Return ->
       begin
	 try
	   let f, a = List.hd !fun_stack in
	   let d' =
	     try
	       match f with
		 Some (libname, fname) -> (* function library call : try to apply tainting rules from config *)
		 let rules =
		   let funs = Hashtbl.find Config.tainting_tbl libname in
		   fst (List.find (fun v -> String.compare (fst v) fname = 0) funs)
		 in
		 apply_tainting rules d
	       | None -> (* internal functions : tainting rules from control flow and data flow are directly infered from analysis *) d
	     with Not_found -> d
	   in
	   fun_stack := List.tl !fun_stack;
	   (* check tainting rules *)
	   check_tainting f a d';
	   (* check whether instruction pointers supposed and effective agree *)
	   try
	     let rip         = Register.stack_pointer ()			                                            in
	     let ip_on_stack = D.mem_to_addresses d' (Asm.Lval (Asm.M (Asm.Lval (Asm.V (Asm.T rip)), (Register.size rip)))) in
	     begin
	       match Data.Address.Set.elements ip_on_stack with
	       | [ip_on_stack] ->
		  if not (Data.Address.equal a ip_on_stack) then
		    Log.error "Interpreter: computed instruction pointer %s differs from instruction pointer found on the stack %s at RET intruction"
		  else
		    v.Cfa.State.ip <- a;
	       | _ -> Log.error "Intepreter: too much values computed for the instruction pointer at return instruction" 
	     end;
	     d'
	   with
	     _ -> Log.error "Intepreter: computed instruction pointer at return instruction too imprecise or undefined"
	 with
	 | _ -> Log.from_analysis (Printf.sprintf "return instruction at %s without previous call instruction\n" (Data.Address.to_string v.Cfa.State.ip)); d
       end
    | _       -> Log.error (Printf.sprintf "Interpreter.process_stmt: %s statement" (string_of_stmt stmt))
    in

    process d stmt
	    
  (* update the abstract value field of the given vertices wrt to their list of statements and the abstract value of their predecessor *)
  (* vertices are supposed to be sorted in topological order *)
  let update_abstract_values g vertices fun_stack =
    List.map (fun v ->
	let p = Cfa.pred g v in
	let d' = List.fold_left (fun d stmt -> process_stmt g v d stmt fun_stack) p.Cfa.State.v v.Cfa.State.stmts in
	v.Cfa.State.v <- d';
	v
      ) vertices

  
  let n = ref 0;;
    
  (** [filter_vertices _g_ vertices] returns vertices in _vertices_ that are already in _g_ (same address and same decoding context and subsuming abstract value) *)
  let filter_vertices g vertices =
    List.map (fun (label, v) ->
	match label with
	| None -> v
	| Some e -> v.Cfa.State.v <- restrict v.Cfa.State.v e true) vertices; v
    let same prev v' =
      if Data.Address.equal v.Cfa.State.ip v'.Cfa.State.ip then
	begin
	  v.Cfa.State.v <- D.join prev.Cfa.State.v v'.Cfa.State.v;
	  (* first to conditions ensure the decoding context is the same *)
	  prev.Cfa.State.ctx.Cfa.State.addr_sz = v'.Cfa.State.ctx.Cfa.State.addr_sz &&
						   prev.Cfa.State.ctx.Cfa.State.op_sz = v'.Cfa.State.ctx.Cfa.State.op_sz &&
						     (* fixpoint reached *)
						     D.subset v'.Cfa.State.v prev.Cfa.State.v
	end
      else
	false
    in
    List.fold_left (fun l v ->
	try
	  if Config.SAddresses.mem (Data.Address.to_int v.Cfa.State.ip) !Config.blackAddresses then
	     Log.from_analysis (Printf.sprintf "Address %s reached but not explored because it belongs to the cut off branches\n"
					       (Data.Address.to_string v.Cfa.State.ip))
	  else
	  (** explore if a greater abstract state of v has already been explored *)
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
     (* check whether the instruction pointer is in the black list of addresses to decode*)
    if Config.SAddresses.mem (Data.Address.to_int s.Cfa.State.ip) !Config.blackAddresses then
      Log.error "Interpreter not started as the entry point belongs to the cut off branches\n";
    (* boolean variable used as condition for exploration of the CFA *)
    let continue = ref true		      in
    (* set of waiting nodes in the CFA waiting to be processed *)
    let waiting  = ref (Vertices.singleton s) in
    (* set d to the initial internal state of the decoder *)
    let d = ref (Decoder.init ())             in
    (* function stack *)
    let fun_stack = ref []                    in
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
	  let new_vertices = update_abstract_values g vertices fun_stack                                         in
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

