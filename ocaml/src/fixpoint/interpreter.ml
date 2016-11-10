(** Fipoint iterator *)

(** external signature of the module *)
module type T =
  sig
    type domain
    module Cfa:
    sig
      type t
      module State:
      sig
	(** data type for the decoding context *)
	  type ctx_t = {
	      addr_sz: int; (** size in bits of the addresses *)
	      op_sz  : int; (** size in bits of operands *)
	    }

	  (** abstract data type of a state *)
	  type t = {
	      id: int; 	     		    (** unique identificator of the state *)
	      mutable ip: Data.Address.t;   (** instruction pointer *)
	      mutable v: domain; 	    (** abstract value *)
	      mutable ctx: ctx_t ; 	    (** context of decoding *)
	      mutable stmts: Asm.stmt list; (** list of statements of the succesor state *)
	      mutable final: bool;          (** true whenever a widening operator has been applied to the v field *)
	      mutable back_loop: bool; (** true whenever the state belongs to a loop that is backward analysed *)
	      mutable forward_loop: bool; (** true whenever the state belongs to a loop that is forward analysed in CFA mode *)
	      mutable branch: bool option; (** None is for unconditional predecessor. Some true if the predecessor is a If-statement for which the true branch has been taken. Some false if the false branch has been taken *)
	      mutable bytes: char list;      (** corresponding list of bytes *)
	      mutable is_tainted: bool; (** true whenever a source left value is the stmt list (field stmts) is tainted *)
	    }
      end
      val init: Data.Address.t -> State.t
      val create: unit -> t
      val add_vertex: t -> State.t -> unit
      val print: string -> string -> t -> unit
      val unmarshal: string -> t
      val marshal: string -> t -> unit
      val init_abstract_value: unit -> domain
      val last_addr: t -> Data.Address.t -> State.t
    end
    val forward_bin: Code.t -> Cfa.t -> Cfa.State.t -> (Cfa.t -> unit) -> Cfa.t
    val forward_cfa: Cfa.t -> Cfa.State.t -> (Cfa.t -> unit) -> Cfa.t 
    val backward: Cfa.t -> Cfa.State.t -> (Cfa.t -> unit) -> Cfa.t
    val interleave: Code.t -> Cfa.t -> Cfa.State.t -> (Cfa.t -> unit) -> Cfa.t
  end
    
module Make(D: Domain.T): (T with type domain = D.t) =
  struct

    type domain = D.t
		    
    (** Decoder *)
    module Decoder = Decoder.Make(D)
				 
    (** Control Flow Automaton *)
    module Cfa = Decoder.Cfa 
			      
    open Asm
	    				    
    (* Hash table to know when a widening has to be processed, that is when the associated value reaches the threshold Config.unroll *)
    let unroll_tbl: (Data.Address.t, int * D.t) Hashtbl.t = Hashtbl.create 10
			   
    (** opposite the given comparison operator *)
    let inv_cmp (cmp: Asm.cmp): Asm.cmp =
      match cmp with
      | EQ  -> NEQ
      | NEQ -> EQ
      | LT  -> GEQ
      | GEQ -> LT
      | LEQ -> GT
      | GT  -> LEQ
		 
    let restrict (d: D.t) (e: Asm.bexp) (b: bool): (D.t * bool) =
      let rec process e b =
        match e with
        | BConst b' 		  -> if b = b' then d, false else D.bot, false
        | BUnOp (LogNot, e) 	  -> process e (not b)
					     
        | BBinOp (LogOr, e1, e2)  ->
           let v1, b1 = process e1 b in
           let v2, b2 = process e2 b in
	   let is_tainted = b1||b2 in
           if b then D.join v1 v2, is_tainted
           else D.meet v1 v2, is_tainted
		       
        | BBinOp (LogAnd, e1, e2) ->
           let v1, b1 = process e1 b in
           let v2, b2 = process e2 b in
	   let is_tainted = b1||b2 in
           if b then D.meet v1 v2, is_tainted
           else D.join v1 v2, is_tainted
		       
        | Asm.Cmp (cmp, e1, e2)   ->
           let cmp' = if b then cmp else inv_cmp cmp in
           D.compare d e1 cmp' e2
      in
      process e b

	      		   
    (** widen the given vertex with all previous vertices that have the same ip as v *)
    let widen prev v =
      let join_v = D.join prev v.Cfa.State.v in
      v.Cfa.State.final <- true;
      v.Cfa.State.v <- D.widen prev join_v
			       
			       
    (** update the abstract value field of the given vertices wrt to their list of statements and the abstract value of their predecessor *)
    (** the widening may be also launched if the threshold is reached *)
    let update_abstract_value (g: Cfa.t) (v: Cfa.State.t) (ip: Data.Address.t) (process_stmts: Cfa.t -> Cfa.State.t -> Data.Address.t -> Cfa.State.t list): Cfa.State.t list =
      try
        let l = process_stmts g v ip in
        List.iter (fun v ->
            let n, jd =
              try
		let n', jd' = Hashtbl.find unroll_tbl ip in
		let d' = D.join jd' v.Cfa.State.v in
		Hashtbl.replace unroll_tbl ip (n'+1, d'); n'+1, jd'
              with Not_found ->
		Hashtbl.add unroll_tbl v.Cfa.State.ip (1, v.Cfa.State.v);
		1, v.Cfa.State.v
            in
            if n <= !Config.unroll then
              ()
            else 
              widen jd v
          ) l;
        List.fold_left (fun l' v -> if D.is_bot v.Cfa.State.v then
                                      begin
					Log.from_analysis (Printf.sprintf "unreachable state at address %s" (Data.Address.to_string ip));
					Cfa.remove_state g v; l'
                                      end
				    else v::l') [] l (* TODO: optimize by avoiding creating a state then removing it if its abstract value is bot *)
      with Exceptions.Empty -> Log.from_analysis (Printf.sprintf "No more reachable states from %s\n" (Data.Address.to_string ip)); []
								
 
    (*************************** Forward from binary file ************************)
    (*****************************************************************************)
   
    (** returns true whenever the given list of statements has a jump stmt (Jmp, Call, Return) *)
    let rec has_jmp stmts =
        match stmts with
        |	[] -> false
        | s::stmts' ->
           let b =
             match s with
             | Call _ | Return  | Jmp _ -> true
             | If (_, tstmts, estmts)   -> (has_jmp tstmts) || (has_jmp estmts)
             | _ 			      -> false
           in
           b || (has_jmp stmts')
    
    exception Jmp_exn
    let rec process_value (d: D.t) (s: Asm.stmt) =
        match s with
        | Nop 				 -> d, false
        | If (e, then_stmts, else_stmts) -> process_if d e then_stmts else_stmts       
        | Set (dst, src) 		 -> D.set dst src d
        | Directive (Remove r) 		 -> let d' = D.remove_register r d in Register.remove r; d', false
        | Directive (Forget r) 		 -> D.forget_lval (V (T r)) d, false
        | _ 				 -> raise Jmp_exn
						     
    and process_if (d: D.t) (e: Asm.bexp) (then_stmts: Asm.stmt list) (else_stmts: Asm.stmt list) =
      if has_jmp then_stmts || has_jmp else_stmts then
             raise Jmp_exn
           else
             let dt, bt = List.fold_left (fun (d, b) s -> let d', b' = process_value d s in d', b||b') (restrict d e true) then_stmts in
             let de, be = List.fold_left (fun (d, b) s -> let d', b' = process_value d s in d', b||b') (restrict d e false) else_stmts in
             D.join dt de, bt||be
				 
    let process_ret fun_stack v =
      try
	begin
	let d = v.Cfa.State.v in
	let d', ipstack =
            let _f, ipstack = List.hd !fun_stack in
            fun_stack := List.tl !fun_stack;	
            (* check and apply tainting and typing rules *)
	    (* 1. check for assert *)
	    (* 2. taint ret *)
	    (* 3. type ret *)
            d, Some ipstack
	    in   
	    (* check whether instruction pointers supposed and effective do agree *)
	    try
              let sp = Register.stack_pointer () in
              let ip_on_stack, is_tainted = D.mem_to_addresses d' (Asm.Lval (Asm.M (Asm.Lval (Asm.V (Asm.T sp)), (Register.size sp)))) in
              match Data.Address.Set.elements (ip_on_stack) with
              | [a] ->
		 v.Cfa.State.ip <- a;
		 begin
		   match ipstack with
		   | Some ip' -> 
                      if not (Data.Address.equal ip' a) then
			Log.from_analysis (Printf.sprintf "computed instruction pointer %s differs from instruction pointer found on the stack %s at RET instruction"
							  (Data.Address.to_string ip') (Data.Address.to_string a))
		   | None -> ()
		 end;
		 Some v, is_tainted
              | _ -> raise Exit
	    with
              _ -> Log.error "computed instruction pointer at return instruction is either undefined or imprecise"
	  end
	with Failure "hd" -> Log.from_analysis (Printf.sprintf "RET without previous CALL at address %s" (Data.Address.to_string v.Cfa.State.ip)); None, false
		       

    (** returns the result of the transfert function corresponding to the statement on the given abstract value *)
    let process_stmts fun_stack g (v: Cfa.State.t) ip: Cfa.State.t list =
      let fold_to_target (apply: Data.Address.t -> unit) (vertices: Cfa.State.t list) (target: Asm.exp): (Cfa.State.t list * bool) =
		List.fold_left (fun (l, b) v ->
                    try
		      let addrs, is_tainted = D.mem_to_addresses v.Cfa.State.v target in
                      let addresses = Data.Address.Set.elements addrs in
                      match addresses with
                      | [a] -> v.Cfa.State.ip <- a; apply a; v::l, b||is_tainted
                      | [ ] -> Log.error (Printf.sprintf "Unreachable jump target from ip = %s\n" (Data.Address.to_string v.Cfa.State.ip))
                      | l -> Log.error (Printf.sprintf "Interpreter: please select between the addresses %s for jump target from %s\n"
						       (List.fold_left (fun s a -> s^(Data.Address.to_string a)) "" l) (Data.Address.to_string v.Cfa.State.ip))
                    with
                    | Exceptions.Enum_failure -> Log.error (Printf.sprintf "Interpreter: uncomputable set of address targets for jump at ip = %s\n" (Data.Address.to_string v.Cfa.State.ip))
		  ) ([], false) vertices

      in
      let add_to_fun_stack a =
	let f =
          try
            Some (Hashtbl.find Config.import_tbl (Data.Address.to_int a))
          with Not_found -> None
	in
	fun_stack := (f, ip)::!fun_stack
      in
      let copy v d branch is_pred =
	(* TODO: optimize with Cfa.State.copy that copies every field and then here some are updated => copy them directly *)
        let v' = Cfa.copy_state g v in
        v'.Cfa.State.stmts <- [];
        v'.Cfa.State.v <- d;
	v'.Cfa.State.branch <- branch;
        if is_pred then
          Cfa.add_edge g v v'
        else
          Cfa.add_edge g (Cfa.pred g v) v';
        v'
      in
      

      let rec process_if_with_jmp (vertices: Cfa.State.t list) (e: Asm.bexp) (istmts: Asm.stmt list) (estmts: Asm.stmt list) =
	let process_branch stmts branch =
	  let vertices', b = (List.fold_left (fun (l, b) v ->
					      try
						let d, is_tainted = restrict v.Cfa.State.v e branch in
						if D.is_bot d then
						  l, b
						else
						  (copy v d (Some true) false)::l, b||is_tainted
					      with Exceptions.Empty -> l, b) ([], false) vertices)
	  in
	  let vert, b' = process_list vertices' stmts in
	  vert, b||b'
	in
	let then', bt = process_branch istmts true in
	let else', be = process_branch estmts false in
	List.iter (fun v -> Cfa.remove_state g v) vertices;
	then' @ else', be||bt
      	    
      
      and process_vertices (vertices: Cfa.State.t list) (s: Asm.stmt): (Cfa.State.t list * bool) =
        try
          List.fold_left (fun (l, b) v -> let d, b' = process_value v.Cfa.State.v s in v.Cfa.State.v <- d; v::l, b||b') ([], false) vertices
        with Jmp_exn ->
             match s with 
             | If (e, then_stmts, else_stmts) ->  process_if_with_jmp vertices e then_stmts else_stmts 
		
             | Jmp (A a) -> List.map (fun v -> v.Cfa.State.ip <- a; v) vertices, false 
				     
             | Jmp (R target) -> fold_to_target (fun _a -> ()) vertices target
			 
             | Call (A a) -> add_to_fun_stack a; List.iter (fun v -> v.Cfa.State.ip <- a) vertices; vertices, false
	
	     | Call (R target) -> fold_to_target add_to_fun_stack vertices target
		
             | Return -> List.fold_left (fun (l, b) v ->
			     let v', b' = process_ret fun_stack v in
			     match v' with
			     | None -> l, b||b'
			     | Some v -> v::l, b||b') ([], false) vertices
				  
             | _       -> vertices, false
			    
      and process_list (vertices: Cfa.State.t list) (stmts: Asm.stmt list): (Cfa.State.t list * bool) =
        match stmts with
        | s::stmts ->
	   begin
	     try
               let (new_vertices: Cfa.State.t list), (b: bool) = process_vertices vertices s in
               let vert, b' = process_list new_vertices stmts in vert, (b||b')
	     with Exceptions.Bot_deref -> [], false (* in case of undefined dereference corresponding vertices are no more explored. They are not added to the waiting list neither *)
	   end
        | []       -> vertices, false
      in
      let vstart = copy v v.Cfa.State.v None true
      in
      vstart.Cfa.State.ip <- ip;
      vstart.Cfa.State.is_tainted <- false;
      let vertices, b = process_list [vstart] v.Cfa.State.stmts in
      if b then v.Cfa.State.is_tainted <- true;
      vertices

    (** [filter_vertices g vertices] returns vertices in _vertices_ that are already in _g_ (same address and same decoding context and subsuming abstract value) *)
    let filter_vertices g vertices =
      (* predicate to check whether a new vertex has to be explored or not *)
      let same prev v' =
        Data.Address.equal prev.Cfa.State.ip v'.Cfa.State.ip &&
          prev.Cfa.State.ctx.Cfa.State.addr_sz = v'.Cfa.State.ctx.Cfa.State.addr_sz &&
            prev.Cfa.State.ctx.Cfa.State.op_sz = v'.Cfa.State.ctx.Cfa.State.op_sz &&
              (* fixpoint reached *)
              D.subset v'.Cfa.State.v prev.Cfa.State.v
      in
      List.fold_left (fun l v ->
          try
            (* filters on cutting instruction pointers *)
            if Config.SAddresses.mem (Data.Address.to_int v.Cfa.State.ip) !Config.blackAddresses then
              begin
              Log.from_analysis (Printf.sprintf "Address %s reached but not explored because it belongs to the cut off branches\n"
						(Data.Address.to_string v.Cfa.State.ip));
              raise Exit
              end
            else
              (** explore if a greater abstract state of v has already been explored *)
              Cfa.iter_vertex (fun prev ->
                  if v.Cfa.State.id = prev.Cfa.State.id then
                    ()
                  else
                    if same prev v then raise Exit
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
    let forward_bin (code: Code.t) (g: Cfa.t) (s: Cfa.State.t) (dump: Cfa.t -> unit): Cfa.t =
      let module Vertices = Set.Make(Cfa.State) in
      (* check whether the instruction pointer is in the black list of addresses to decode *)
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
            (* the corresponding instruction is decoded and the successor vertex of v are computed and added to    *)
            (* the CFA                                                                                             *)
            (* except the abstract value field which is set to v.Cfa.State.value. The right value will be          *)
            (* computed next step                                                                                  *)
            (* the new instruction pointer (offset variable) is also returned                                      *)
            let r = Decoder.parse text' g !d v v.Cfa.State.ip (new decoder_oracle v.Cfa.State.v)                   in
            match r with
            | Some (v, ip', d') ->
               (* these vertices are updated by their right abstract values and the new ip                         *)
               let new_vertices = update_abstract_value g v ip' (process_stmts fun_stack)                         in
               (* among these computed vertices only new are added to the waiting set of vertices to compute       *)
               let vertices'  = filter_vertices g new_vertices				     		         in
               List.iter (fun v -> waiting := Vertices.add v !waiting) vertices';
               (* udpate the internal state of the decoder *)
               d := d'
            | None -> ()
          with
          | Exceptions.Error msg 	  -> dump g; Log.error msg
          | Exceptions.Enum_failure -> dump g; Log.error "analysis stopped (computed value too much imprecise)"
          | e			  -> dump g; raise e
        end;
        (* boolean condition of loop iteration is updated *)
        continue := not (Vertices.is_empty !waiting);
      done;
      g								      
	
   
    (******************** BACKWARD *******************************)
    (*************************************************************)
    let back_add_sub op dst e1 e2 d =
      match e1, e2 with
      | Lval lv1, Lval lv2 ->
	 let e = Lval dst in
	 let d', b = D.set lv1 (BinOp (op, e, e2)) d in
	 let d, b' = D.set lv2 (BinOp (op, e, e1)) d' in
	 d, b||b'
		 
      | Lval lv, e
      | e, Lval lv -> 
	 let e' = Lval dst in
	 D.set lv (BinOp (op, e', e)) d
      | _ -> D.forget_lval dst d, false
			   
    let back_set (dst: Asm.lval) (src: Asm.exp) (d: D.t): (D.t * bool) =
      Log.debug "back_set";
      match src with
      | Lval lv -> D.set lv (Lval dst) d
      | UnOp (Not, Lval lv) -> Log.debug "second case";D.set lv (UnOp (Not, Lval dst)) d 
      | BinOp (Add, e1, e2)  -> back_add_sub Sub dst e1 e2 d
      | BinOp (Sub, e1, e2) -> back_add_sub Add dst e1 e2 d
      | _ -> Log.debug "default case"; D.forget_lval dst d, false 
	
    (** backward transfert function on the given abstract value *)
    (** BE CAREFUL: this function does not apply to nested if statements *)
    let backward_process (branch: bool option) (d: D.t) (stmt: Asm.stmt) : (D.t * bool) =
      let rec back d stmt =
	match stmt with
	| Call _
	| Return
	| Jmp _
	| Nop -> d, false
	| Directive (Forget _) -> d, false 
	| Directive (Remove r) -> D.add_register r d, false
	| Set (dst, src) -> back_set dst src d
	| If (e, istmts, estmts) ->
	   match branch with
	   | Some true -> let d', b = List.fold_left (fun (d, b) s -> let d', b' = back d s in d', b||b') (d, false) istmts in let v, b' = restrict d' e true in v, b||b'
	   | Some false -> let d', b = List.fold_left (fun (d, b) s -> let d', b' = back d s in d', b||b') (d, false) estmts in let v, b' = restrict d' e false in v, b||b'
	   | None -> Log.error "illegal branch value for backward analysis"
      in
      back d stmt

    let back_update_abstract_value (g:Cfa.t) (pred: Cfa.State.t) (ip: Data.Address.t) (v: Cfa.State.t): Cfa.State.t list =
      Log.debug (Printf.sprintf "back_udpdate_abstract_value at %s (pred is at %s)" (Data.Address.to_string v.Cfa.State.ip) (Data.Address.to_string pred.Cfa.State.ip));
      let backward _g v _ip =
	let d', is_tainted = List.fold_left (fun (d, b) s ->
	  let d', b' = backward_process v.Cfa.State.branch d s in
	  Log.debug (Printf.sprintf "back_process for %s" (Asm.string_of_stmt s true));
	  if D.is_bot d' then
	  Log.debug "returns bot";
	  d', b||b') (v.Cfa.State.v, false) (List.rev pred.Cfa.State.stmts)
	in
	Log.debug "meet";
	pred.Cfa.State.v <- D.meet pred.Cfa.State.v d';
	pred.Cfa.State.is_tainted <- is_tainted;
	[pred]
      in
      update_abstract_value g v ip backward
      
			      
    let back_unroll g v pred =
      if v.Cfa.State.final then
	begin
	  v.Cfa.State.final <- false;
	  let new_pred = Cfa.copy_state g v in
	  new_pred.Cfa.State.back_loop <- true;
	  Cfa.remove_edge g pred v;
	  Cfa.add_vertex g new_pred;
	  Cfa.add_edge g pred new_pred;
	  Cfa.add_edge g new_pred v;
	  new_pred
	end
      else
	begin
	  pred.Cfa.State.v <- v.Cfa.State.v;
	  pred
	end

    (*************************************)
    (* FORWARD AUXILARY FUNCTIONS ON CFA *)
    (*************************************)
    let unroll g v succ =
      if v.Cfa.State.final then
	begin
	  v.Cfa.State.final <- false;
	  let new_succ = Cfa.copy_state g v in
	  new_succ.Cfa.State.forward_loop <- true;
	  Cfa.remove_edge g v succ;
	  Cfa.add_vertex g new_succ;
	  Cfa.add_edge g v new_succ;
	  Cfa.add_edge g new_succ succ;
	  new_succ
	end
      else
	begin
	  succ.Cfa.State.v <- v.Cfa.State.v;
	  succ
	end

      
    let forward_process (d: D.t) (stmt: Asm.stmt) (branch: bool option): (D.t * bool) =
      let rec forward (d: D.t) (stmt: Asm.stmt): (D.t * bool) =
	match stmt with
	| Asm.Nop 
	| Asm.Directive (Asm.Forget _) 
	| Asm.Directive (Asm.Remove _) 
	| Asm.Jmp (Asm.A _)
	| Asm.Return
	| Asm.Call (Asm.A _) -> d, false
	| Asm.Set (dst, src) -> D.set dst src d
	| Asm.If (e, istmts, estmts) ->
	   begin
	     try process_if d e istmts estmts
	     with Jmp_exn ->
	       match branch with
	       | Some true -> List.fold_left (fun (d, b) stmt -> let d', b' = forward d stmt in d', b||b') (restrict d e true) istmts
	       | Some false -> List.fold_left (fun (d, b) stmt -> let d', b' = forward d stmt in d', b||b') (restrict d e false) estmts
	       | None -> Log.error "Illegal call to Interpreter.forward_process"
	   end
	| Asm.Call (Asm.R _) -> D.forget d, true
	| Asm.Jmp (Asm.R _) -> D.forget d, true (* TODO may be more precise but check whether the target is really in the CFA. If not then go back to forward_bin for that branch *)
      in
      forward d stmt
	      
    let forward_abstract_value (g:Cfa.t) (succ: Cfa.State.t) (ip: Data.Address.t) (v: Cfa.State.t): Cfa.State.t list =
      let forward _g v _ip =
	let d', is_tainted = List.fold_left (fun (d, b) s ->
				 let d', b' = forward_process d s (succ.Cfa.State.branch) in
				 d', b||b') (v.Cfa.State.v, false) (succ.Cfa.State.stmts)
       in
      	succ.Cfa.State.v <- D.meet succ.Cfa.State.v d';
	succ.Cfa.State.is_tainted <- is_tainted;
	[succ]
      in
      update_abstract_value g v ip forward
    (****************************)
    (* FIXPOINT ON CFA *)
    (****************************)
      let cfa_iteration (update_abstract_value: Cfa.t -> Cfa.State.t -> Data.Address.t -> Cfa.State.t list -> Cfa.State.t list)
			(next: Cfa.t -> Cfa.State.t -> Cfa.State.t list)
			(unroll: Cfa.t -> Cfa.State.t -> Cfa.State.t -> Cfa.State.t) (g: Cfa.t) (s: Cfa.State.t) (dump: Cfa.t -> unit): Cfa.t =
	if D.is_bot s.Cfa.State.v then
	begin
	  dump g;
	  Log.error "analysis not started: empty meet with previous computed value"
	end
      else
	let module Vertices = Set.Make(Cfa.State) in
	let continue = ref true in
	let waiting = ref (Vertices.singleton s) in
	try
	  while !continue do
	    let v = Vertices.choose !waiting in
	    waiting := Vertices.remove v !waiting;
	    let v' = next g v in
	    let new_vertices = List.fold_left (fun l v' -> (update_abstract_value g v' v'.Cfa.State.ip [v'])@l) [] v' in
	    let new_vertices' = List.map (unroll g v) new_vertices in
	    let vertices' = filter_vertices g new_vertices' in
	    List.iter (fun v -> waiting := Vertices.add v !waiting) vertices';
	    continue := not (Vertices.is_empty !waiting)
	  done;
	  g
	with
	| Invalid_argument _ -> Log.from_analysis "entry node of the CFA reached"; g
	| e -> dump g; raise e
			     
      let backward (g: Cfa.t) (s: Cfa.State.t) (dump: Cfa.t -> unit): Cfa.t =
	Log.debug "entree dans backward";
	Log.debug (Printf.sprintf "esp = %s" (Data.Word.to_string (Data.Word.of_int (D.value_of_register s.Cfa.State.v (Register.of_name "esp")) 32)));
	cfa_iteration (fun g v ip vert -> back_update_abstract_value g v ip (List.hd vert))
		      (fun g v -> [Cfa.pred g v]) back_unroll g s dump		    
  
      let forward_cfa (g: Cfa.t) (s: Cfa.State.t) (dump: Cfa.t -> unit): Cfa.t =
	cfa_iteration (fun g v ip vert -> List.fold_left (fun l v' -> (forward_abstract_value g v ip v')@l) [] vert)
		      Cfa.succs unroll g s dump
      
    (************* INTERLEAVING OF FORWARD/BACKWARD ANALYSES *******)
    (******************************************************)
    let interleave (code: Code.t) (g: Cfa.t) (s: Cfa.State.t) (dump: Cfa.t -> unit): Cfa.t =
      let rec process i cfa =
	if i < !Config.refinements then
	  begin
	    Hashtbl.clear unroll_tbl;
	    let last = Cfa.last g in
	    let cfa' = List.fold_left (fun cfa s -> let cfa' = backward cfa s dump in Hashtbl.clear unroll_tbl; cfa') cfa last in
	    process (i+1) (forward_cfa cfa' s dump)
	  end
	else
	  cfa
      in
      process 0 (forward_bin code g s dump)
  end
     
