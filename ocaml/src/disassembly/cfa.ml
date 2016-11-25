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
	      id: int; 	     		    (** unique identificator of the state *)
	      mutable ip: Data.Address.t;   (** instruction pointer *)
	      mutable v: Domain.t; 	    (** abstract value *)
	      mutable ctx: ctx_t ; 	    (** context of decoding *)
	      mutable stmts: Asm.stmt list; (** list of statements of the succesor state *)
	      mutable final: bool;          (** true whenever a widening operator has been applied to the v field *)
	      mutable back_loop: bool; (** true whenever the state belongs to a loop that is backward analysed *)
	      mutable forward_loop: bool; (** true whenever the state belongs to a loop that is forward analysed in CFA mode *)
	      mutable branch: bool option; (** None is for unconditional predecessor. Some true if the predecessor is a If-statement for which the true branch has been taken. Some false if the false branch has been taken *)
	      mutable bytes: char list;      (** corresponding list of bytes *)
	    mutable is_tainted: bool (** true whenever a source left value is the stmt list (field stmts) may be tainted *)
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

	end

      module G = Graph.Imperative.Digraph.ConcreteBidirectional(State)
      open State

      (** type of a CFA *)
      type t = G.t

      (* utilities for memory and register initialization with respect to the provided configuration *)
      (***********************************************************************************************)

      (* returns the extension of the string b with '0' so that the returned string is of length sz *)
      (* length of b is supposed to be <= sz *)
      (* it is used both for initializing successive memory locations (values and taint) and the taint of registers *)
      let pad b sz =
	let n = String.length b in
	if n = sz then b
	else
	  begin
	    let s = String.make sz '0' in
	    let o = sz - n  in
	    for i = 0 to n-1 do
	      Bytes.set s (i+o) (String.get b i)
	    done;
	    s
	  end

      (* return the given domain updated by the initial values and intitial tainting for registers with respected ti the provided configuration *)
      let init_registers d =
	let check b sz name =
	  if (String.length (Bits.z_to_bit_string b)) > sz then
	       Log.error (Printf.sprintf "Illegal initialisation for register %s" name)
	in
	let check_mask b m sz name =
	 if (String.length (Bits.z_to_bit_string b)) > sz || (String.length (Bits.z_to_bit_string m)) > sz then
	   Log.error (Printf.sprintf "Illegal initialization for register %s" name)
	in
	(* checks whether the provided value is compatible with the capacity of the parameter of type Register _r_ *)
	let check_init_size r (c, t) =
	  let sz   = Register.size r in
	  let name = Register.name r in
	  begin
	  match c with
	  | Config.Content c    -> check c sz name
	  | Config.CMask (b, m) -> check_mask b m sz name
	  | _ -> Log.error "Illegal memory init \"|xx|\" spec used for register"
	  end;
	  begin
	    match t with
	    | Some (Config.Taint c)      -> check c sz name
	    | Some (Config.TMask (b, m)) -> check_mask b m sz name
	    | _ -> ()
	  end;
	  (c, t)
	in
	  (* the domain d' is updated with the content for each register with initial content and tainting value given in the configuration file *)
	Hashtbl.fold
	  (fun r v d ->
	    let region = if Register.is_stack_pointer r then Data.Address.Stack else Data.Address.Global
	    in
	    Domain.set_register_from_config r region (check_init_size r v) d
	  )
	  Config.register_content d


    (* main function to initialize memory locations (Global/Stack/Heap) both for content and tainting *)
    (* this filling is done by iterating on corresponding tables in Config *)
    let init_mem domain region content_tbl =
        Hashtbl.fold (fun (addr, nb) content domain ->
                            let addr' = Data.Address.of_int region addr !Config.address_sz in
                            Domain.set_memory_from_config addr' Data.Address.Global content nb domain
                     ) content_tbl domain
      (* end of init utilities *)
      (*************************)

    (** CFA creation *)
    (** return the abstract value generated from the Config module *)
    let init_abstract_value () =
      let d  = List.fold_left (fun d r -> Domain.add_register r d) (Domain.init()) (Register.used()) in
	(* initialisation of Global memory + registers *)
	let d' = init_mem (init_registers d) Data.Address.Global Config.memory_content in
	(* init of the Stack memory *)
	let d' = init_mem d' Data.Address.Stack Config.stack_content in
	(* init of the Heap memory *)
	init_mem d' Data.Address.Heap Config.heap_content
	
      (** returned CFA has only one node : the state whose ip is given by the parameter and whose domain field is generated from the Config module *)
      let init ip =
	let d' = init_abstract_value () in
	{
	    id = 0;
	    ip = ip;
	    v = d';
	    final = false;
	    back_loop = false;
	    forward_loop = false;
	    branch = None;
	    stmts = [];
	    bytes = [];
	    ctx = {
		op_sz = !Config.operand_sz;
		addr_sz = !Config.address_sz;
	      };
	    is_tainted = false;
	}
	

      (* CFA utilities *)
      (*****************)
      (** returns true whenever the two given contexts are equal *)
      let ctx_equal c1 c2 = c1.addr_sz = c2.addr_sz && c1.op_sz = c2.op_sz

      (** [add_state g pred ip s stmts ctx] creates a new state in _g_ with
    - ip as instruction pointer;
    - stmts as list of statements;
    - v as abstract value
    - ctx as decoding context
       *)
      let add_state g ip v stmts ctx final back_loop forward_loop branch bytes is_tainted =
	let v = {
	    id       = new_state_id();
	    v 	     = v;
	    ip 	     = ip;
	    stmts    = stmts ;
	    ctx      = ctx;
	    final    = final;
	    back_loop = back_loop;
	    forward_loop = forward_loop;
	    branch = branch;
	    bytes    = bytes;
	    is_tainted = is_tainted;
	  }
	  in
	  G.add_vertex g v;
	  v

      let add_vertex g v = G.add_vertex g v
					
      let create () = G.create ()
					
      let remove_state g v = G.remove_vertex g v

      let remove_edge g src dst = G.remove_edge g src dst
						   
      (** returns a fresh copy of the given state *)
      let copy_state g s = add_state g s.ip s.v s.stmts s.ctx s.final s.back_loop s.forward_loop s.branch s.bytes s.is_tainted

      (** [add_edge g src dst] adds in _g_ an edge _src_ -> _dst_ *)
      let add_edge g src dst = G.add_edge g src dst

      (** updates the abstract value field of the given state *)
      let update_state s v'=
      	s.v <- Domain.join v' s.v;
      	Domain.subset s.v v'

      (** updates the context and statement fields of the given state *)
      let update_stmts s stmts op_sz addr_sz =
      	s.stmts <- stmts;
      	s.ctx   <- { addr_sz = addr_sz; op_sz = op_sz }

      (** returns the list of successors of the given vertex in the given CFA *)
      let succs g v  = G.succ g v

      (** fold on all vertices of a graph *)
      let fold_vertex f g i = G.fold_vertex f g i

      (** iter on all vertices of a graph *)
      let iter_vertex f g = G.iter_vertex f g

      (** returns the unique predecessor of the given vertex in the given CFA *)
      (** may raise an exception if the vertex has no predessor *)
      let pred g v   =
	try List.hd (G.pred g v)
	with _ -> raise (Invalid_argument "vertex without predecessor")

      (** returns every node without successor in the given CFA *)
      let last g =
	G.fold_vertex (fun v l -> if succs g v = [] then v::l else l) g []
	       
      (** returns the state with the highest id and which has the given addr as ip field *)
      let last_addr g ip =
	let s = ref None in
	let last s' =
	  if Data.Address.compare s'.ip ip = 0 then
	    match !s with
	    | None -> s := Some s'
	    | Some prev -> if prev.id < s'.id then s := Some s'
	in
	G.iter_vertex last g;
	match !s with
	| None -> raise Not_found
	| Some s'   -> s'
			   
      (** dump the given CFA into the given file *)
      (** dot generation is also processed *)
      module GDot = struct
	include G
	let edge_attributes _e = []
	let default_edge_attributes _e = []
	let get_subgraph _g = None
	let vertex_attributes _v = []
	let default_vertex_attributes _v = []
	let graph_attributes _g = []
	let vertex_name v = (string_of_int v.id)
      end
      module Dot = Graph.Graphviz.Dot(GDot)

      let print dumpfile dotfile g =
	let f = open_out dumpfile in
	(* state printing (detailed) *)
	let print_ip s =
	  let bytes = List.fold_left (fun s c -> s ^" " ^ (Printf.sprintf "%02x" (Char.code c))) "" s.bytes in
	  Printf.fprintf f "[node = %d]\naddress = %s\nbytes =%s\nfinal =%s\ntainted=%s\n" s.id (Data.Address.to_string s.ip) bytes (string_of_bool s.final) (string_of_bool s.is_tainted);
      List.iter (fun v -> Printf.fprintf f "%s\n" v) (Domain.to_string s.v);
	  if !Config.verbose then
	    begin
	      Printf.fprintf f "statements =";
	      List.iter (fun stmt -> Printf.fprintf f " %s\n" (Asm.string_of_stmt stmt false)) s.stmts;
	    end;
	  Printf.fprintf f "\n";
	in
	G.iter_vertex print_ip g;
	(* edge printing (summary) *)
	Printf.fprintf f "[edges]\n";
	G.iter_edges_e (fun e -> Printf.fprintf f "e%d_%d = %d -> %d\n" (G.E.src e).id (G.E.dst e).id (G.E.src e).id (G.E.dst e).id) g;
	close_out f;
	(* dot generation *)
	if dotfile <> "" then
	  begin
	    let f' = open_out dotfile in
	    Dot.output_graph f' g;
	    close_out f'
	  end

      (** marshalling in that order:
           - cfa
           - state_id
	     *)
      let marshal outfname cfa =
	let cfa_marshal_fd = open_out_bin outfname in
	Marshal.to_channel cfa_marshal_fd cfa [];
	Marshal.to_channel cfa_marshal_fd !state_cpt [];
	close_out cfa_marshal_fd;;

      let unmarshal infname =
	let cfa_marshal_fd = open_in_bin infname in
	let origcfa = Marshal.from_channel cfa_marshal_fd in
	let last_id = Marshal.from_channel cfa_marshal_fd in
	state_cpt := last_id;
	close_in cfa_marshal_fd;
        origcfa;

    end
  (** module Cfa *)
