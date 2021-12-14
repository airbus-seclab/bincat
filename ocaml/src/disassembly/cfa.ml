(*
    This file is part of BinCAT.
    Copyright 2014-2021 - Airbus

    BinCAT is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or (at your
    option) any later version.

    BinCAT is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with BinCAT.  If not, see <http://www.gnu.org/licenses/>.
*)


(* Log module for the CFG *)

module L = Log.Make(struct let name = "cfa" end)

module type T =
sig
  type domain


  (** abstract data type for the nodes of the control flow graph *)
  module State:
  sig

    (** data type for the decoding context *)
    type ctx_t = {
      addr_sz: int; (** size in bits of the addresses *)
      op_sz  : int; (** size in bits of operands *)
      }
               
    (** data type for handler management *)
    type handler_kind_t =
      | Direct of Data.Address.t
      | Inlined of Asm.stmt list
                 
    type t  = {
      id: int;                          (** unique identificator of the state *)
      mutable ip: Data.Address.t;       (** instruction pointer *)
      mutable v: domain;                (** abstract value *)
      mutable back_v: domain option; (** abstract value computed in backward mode. None means undefined *)
      mutable ctx: ctx_t ;              (** context of decoding *)
      mutable stmts: Asm.stmt list;     (** list of statements of the succesor state *)
      mutable final: bool;              (** true whenever a widening operator has been applied to the v field *)
      mutable back_loop: bool;          (** true whenever the state belongs to a loop that is backward analysed *)
      mutable forward_loop: bool;       (** true whenever the state belongs to a loop that is forward analysed in CFA mode *)
      mutable branch: bool option;      (** None is for unconditional predecessor. Some true if the predecessor is a If-statement for which the true branch has been taken. Some false if the false branch has been taken *)
      mutable bytes: char list;         (** corresponding list of bytes *)
      mutable taint_sources: Taint.Set.t;    (** set of taint sources*)
      mutable back_taint_sources: Taint.Set.t option; (** set of taint sources in backward mode. None means undefined *)
      mutable handlers: (int, Data.Address.t) Hashtbl.t * (int -> Asm.stmt list); (** table of user defined handlers * default handler behavior *)
    }

    val compare: t -> t -> int
  end

  (** oracle for retrieving any semantic information computed by the interpreter *)
  class oracle:
          domain ->
          (int, Data.Address.t) Hashtbl.t * (int -> Asm.stmt list) ->
  object
    (** returns the computed concrete value of the given register
        may raise an exception if the conretization fails
        (not a singleton, bottom) *)
    method value_of_register: Register.t -> Z.t

    (** returns the address associated to the given interrupt number *)
    method get_handler: int -> State.handler_kind_t
         
  end

  (** abstract data type of the control flow graph *)
  type t

  (** [create] creates an empty CFG *)
  val create: unit -> t

  (** [init_state addr] creates a state whose ip field is _addr_ *)
  val init_state: Data.Address.t -> (Register.t * Data.Word.t) list -> (int -> Asm.stmt list) -> State.t

  (** [add_state cfg state] adds the state _state_ from the CFG _cfg_ *)
  val add_state: t -> State.t -> unit

  (** [copy_state cfg state] creates a fresh copy of the state _state_ in the CFG _cfg_.
      The fresh copy is returned *)
  val copy_state: t -> State.t -> State.t

  (** [remove_state cfg state] removes the state _state_ from the CFG _cfg_ *)
  val remove_state: t -> State.t -> unit

  (** [pred cfg state] returns the unique predecessor of the state _state_ in the given cfg _cfg_.
      May raise an exception if thestate has no predecessor *)
  val pred: t -> State.t -> State.t

  (** [pred cfg state] returns the successor of the state _state_ in the given cfg _cfg_. *)
  val succs: t -> State.t -> State.t list

  (** iter the function on all states of the graph *)
  val iter_state: (State.t -> unit) -> t -> unit

  (** [add_successor cfg src dst] set _dst_ to be a successor of _src_ in the CFG _cfg_ *)
  val add_successor: t -> State.t -> State.t -> unit

  (** [remove_successor cfg src dst] removes _dst_ from the successor set of _src_ in the CFG _cfg_ *)
  val remove_successor: t -> State.t -> State.t -> unit

  (** [last_addr cfg] returns the address of latest added state of _cfg_ whose address is _addr_ *)
  val last_addr: t -> Data.Address.t -> State.t

  (** returns every state without successor in the given cfg *)
  val sinks: t -> State.t list

  (** [print dumpfile cfg] dump the _cfg_ into the text file _dumpfile_ *)
  val print: string -> t -> unit

  (** [marshal fname cfg] marshal the CFG _cfg_ and stores the result into the file _fname_ *)
  val marshal: out_channel -> t -> unit

  (** [unmarshal fname] unmarshal the CFG in the file _fname_ *)
  val unmarshal: in_channel -> t

  (** [init_abstract_value] builds the initial abstract value from the input configuration *)

  val init_abstract_value: Data.Address.t -> (Register.t * Data.Word.t) list -> domain * Taint.Set.t

  (** [update_abstract_value] updates the given abstract state from the input configuration *)
  val update_abstract_value: Data.Address.t -> domain -> domain * Taint.Set.t

  (** [iter_state_ip f ip] iterates function _f_ on states that have _ip_ as ip field *)
  val iter_state_ip: (State.t -> unit) -> t -> Data.Address.t -> unit

  val update_ips: t -> State.t -> unit
end

(** the control flow automaton functor *)



module Make(Domain: Domain.T) =
struct

  type domain = Domain.t

  (** Abstract data type of nodes of the CFA *)
  module State =
  struct

    (** data type for the decoding context *)
    type ctx_t = {
      addr_sz: int; (** size in bits of the addresses *)
      op_sz  : int; (** size in bits of operands *)
    }

    type handler_kind_t =
      | Direct of Data.Address.t
      | Inlined of Asm.stmt list
                 
    (** abstract data type of a state *)
    type t = {
      id: int;                          (** unique identificator of the state *)
      mutable ip: Data.Address.t;       (** instruction pointer *)
      mutable v: Domain.t;              (** abstract value *)
      mutable back_v: domain option; (** abstract value computed in backward mode. None means undefined *)
      mutable ctx: ctx_t ;              (** context of decoding *)
      mutable stmts: Asm.stmt list;     (** list of statements of the succesor state *)
      mutable final: bool;              (** true whenever a widening operator has been applied to the v field *)
      mutable back_loop: bool;          (** true whenever the state belongs to a loop that is backward analysed *)
      mutable forward_loop: bool;       (** true whenever the state belongs to a loop that is forward analysed in CFA mode *)
      mutable branch: bool option;      (** None is for unconditional predecessor. Some true if the predecessor is a If-statement for which the true branch has been taken. Some false if the false branch has been taken *)
      mutable bytes: char list;         (** corresponding list of bytes *)
      mutable taint_sources: Taint.Set.t;     (** set of taint sources. Empty if not tainted  *)
      mutable back_taint_sources: Taint.Set.t option; (** set of taint sources in backward mode. None means undefined *)
      mutable handlers: (int, Data.Address.t) Hashtbl.t * (int -> Asm.stmt list); (** table of user defined handlers * default handler behavior *)
    }

    (** the state identificator counter *)
    let state_cpt = ref 0

    (** returns a fresh state identificator *)
    let new_state_id () = state_cpt := !state_cpt + 1; !state_cpt

    (** state equality returns true whenever they are the physically the same (do not compare the content) *)
    let equal s1 s2   = s1.id = s2.id

    (** state comparison: returns 0 whenever they are the physically the same (do not compare the content) *)
    let compare s1 s2 = s1.id - s2.id
    (** otherwise return a negative integer if the first state has been created before the second one; a positive integer if it has been created later *)

    (** hashes a state *)
    let hash b  = b.id

  end

  module G = Graph.Imperative.Digraph.ConcreteBidirectional(State)
  open State


  class oracle (d: domain) (handlers: (((int, Data.Address.t) Hashtbl.t) * (int -> Asm.stmt list))) =
  object
    method value_of_register (reg: Register.t) = Domain.value_of_register d reg

    method get_handler i = 
      try
        State.Direct (Hashtbl.find (fst handlers) i)
      with Not_found -> State.Inlined ((snd handlers) i)
  end

  (** type of a CFA *)
  type t = G.t * (Data.Address.t, State.t list) Hashtbl.t

  (* utilities for memory and register initialization with respect to the provided configuration *)
  (***********************************************************************************************)


  (* return the given domain updated by the initial values and intitial tainting for registers with respected ti the provided configuration *)
  let init_registers d =
    (* the domain d' is updated with the content for each register with initial content and tainting value given in the configuration file *)
    List.fold_left
      (fun (d, taint) rcontent  ->
        let rname = fst rcontent in
        let v = snd rcontent in
        let r = Register.of_name rname in
        Init_check.check_register_init r v;
        let d', taint' = Domain.set_register_from_config r v d in
        d', Taint.Set.union taint taint'
      )
      (d, Taint.Set.singleton Taint.U) (List.append (!Config.registers_from_dump) (List.rev !Config.register_content))

    (* main function to initialize memory locations (Global/Stack/Heap) both for content and tainting *)
    (* this filling is done by iterating on corresponding lists in Config *)
    let init_mem domain region content_list =
        List.fold_left (fun (domain, prev_taint) entry -> let addr, nb = fst entry in
                            let content = snd entry in
                            L.debug (fun p->p "init: %x" (Z.to_int addr));
                            let addr' = Data.Address.of_int region addr !Config.address_sz in
                            let d', taint' = Domain.set_memory_from_config addr' content nb domain in
                            d', Taint.Set.union prev_taint taint'
                     ) (domain, Taint.Set.singleton Taint.U) (List.rev content_list)
      (* end of init utilities *)

    let get_content_size c =
      match c with
      | Some c' -> Config.size_of_content c'
      | None -> 0
         
    let init_heap ip domain content_list =
      (* TODO: factorize with init_mem *)
      List.fold_left
        (fun (domain, prev_taint) entry ->
          let offset, nb = fst entry in
          let content = snd entry in
          let content_size = Z.of_int (get_content_size (fst content)) in
          let nb' = Z.of_int nb in
          let region, id = Data.Address.new_heap_region (Z.mul nb' content_size) in
          Hashtbl.add Dump.heap_id_tbl id ip;
          let addr' = Data.Address.of_int region offset !Config.address_sz in
          let d', taint =
            Domain.set_memory_from_config addr' content nb domain
          in
          d', Taint.Set.union prev_taint taint
        ) (domain, Taint.Set.singleton Taint.U) (List.rev content_list)
  
      
  let update_abstract_value ip d =
    (* initialisation of Global memory + registers *)
    let d', taint1 = init_registers d in
    let d', taint2 = init_mem d' Data.Address.Global !Config.memory_content in
    (* init of the Heap memory *)
    let d', taint3 = init_heap ip d' !Config.heap_content in
    d', Taint.Set.union taint3 (Taint.Set.union taint2 taint1)

  let init_abstract_value ip init_reg =
    let d  = List.fold_left (fun d r ->
                 let exp =
                   try
                     Some (List.assoc r init_reg)
                   with Not_found -> None
                 in
                 Domain.add_register r d exp) (Domain.init()) (Register.used()) in
      update_abstract_value ip d


  (* CFA creation.
     Return the abstract value generated from the Config module *)
    
  let init_state (ip: Data.Address.t) init_reg default_handlers: State.t =
    let d', _taint = init_abstract_value ip init_reg in
    {
      id = 0;
      ip = ip;
      v = d';
      back_v = None;
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
      taint_sources = Taint.Set.singleton Taint.U;
      back_taint_sources = None;
      handlers = Hashtbl.create 5, default_handlers;
    }


  (* CFA utilities *)
  (*****************)

  let update_ips (_g, ips) v =
    let states =
       try Hashtbl.find ips v.State.ip
      with Not_found -> []
    in
    Hashtbl.replace ips v.State.ip (v::states)
    
  let copy_state (g, _ips) v =
    let v = { v with id = new_state_id() } in
    G.add_vertex g v;
    v


  let create () = G.create (), Hashtbl.create 117

  let remove_state (g, ips: t) (v: State.t): unit =
    let vid = v.State.id in
    let rec remove l =
      match l with
      | [] -> []
      | a::l ->
         if a.State.id = vid then l else a::(remove l)
    in
    let states =
      try
        remove (Hashtbl.find ips v.State.ip)
      with Not_found -> []
    in
    G.remove_vertex g v;
    Hashtbl.replace ips v.State.ip states

  let remove_successor ((g, _): t) (src: State.t) (dst: State.t): unit = G.remove_edge g src dst

  let add_state (g, _ips: t) (v: State.t): unit =
    G.add_vertex g v

  let add_successor (g, _ips) src dst: unit = G.add_edge g src dst


  (** returns the list of successors of the given vertex in the given CFA *)
  let succs (g, _) v  = G.succ g v

  let iter_state (f: State.t -> unit) (g, _: t): unit = G.iter_vertex f g

  let iter_state_ip (f: State.t -> unit) (_, ips) ip =
    try List.iter f (Hashtbl.find ips ip)
    with Not_found -> ()

  let pred (g, _ips: t) (v: State.t): State.t =
    try List.hd (G.pred g v)
    with _ -> raise (Invalid_argument "vertex without predecessor")

  let sinks (g, ips: t): State.t list =
    G.fold_vertex (fun v l -> if succs (g, ips) v = [] then v::l else l) g []

  let last_addr (_, ips: t) (ip: Data.Address.t): State.t =
    try List.hd (Hashtbl.find ips ip)
    with _ -> raise Not_found

  let print (dumpfile: string) (g, _: t): unit =
    let f = open_out dumpfile in
    (* state printing (detailed) *)
    let print_field = if !Config.analysis = Config.Backward then
        fun s id ->
          match s.back_v with
          | None -> Domain.to_string s.v id
          | Some v -> Domain.to_string v id
      else
         fun s id -> Domain.to_string s.v id
    in
    let print_ip s =
      let bytes = List.fold_left (fun s c -> s ^" " ^ (Printf.sprintf "%02x" (Char.code c))) "" s.bytes in
      Printf.fprintf f "[node = %d]\naddress = %s\nbytes =%s\nfinal =%s\ntainted=%s\n" s.id
        (Data.Address.to_string s.ip) bytes (string_of_bool s.final)
        (Taint.string_of_set s.taint_sources);
      if !Config.loglevel > 2 then
        begin
          Printf.fprintf f "statements =";
          List.iter (fun stmt -> Printf.fprintf f " %s\n" (Asm.string_of_stmt stmt true)) s.stmts;
        end
      else
        Printf.fprintf f "\n";
      List.iter (fun v -> Printf.fprintf f "%s\n" v) (print_field s s.id);
      Printf.fprintf f "\n";
    in
    begin
    match !(Config.argv_options.Config.no_state) with
        | None | Some (false) ->  G.iter_vertex print_ip g;
        | Some (true) -> ();
    end;
    let architecture_str = Config.archi_to_string !Config.architecture in
    Printf.fprintf f "\n[program]\nnull = 0x%s\nmem_sz=%d\nstack_width=%d\n" (Z.format "%02x" (!Config.null_cst) ) (!Config.address_sz)(!Config.stack_width);
    Printf.fprintf f "architecture = %s\n\n" architecture_str;
    (* taint sources *)
    Printf.fprintf f "[taint sources]\n"; 
    Hashtbl.iter (fun id src -> Printf.fprintf f "%d = %s\n" id (Dump.string_of_src src)) Dump.taint_src_tbl;
    Printf.fprintf f "\n";
    Printf.fprintf f "[heap ids]\n";
    Hashtbl.iter (fun id ip -> Printf.fprintf f "heap-%d = %s\n" id (Data.Address.to_string ip)) Dump.heap_id_tbl;
    Printf.fprintf f "\n";
    (* edge printing (summary) *)
    Printf.fprintf f "[edges]\n";
    G.iter_edges_e (fun e -> Printf.fprintf f "e%d_%d = %d -> %d\n" (G.E.src e).id (G.E.dst e).id (G.E.src e).id (G.E.dst e).id) g;
    close_out f;;


  let marshal (fid: out_channel) (cfa, ips: t): unit =
    Marshal.to_channel fid cfa [Marshal.Closures];
    Marshal.to_channel fid ips [Marshal.Closures];
    Marshal.to_channel fid !state_cpt [];;
  
  let unmarshal fid: t =
    let origcfa = Marshal.from_channel fid in
    let origips = Marshal.from_channel fid in
    let last_id = Marshal.from_channel fid in
    state_cpt := last_id;
    origcfa, origips

end
(** module Cfa *)
