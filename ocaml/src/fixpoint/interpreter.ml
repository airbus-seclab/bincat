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

(** Fixpoint iterator *)

module L = Log.Make(struct let name = "interpreter" end)

module Make(D: Domain.T)(Decoder: Decoder.Make)(Stubs: Stubs.T with type domain_t = D.t) =
struct

  module Decoder = Decoder(D)(Stubs)
  module Cfa = Decoder.Cfa
 

 (* Hash table to know when a widening has to be processed, that is when the associated value reaches the threshold Config.unroll *)
  let unroll_tbl: ((Data.Address.t, int * D.t) Hashtbl.t) ref = ref (Hashtbl.create 1000)
                                                              
  (* Hash table to store number of times a function has been analysed *)
  let fun_unroll_tbl: (Data.Address.t, int) Hashtbl.t = Hashtbl.create 10
                                                      
  (* current unroll value *)
  (* None is for the default value set in Config *)
  let unroll_nb = ref None

  (** widen the given state with all previous vertices that have the same ip as v *)
  let widen prev v =
    v.Cfa.State.final <- true;
    v.Cfa.State.v <- D.widen prev v.Cfa.State.v
    
    (** update the abstract value field of the given vertices wrt to their list of statements and the abstract value of their predecessor
    the widening may be also launched if the threshold is reached *)    
  let update_abstract_value (g: Cfa.t) (v: Cfa.State.t) (get_field: Cfa.State.t -> D.t) (ip: Data.Address.t) (process_stmts: Cfa.t -> Cfa.State.t -> Data.Address.t -> Cfa.State.t list): Cfa.State.t list =
      try
        let l = process_stmts g v ip in
        List.iter (fun v ->
          let d = get_field v in
          let n, jd =
            try
              let n', jd' = Hashtbl.find !unroll_tbl ip in
              let d' = D.join jd' d in
              Hashtbl.replace !unroll_tbl ip (n'+1, d'); n'+1, jd'
            with Not_found ->
              Hashtbl.add !unroll_tbl v.Cfa.State.ip (1, d);
              1, d
          in
          let nb_max = 
            match !unroll_nb with
            | None -> !Config.unroll
            | Some n -> n
          in
          if n <= nb_max then
            ()
          else
            begin
              L.analysis (fun p -> p "widening occurs at %s" (Data.Address.to_string ip));
              widen jd v
            end
        ) l;
        List.fold_left (fun l' v ->
          if D.is_bot (get_field v) then
            begin
              L.analysis (fun p -> p "unreachable state at address %s" (Data.Address.to_string ip));
              Cfa.remove_state g v; l'
            end
          else v::l') [] l (* TODO: optimize by avoiding creating a state then removing it if its abstract value is bot *)
      with Exceptions.Empty _ -> L.analysis (fun p -> p "No new reachable states from %s\n" (Data.Address.to_string ip)); []

  let is_subset prev v' =
    Data.Address.equal prev.Cfa.State.ip v'.Cfa.State.ip && (* TODO: optimize as normally is_subset is called on same ip addresses *)
      prev.Cfa.State.ctx.Cfa.State.addr_sz = v'.Cfa.State.ctx.Cfa.State.addr_sz &&
        prev.Cfa.State.ctx.Cfa.State.op_sz = v'.Cfa.State.ctx.Cfa.State.op_sz &&        
                                                   (* fixpoint reached *)
          D.is_subset v'.Cfa.State.v prev.Cfa.State.v

 (** [filter_vertices subsuming g vertices] returns vertices in _vertices_ that are not already in _g_ 
     (same address and same decoding context and subsuming abstract value if subsuming = true) *)
    let filter_vertices (subsuming: bool) g vertices =
      (* predicate to check whether a new state has to be explored or not *)
     
      let res =
        List.fold_left (fun l v ->
          try
            (* filters on cutting instruction pointers *)
            if Config.SAddresses.mem (Data.Address.to_int v.Cfa.State.ip) !Config.blackAddresses then
              begin
              L.analysis (fun p -> p "Address %s reached but not explored because it belongs to the cut off branches\n"
                        (Data.Address.to_string v.Cfa.State.ip));
              raise Exit
              end
            else
              
              (* explore if a greater abstract state of v has already been explored *)
              if subsuming then
                begin
                  Cfa.iter_state_ip (fun prev ->
                      if v.Cfa.State.id = prev.Cfa.State.id then
                        ()
                      else
                        if is_subset prev v then
                          begin
                            L.analysis (fun p -> p "fixed point reached between (%d) and (%d)" prev.Cfa.State.id v.Cfa.State.id);
                            raise Exit
                          end
                   
                    ) g v.Cfa.State.ip;
                  v::l
                end
              else v::l
          with
            Exit -> l
          ) [] vertices
      in
      L.debug (fun p -> p "at filter_vertices: %d new vertices to explore. Before filter: %d vertices" (List.length (res)) (List.length vertices));
      if List.length res > 0 then
        begin
          List.iter(fun rv -> L.debug (fun p -> p "remaining vertice to explore: %d" rv.Cfa.State.id) ) res;
        end;
      res
     
                
    let cfa_iteration (update_abstract_value: Cfa.t -> Cfa.State.t -> Data.Address.t -> Cfa.State.t list -> Cfa.State.t list)
        (next: Cfa.t -> Cfa.State.t -> Cfa.State.t list)
        (unroll: Cfa.t -> Cfa.State.t -> Cfa.State.t -> Cfa.State.t) (g: Cfa.t) (s: Cfa.State.t) (dump: Cfa.t -> unit): Cfa.t =
      if D.is_bot s.Cfa.State.v then
        begin
          dump g;
          L.abort (fun p -> p "analysis not started: empty meet with previous computed value")
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
            let new_vertices =
              List.fold_left (fun l v' -> (update_abstract_value g v v'.Cfa.State.ip [v'])@l) [] v'
            in
            let new_vertices' = List.map (unroll g v) new_vertices in
            let vertices' = filter_vertices false g new_vertices' in
            List.iter (fun v ->
                Cfa.update_ips g v;
                waiting := Vertices.add v !waiting) vertices';
            continue := not (Vertices.is_empty !waiting);
          done;
          g
        with
        | Invalid_argument _ -> L.analysis (fun p -> p "entry node of the CFA reached"); g
        | e -> dump g; raise e

    module Core =
      struct
        type ctx_t = Decoder.ctx_t
        let unroll_nb = unroll_nb
        let cfa_iteration = cfa_iteration
        let update_abstract_value = update_abstract_value
        let parse = Decoder.parse
        let init = Decoder.init
        let unroll_tbl = unroll_tbl
        let fun_unroll_tbl = fun_unroll_tbl
        let filter_vertices = filter_vertices
      end
      
    module Forward = Forward.Make(D)(Cfa)(Stubs)(Decoder)(Core)
    module Backward = Backward.Make(D)(Cfa)(Decoder)(Core)
   
    (************* INTERLEAVING OF FORWARD/BACKWARD ANALYSES *******)
    let interleave_from_cfa (g: Cfa.t) (dump: Cfa.t -> unit): Cfa.t =
      L.analysis (fun p -> p "entering interleaving mode");
      let process mode cfa =
        Hashtbl.clear !unroll_tbl;
        List.fold_left (fun g s0 -> mode g s0 dump) cfa (Cfa.sinks cfa)
      in
      let g_bwd = process Backward.from_cfa g in
      process Forward.from_cfa g_bwd
      
    let make_registers () = Decoder.init_registers ()
end
