(*
    This file is part of BinCAT.
    Copyright 2014-2020 - Airbus

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

module Make(D: Domain.T)(Decoder: Decoder.Make) =
struct

    (** stubs *)
    module Stubs = Stubs.Make(D)

    (** Decoder *)
    module Decoder = Decoder(D)(Stubs)

   

    (** Control Flow Automaton *)
    module Cfa = Decoder.Cfa

module B = Backward
module F = Forward
    open Asm

  

    (** opposite the given comparison operator *)
    let inv_cmp (cmp: Asm.cmp): Asm.cmp =
      match cmp with
      | EQ  -> NEQ
      | NEQ -> EQ
      | LT  -> GEQ
      | GEQ -> LT
      | LEQ -> GT
      | GT  -> LEQ

    let restrict (d: D.t) (e: Asm.bexp) (b: bool): (D.t * Taint.Set.t) =
      L.debug (fun p -> p "restrict: e=%s b=%B" (Asm.string_of_bexp e true) b);
      let rec process e b =
        match e with
        | BConst b'           -> if b = b' then d, Taint.Set.singleton Taint.U else D.bot, Taint.Set.singleton Taint.BOT
        | BUnOp (LogNot, e)  -> process e (not b)

        | BBinOp (LogOr, e1, e2)  ->
           let v1, taint1 = process e1 b in
           let v2, taint2 = process e2 b in
           let taint_sources =
             if b then Taint.Set.union taint1 taint2
             else Taint.Set.inter taint1 taint2
           in
           if b then D.join v1 v2, taint_sources
           else D.meet v1 v2, taint_sources
             
        | BBinOp (LogAnd, e1, e2) ->
           let v1, taint1 = process e1 b in
           let v2, taint2 = process e2 b in
           let taint_sources =
             if b then Taint.Set.inter taint1 taint2
             else Taint.Set.union taint1 taint2 in
           if b then D.meet v1 v2, taint_sources
           else D.join v1 v2, taint_sources

        | Asm.Cmp (cmp, e1, e2)   ->
           let cmp' = if b then cmp else inv_cmp cmp in
           D.compare d e1 cmp' e2
      in
      process e b


    (*************************** Forward from binary file ************************)
    (*****************************************************************************)


    (** returns true whenever the given list of statements has a jump stmt (Jmp, Call, Return) *)
    let rec has_jmp stmts =
        match stmts with
        | [] -> false
        | s::stmts' ->
             match s with
             | Call _ | Return  | Jmp _ -> true
             | If (_, tstmts, estmts)   -> (has_jmp tstmts) || (has_jmp estmts)
             | _                -> (has_jmp stmts')

    let unroll_wrapper (f: unit -> int): unit =
      try
        match !unroll_nb with
        | Some _ -> ()
        | None ->
           let n = max (f ()) !Config.unroll in
           unroll_nb := Some n;
           L.analysis (fun p -> p "automatic loop unrolling detection. Computed value is 0x%x" n)
      with _ -> ()

    exception Jmp_exn

    type fun_stack_t = ((string * string) option * Data.Address.t * Cfa.State.t * (Data.Address.t, int * D.t) Hashtbl.t) list ref

    let rec process_value (ip: Data.Address.t) (d: D.t) (s: Asm.stmt) (fun_stack: fun_stack_t) (node_id: int): D.t * Taint.Set.t =
        L.debug2 (fun p -> p "process_value VVVVVVVVVVVVVVVVVVVVVVVVVVVVVV\n%s\n---------\n%s\n---------" (String.concat " " (D.to_string d node_id)) (Asm.string_of_stmt s true));
      try
        let res, tainted =
            match s with
            | Nop                -> d, Taint.Set.singleton Taint.U
            | If (e, then_stmts, else_stmts) -> process_if ip d e then_stmts else_stmts fun_stack node_id
            | Set (dst, src)         -> D.set dst src d
            | Directive (Remove r)       -> let d' = D.remove_register r d in Register.remove r; d', Taint.Set.singleton Taint.U
            | Directive (Forget lval)        -> D.forget_lval lval d, Taint.Set.singleton Taint.U
            | Directive (Unroll (e, bs)) ->
               begin
                 try
                   let f () = min ((Z.to_int (D.value_of_exp d e)) + 1) bs in
                   unroll_wrapper f
                 with _ -> ()
               end;
              d, Taint.Set.singleton Taint.U

            | Directive (Default_unroll) ->
               L.analysis (fun p -> p "set unroll parameter to its default value");
              unroll_nb := None;
              d, Taint.Set.singleton Taint.U

            | Asm.Directive (Asm.Unroll_until (addr, cmp, terminator, upper_bound, sz)) ->
               begin
                 try
                   let f () =
                     D.get_offset_from addr cmp terminator upper_bound sz d
                   in
                   unroll_wrapper f;
                 with _ -> ()
               end;
               d, Taint.Set.singleton Taint.U

            | Directive (Taint (e, lv))      ->
                begin
                 match lv with
                 | V (T r) ->
                    begin
                      match e with
                      | None ->
                         let taint_src = Taint.new_src () in
                         Hashtbl.add Dump.taint_src_tbl taint_src (Dump.R r);
                         let mask = Config.Taint_all taint_src in
                         D.taint_register_mask r mask d
                      | Some c ->
                         let taints = D.taint_sources c d in
                         let taint' = Taint.Set.fold Taint.logor taints Taint.U in
                         (* TODO: could be more precise here  but  taint_sources should be inlined in span_taint_to_register *)
                         D.span_taint_to_register r taint' d
                    end

                 | M (_, 8) ->
                    begin
                      try

                        match Data.Address.Set.elements (fst (D.mem_to_addresses d (Lval lv))) with
                        | [a] ->
                           begin
                             match e with
                             | None ->
                                let taint_src = Taint.new_src () in
                                Hashtbl.add Dump.taint_src_tbl taint_src (Dump.M (a, 8));
                                D.taint_address_mask a [Config.Taint (Z.of_int 0xff, taint_src)] d
                             | Some c ->
                                let taints = D.taint_sources c d  in
                                let taint' = Taint.Set.fold Taint.logor taints Taint.U in
                                (* TODO/ same remark on precision *)
                                D.span_taint_to_addr a taint' d
                           end
                        | _ -> raise Exit
                      with _ -> L.analysis (fun p -> p "Tainting directive ignored"); d, Taint.Set.singleton Taint.U
                    end
                 | _ -> L.analysis (fun p -> p "Tainting directive for %s ignored" (Asm.string_of_lval lv false)); d, Taint.Set.singleton Taint.U
               end
            | Directive (Type (lv, t)) -> D.set_type lv t d, Taint.Set.singleton Taint.U

            | Directive (Skip (f, call_conv)) as skip_statement ->
               L.analysis (fun p -> p "Skipping %s" (Asm.string_of_fun f));
               (* TODO: optimize to avoid type switching *)
               let f' =
                 match f with
                 | Asm.Fun_name s -> Config.Fun_name s
                 | Asm.Fun_addr a -> Config.Fun_addr (Data.Address.to_int a)
               in                                   
               let d',  taint, cleanup_stmts = Stubs.skip d f' call_conv in
               let d', taint' =
                 Log.Trace.trace (Data.Address.global_of_int (Z.of_int 0))  (fun p -> p "%s" (string_of_stmts (skip_statement :: cleanup_stmts) true));
                 List.fold_left (fun (d, t) stmt ->
                     let dd, tt = process_value ip d stmt fun_stack node_id in
                     dd, Taint.Set.union t tt) (d', taint) cleanup_stmts
               in
               d', taint'
               
            | Directive (Stub (fun_name, call_conv)) as stub_statement ->
               let prev_ip =
                 try
                   let _, _, v, _ = List.hd !fun_stack in
                   Some v.Cfa.State.ip
                 with Failure _ -> None
               in
               let d', taint', cleanup_stmts = Stubs.process ip prev_ip d fun_name call_conv in
               let d', taint' =
                 Log.Trace.trace (Data.Address.global_of_int (Z.of_int 0))  (fun p -> p "%s" (string_of_stmts (stub_statement :: cleanup_stmts) true));
                 List.fold_left (fun (d, t) stmt ->
                     let dd, tt = process_value ip d stmt fun_stack node_id in
                     dd, Taint.Set.union t tt) (d', taint') cleanup_stmts
               in
               d', taint'
              
            | _ -> raise Jmp_exn
                 
        in
        res, tainted
      with Exceptions.Empty _ -> D.bot, Taint.Set.singleton Taint.BOT

    and process_if (ip: Data.Address.t) (d: D.t) (e: Asm.bexp) (then_stmts: Asm.stmt list) (else_stmts: Asm.stmt list) fun_stack (node_id: int) =
      if has_jmp then_stmts || has_jmp else_stmts then
             raise Jmp_exn
           else
             let dt, bt = List.fold_left (fun (d, b) s -> let d', b' = process_value ip d s fun_stack node_id in d', Taint.Set.union b b') (restrict d e true) then_stmts in
             let de, be = List.fold_left (fun (d, b) s -> let d', b' = process_value ip d s fun_stack node_id in d', Taint.Set.union b b') (restrict d e false) else_stmts in
             D.join dt de, Taint.Set.union bt be

    (** returns the result of the transfert function corresponding to the statement on the given abstract value *)
    let skip_or_import_call vertices a fun_stack =     
      (* will raise Not_found if no import or skip is found *)
      L.debug2 (fun p -> p "skip_or_import_tbl at %s" (Data.Address.to_string a));
      let fundec =
        try
          let import_desc = Hashtbl.find Decoder.Imports.tbl a in
            Decoder.Imports.skip (Some import_desc) a
        with
        | Not_found -> Decoder.Imports.skip None a
      in
        let stmts = fundec.Asm.prologue @ fundec.Asm.stub @ fundec.Asm.epilogue in
        let ret_addr_exp = fundec.Asm.ret_addr in
        let t =
            List.fold_left (fun t v ->             
                let d', t' =
                  List.fold_left (fun (d, t) stmt ->
                      let d', t' = process_value a d stmt fun_stack v.Cfa.State.id in
                      d', Taint.Set.union t t') (v.Cfa.State.v, Taint.Set.singleton Taint.U) stmts
                in
                v.Cfa.State.v <- d';
                let addrs, _ = D.mem_to_addresses d' ret_addr_exp in
                let a =
                  match Data.Address.Set.elements addrs with
                  | [a] -> a
                  | []  -> L.abort (fun p->p "no return address")
                  | _l  -> L.abort (fun p->p "multiple return addresses")
                in
                L.analysis (fun p -> p "returning from stub to %s" (Data.Address.to_string a));
                v.Cfa.State.ip <- a;
                Log.Trace.trace a (fun p -> p "%s"
                                              (Asm.string_of_stmts [ Asm.Jmp(R ret_addr_exp) ] true));
                Taint.Set.union t t') (Taint.Set.singleton Taint.U) vertices
        in
        vertices, t

    
    let process_stmts fun_stack g (v: Cfa.State.t) (ip: Data.Address.t): Cfa.State.t list =
        let fold_to_target (apply: Data.Address.t -> unit) (vertices: Cfa.State.t list) (target: Asm.exp) : (Cfa.State.t list * Taint.Set.t) =
            let import = ref false in
            let res =
                List.fold_left (fun (l, t) v ->
                    try
                        let addrs, taint_sources = D.mem_to_addresses v.Cfa.State.v target in
                        let addresses = Data.Address.Set.elements addrs in
                        match addresses with
                        | [a] ->
                          begin
                              L.debug (fun p->p "fold_to_target addr : %s" (Data.Address.to_string a));
                              try let res = skip_or_import_call [v] a fun_stack in import := true; res
                              with Not_found -> v.Cfa.State.ip <- a; apply a; v::l, Taint.Set.union t taint_sources
                          end
                        | [] -> L.abort (fun p -> p "Unreachable jump target from ip = %s\n" (Data.Address.to_string v.Cfa.State.ip))
                        | l -> L.abort (fun p -> p "Please select between the addresses %s for jump target from %s\n"
                                              (List.fold_left (fun s a -> s^(Data.Address.to_string a)) "" l) (Data.Address.to_string v.Cfa.State.ip))
                    with
                    | Exceptions.Too_many_concrete_elements _ as e ->
                       L.exc_and_abort e (fun p -> p "Uncomputable set of address targets for jump at ip = %s\n" (Data.Address.to_string v.Cfa.State.ip))
                ) ([], Taint.Set.singleton Taint.U) vertices
            in
            if !import then begin try fun_stack := List.tl !fun_stack with Failure _ -> () end; 
            res

      in
      let add_to_fun_stack a =
        begin
        try
          let n' = (Hashtbl.find fun_unroll_tbl a) + 1 in
          if n' <= !Config.fun_unroll then
          Hashtbl.replace fun_unroll_tbl a n'
          else
            L.abort (fun p -> p "function at %s has been analysed more than %d times. Analysis stops" (Data.Address.to_string a) !Config.fun_unroll)
        with Not_found -> Hashtbl.add fun_unroll_tbl a 1
        end;
        let f =
          try
            Some (Hashtbl.find Config.import_tbl (Data.Address.to_int a))
          with Not_found -> None
        in
        fun_stack := (f, ip, v, !unroll_tbl)::!fun_stack;
        unroll_tbl := Hashtbl.create 1000
      in
      
      let copy v d branch is_pred =
    (* TODO: optimize with Cfa.State.copy that copies every field and then here some are updated => copy them directly *)
        let v' = Cfa.copy_state g v in
        v'.Cfa.State.stmts <- [];
        v'.Cfa.State.v <- d;
        v'.Cfa.State.branch <- branch;
        v'.Cfa.State.bytes <- [];
        v'.Cfa.State.taint_sources <- Taint.Set.singleton Taint.U;
        if is_pred then
          Cfa.add_successor g v v'
        else
          Cfa.add_successor g (Cfa.pred g v) v';
        v'
      in


    let iprocess_ret ipstack v fun_stack =
      let d = v.Cfa.State.v in
      let sp = Register.stack_pointer () in
      let ip_on_stack, taint_sources = D.mem_to_addresses d (Asm.Lval (Asm.M (Asm.Lval (Asm.V (Asm.T sp)), (Register.size sp)))) in
      match Data.Address.Set.elements (ip_on_stack) with
      | [a] ->
         begin
           match ipstack with
           | Some ip' ->
              if not (Data.Address.equal ip' a) then
                L.analysis (fun p -> p "computed instruction pointer %s differs from instruction pointer found on the stack %s at RET instruction"
                                       (Data.Address.to_string ip') (Data.Address.to_string a))
           | None -> ()
         end;
        
         begin
           try
             add_to_fun_stack a;
             let vert, t = skip_or_import_call [v] a fun_stack in
             Some vert, t
           with Not_found ->
             v.Cfa.State.ip <- a;
             Some [v], taint_sources
         end
      | _ -> L.abort (fun p -> p "computed instruction pointer at return instruction is either undefined or imprecise")

    in  
               
    let process_ret (fun_stack: fun_stack_t) v =
      try
        let _f, ipstack, _v, prev_unroll_tbl = List.hd !fun_stack in
        fun_stack := List.tl !fun_stack;
        unroll_tbl := prev_unroll_tbl;
        iprocess_ret (Some ipstack) v fun_stack
      with Failure _ ->
        L.analysis (fun p -> p "RET without previous CALL at address %s" (Data.Address.to_string v.Cfa.State.ip));
        iprocess_ret None v fun_stack

    in
      
      let rec process_if_with_jmp (vertices: Cfa.State.t list) (e: Asm.bexp) (istmts: Asm.stmt list) (estmts: Asm.stmt list) =
        let process_branch stmts branch =
          let vertices', b = (List.fold_left (fun (l, b) v ->
            try
              let d, taint_sources = restrict v.Cfa.State.v e branch in
              if D.is_bot d then
                l, b
              else
                (copy v d (Some true) false)::l, Taint.Set.union b taint_sources
            with Exceptions.Empty "Interpreter.process_if_with_jmp" -> l, b) ([], Taint.Set.singleton Taint.U) vertices)
          in
          let vert, b' = process_list vertices' stmts in
          vert, Taint.Set.union b b'
        in
        let then', bt = process_branch istmts true in
        let else', be = process_branch estmts false in
        List.iter (fun v -> Cfa.remove_state g v) vertices;
        then' @ else', Taint.Set.union be bt


      and process_vertices (vertices: Cfa.State.t list) (s: Asm.stmt) : (Cfa.State.t list * Taint.Set.t) =
        try
          List.fold_left (fun (l, b) v -> let d, b' = process_value v.Cfa.State.ip v.Cfa.State.v s fun_stack v.Cfa.State.id in
                                          v.Cfa.State.v <- d;
                                          let taint = Taint.Set.union b b' in
                                          (*v.Cfa.State.taint_sources <- taint;*)
                                          v::l, taint) ([], Taint.Set.singleton Taint.U) vertices
        with Jmp_exn ->
             match s with
             | If (e, then_stmts, else_stmts) -> process_if_with_jmp vertices e then_stmts else_stmts 

             | Jmp (A a) ->
                begin
                  try
                    let res = skip_or_import_call vertices a fun_stack in
                    fun_stack := List.tl !fun_stack;
                    res
                  with Not_found ->
                    List.map (fun v -> v.Cfa.State.ip <- a; v) vertices, Taint.Set.singleton Taint.U
                end

             | Jmp (R target) ->
                begin
                  match target with
                  | Lval (M (Const c, _)) ->
                     begin
                       let a = Data.Address.of_word c in
                       try
                         let res = skip_or_import_call vertices a fun_stack in
                         fun_stack := List.tl !fun_stack;
                         res
                       with Not_found ->
                         List.map (fun v -> v.Cfa.State.ip <- a; v) vertices, Taint.Set.singleton Taint.U
                     end
                    
                  | target -> fold_to_target (fun _a -> ()) vertices target
                end
                  
               
             | Call (A a) ->
                add_to_fun_stack a;
                begin
                  try
                    skip_or_import_call vertices a fun_stack
                  with Not_found ->
                    List.iter (fun v -> v.Cfa.State.ip <- a) vertices;
                    vertices, Taint.Set.singleton Taint.U
                end
             | Call (R target) -> fold_to_target add_to_fun_stack vertices target
                                
             | Return ->
                List.fold_left (fun (l, b) v ->
                    let v', b' = process_ret fun_stack v in
                    match v' with
                    | None -> l, Taint.Set.union b b'
                    | Some v -> v@l, Taint.Set.union b b') ([], Taint.Set.singleton Taint.U) vertices
               
             | _       -> vertices, Taint.Set.singleton Taint.U

      and process_list (vertices: Cfa.State.t list) (stmts: Asm.stmt list): Cfa.State.t list * Taint.Set.t =
        match stmts with
        | s::stmts ->
           let new_vert, tainted =
             begin
               try
                 let (new_vertices: Cfa.State.t list), (t: Taint.Set.t) = process_vertices vertices s in
                 let vert, t' = process_list new_vertices stmts in
                 vert, Taint.Set.union t t'
               with Exceptions.Bot_deref -> [], Taint.Set.singleton Taint.BOT (* in case of undefined dereference corresponding vertices are no more explored. They are not added to the waiting list neither *)
             end
           in

           new_vert, tainted
        | []       -> vertices, Taint.Set.singleton Taint.U
      in
      let vstart = copy v v.Cfa.State.v None true in
      vstart.Cfa.State.ip <- ip;
      (* check if the instruction has to be skiped *)
      let ia = Data.Address.to_int v.Cfa.State.ip in
      if not (Config.SAddresses.mem ia !Config.nopAddresses) then
        let vertices, taint = process_list [vstart] v.Cfa.State.stmts in
        begin
          try
            v.Cfa.State.taint_sources <- taint;
            List.iter (fun (_f, _ip, v, _tbl) -> v.Cfa.State.taint_sources <- Taint.Set.union v.Cfa.State.taint_sources taint) !fun_stack;
          with _ as e -> raise e;
        end;
        vertices
      else
        begin
          Log.Trace.trace v.Cfa.State.ip (fun p -> p "nop ; forced by config");
          L.analysis(fun p -> p "Instruction at address %s nopped by config"
                                (Data.Address.to_string v.Cfa.State.ip));
          [vstart]
        end

    let forward_cfa (g: Cfa.t) (s: Cfa.State.t) (dump: Cfa.t -> unit): Cfa.t =
      Core.cfa_iteration (fun g v ip vert -> List.fold_left (fun l v' -> (forward_abstract_value g v ip v')@l) [] vert)
        Cfa.succs unroll g s dump

   

          
    (** fixpoint iterator to build the CFA corresponding to the provided code starting from the initial state s.
     g is the initial CFA reduced to the singleton s *)
    let forward_bin (mapped_mem: Mapped_mem.t) (g: Cfa.t) (s: Cfa.State.t) (dump: Cfa.t -> unit): Cfa.t =
      let module Vertices = Set.Make(Cfa.State) in
      (* check whether the instruction pointer is in the black list of addresses to decode *)
      if Config.SAddresses.mem (Data.Address.to_int s.Cfa.State.ip) !Config.blackAddresses then
        L.abort (fun p -> p "Interpreter not started as the entry point belongs to the cut off branches\n");
      (* boolean variable used as condition for exploration of the CFA *)
      let continue = ref true             in
      (* set of waiting nodes in the CFA waiting to be processed *)
      let waiting  = ref (Vertices.singleton s) in
      (* set d to the initial internal state of the decoder *)
      let d = ref (Decoder.init ())             in
      (* function stack *)
      let fun_stack = ref []                    in
      let hash_add_or_append htbl key rules =
        try
        let existing = Hashtbl.find htbl key in
            Hashtbl.replace htbl key (rules @ existing)
        with Not_found -> Hashtbl.add htbl key rules
      in
      (* compute override rules to apply *)
      let overrides = Hashtbl.create 5 in
      Hashtbl.iter (fun z rules ->
        let ip = Data.Address.of_int Data.Address.Global z !Config.address_sz in
        let rules' =
          List.map (fun (rname, rfun) ->
              let reg = Register.of_name rname in
              let rule = rfun reg in
            Init_check.check_register_init reg rule;
            D.set_register_from_config reg rule) rules
        in
        hash_add_or_append overrides ip rules'
        ) Config.reg_override;
     

      List.iter (fun (tbl, region) ->
        Hashtbl.iter (fun z rules ->
            let ip = Data.Address.of_int Data.Address.Global z !Config.address_sz in
            let rules' =
              List.map (fun ((addr, nb), rule) ->
                  L.analysis (fun p -> p "Adding override rule for address 0x%x" (Z.to_int addr));
                  Init_check.check_mem rule None;
                  let addr' = Data.Address.of_int region addr !Config.address_sz in
                  match rule with
                       | (Some _, _) -> D.set_memory_from_config addr' rule nb
                       | (None, t) -> D.taint_address_mask addr' t
                ) rules
            in
            hash_add_or_append overrides ip rules'

        ) tbl)
        [Config.mem_override, Data.Address.Global ];

        Hashtbl.iter (fun z rules ->
          let ip = Data.Address.of_int Data.Address.Global z !Config.address_sz in
          try
            let rules' =
              List.map (fun (((id, offset), nb), rule) ->
                let id' = Z.to_int id in
                L.analysis (fun p -> p "Adding override rule for heap id %d" id');
                let heap_sz = Data.Address.size_of_heap_region id' in
                Init_check.check_mem rule (Some heap_sz);
                let addr' = Data.Address.of_int (Data.Address.Heap(id', heap_sz)) offset !Config.address_sz in
                match rule with
                | (Some _, _) -> D.set_memory_from_config addr' rule nb
                | (None, t) -> D.taint_address_mask addr' t
              ) rules
            in
            hash_add_or_append overrides ip rules'
              with _ -> raise (Exceptions.Error "id of heap is too large")
        ) Config.heap_override;

      while !continue do
        (* a waiting node is randomly chosen to be explored *)
        let v = Vertices.choose !waiting in
        waiting := Vertices.remove v !waiting;
        begin
          try
            L.info2 (fun p -> p "################### %s" (Data.Address.to_string v.Cfa.State.ip));
            Log.current_address := Some v.Cfa.State.ip;
            (* the subsequence of instruction bytes starting at the offset provided the field ip of v is extracted *)
            let text'        = Mapped_mem.string_from_addr mapped_mem v.Cfa.State.ip !Config.max_instruction_size in
            (* the corresponding instruction is decoded and the successor state of v are computed and added to    *)
            (* the CFA                                                                                             *)
            (* except the abstract value field which is set to v.Cfa.State.value. The right value will be          *)
            (* computed next step                                                                                  *)
            (* the new instruction pointer (offset variable) is also returned                                      *)
            let r = match text' with
            | Some text'' ->  Decoder.parse text'' g !d v v.Cfa.State.ip (new Cfa.oracle v.Cfa.State.v)
            | None -> L.abort(fun p -> p "Could not retrieve %i bytes at %s to decode next instruction"
              !Config.max_instruction_size (Data.Address.to_string v.Cfa.State.ip) ) in
            begin
            match r with
            | Some (v', ip', d') ->
               Log.Trace.trace v.Cfa.State.ip (fun p -> p "%s" (Asm.string_of_stmts v.Cfa.State.stmts true));
               (* add overrides if needed *)               
               begin
                 try
                   let rules = Hashtbl.find overrides v'.Cfa.State.ip in
                   L.analysis (fun p -> p "applied %d override(s)" (List.length rules));
                       let d', taint =
                         List.fold_left (fun (d, taint) rule -> let d', taint' = rule d in d', Taint.Set.union taint taint'
                           ) (v.Cfa.State.v, v.Cfa.State.taint_sources) rules
                       in
                       v.Cfa.State.v <- d';
                       v.Cfa.State.taint_sources <- taint
                 with
                   Not_found -> ()
               end;
               (* these vertices are updated by their right abstract values and the new ip  *)
               let new_vertices = update_abstract_value g v' (fun v -> v.Cfa.State.v) ip' (process_stmts fun_stack) in
           (* among these computed vertices only new are added to the waiting set of vertices to compute       *)
           let vertices'  = filter_vertices true g new_vertices in
           List.iter (fun v -> waiting := Vertices.add v !waiting) vertices';
               (* udpate the internal state of the decoder *)
               d := d'
            | None -> ()
            end;
            Log.latest_finished_address := Some v.Cfa.State.ip;  (* v.Cfa.State.ip can change because of calls and jumps *)

          with
          | Exceptions.Too_many_concrete_elements msg ->
             L.analysis (fun p -> p "%s" msg);
           

          | Exceptions.Use_after_free msg ->
            L.analysis (fun p -> p "possible use after free in alloc %s, at: %s" msg (Data.Address.to_string v.Cfa.State.ip));
           

          | Exceptions.Undefined_free msg ->
             L.analysis (fun p -> p "undefined free detected here: %s" msg);
           
              
          | Exceptions.Double_free ->
              L.analysis (fun p -> p "possible double free detected");
          

          | Exceptions.Stop msg ->
             L.analysis (fun p -> p "analysis stopped for the current context: %s" msg)
            
          | e             -> L.exc e (fun p -> p "Unexpected exception"); dump g; raise e
        end;
        (* boolean condition of loop iteration is updated *)
        continue := not (Vertices.is_empty !waiting);
      done;
      g


    (*************************************)
    (* FORWARD AUXILARY FUNCTIONS ON CFA *)
    (*************************************)
    let unroll g v succ =
      if v.Cfa.State.final then
        begin
          v.Cfa.State.final <- false;
          let new_succ = Cfa.copy_state g v in
          new_succ.Cfa.State.forward_loop <- true;
          Cfa.remove_successor g v succ;
          Cfa.add_state g new_succ;
          Cfa.add_successor g v new_succ;
          Cfa.add_successor g new_succ succ;
          new_succ
        end
      else
        succ


    let forward_process (ip: Data.Address.t) (d: D.t) (stmt: Asm.stmt) (branch: bool option) (node_id: int): (D.t * Taint.Set.t) =
      (* function stack *)
      let fun_stack = ref [] in
      let rec forward (d: D.t) (stmt: Asm.stmt): (D.t * Taint.Set.t) =
        match stmt with
        | Asm.Nop
        | Asm.Directive (Asm.Forget _)
        | Asm.Directive (Asm.Remove _)
        | Asm.Directive (Asm.Taint _)
        | Asm.Directive (Asm.Type _)
        | Asm.Directive (Asm.Unroll _)
        | Asm.Directive (Asm.Stub _)
        | Asm.Directive (Asm.Skip _)
        | Asm.Directive (Asm.Unroll_until _)
        | Asm.Directive Asm.Default_unroll
        | Asm.Jmp (Asm.A _)
        | Asm.Return
        | Asm.Call (Asm.A _) -> d, Taint.Set.singleton Taint.U
        | Asm.Set (dst, src) -> D.set dst src d
        | Assert (_bexp, _msg) -> d, Taint.Set.singleton Taint.U (* TODO *)
        | Asm.If (e, istmts, estmts) ->
           begin
             try process_if ip d e istmts estmts fun_stack node_id
             with Jmp_exn ->
               match branch with
               | Some true -> List.fold_left (fun (d, b) stmt -> let d', b' = forward d stmt in d', Taint.Set.union b b') (restrict d e true) istmts
               | Some false -> List.fold_left (fun (d, b) stmt -> let d', b' = forward d stmt in d', Taint.Set.union b b') (restrict d e false) estmts
               | None -> L.abort (fun p -> p "Illegal call to Interpreter.forward_process")
           end
        | Asm.Call (Asm.R _) -> D.forget d, Taint.Set.singleton Taint.TOP
        | Asm.Jmp (Asm.R _) -> D.forget d, Taint.Set.singleton Taint.TOP (* TODO may be more precise but check whether the target is really in the CFA. If not then go back to forward_bin for that branch *)
      in
      forward d stmt

    let forward_abstract_value (g:Cfa.t) (succ: Cfa.State.t) (ip: Data.Address.t) (v: Cfa.State.t): Cfa.State.t list =
      let forward _g v _ip =
        let d', taint_sources = List.fold_left (fun (d, b) s ->
          let d', b' = forward_process v.Cfa.State.ip d s (succ.Cfa.State.branch) v.Cfa.State.id in
          d', Taint.Set.union b b') (v.Cfa.State.v, Taint.Set.singleton Taint.U) (succ.Cfa.State.stmts)
        in
        succ.Cfa.State.v <- D.meet succ.Cfa.State.v d';
        succ.Cfa.State.taint_sources <- taint_sources;
        [succ]
      in
      update_abstract_value g v (fun v -> v.Cfa.State.v) ip forward

    (****************************)
    (* FIXPOINT ON CFA *)
    (****************************)
    
    let backward (g: Cfa.t) (s: Cfa.State.t) (dump: Cfa.t -> unit): Cfa.t =
      cfa_iteration (fun g v ip vert -> back_update_abstract_value g v ip (List.hd vert))
        (fun g v -> [Cfa.pred g v]) back_unroll g s dump

    let forward_cfa (g: Cfa.t) (s: Cfa.State.t) (dump: Cfa.t -> unit): Cfa.t =
      cfa_iteration (fun g v ip vert -> List.fold_left (fun l v' -> (forward_abstract_value g v ip v')@l) [] vert)
        Cfa.succs unroll g s dump
      
    (************* INTERLEAVING OF FORWARD/BACKWARD ANALYSES *******)
    (***************************************************************)

    let interleave_from_cfa (g: Cfa.t) (dump: Cfa.t -> unit): Cfa.t =
      L.analysis (fun p -> p "entering interleaving mode");
      let process mode cfa =
        Hashtbl.clear !unroll_tbl;
        List.fold_left (fun g s0 -> mode g s0 dump) cfa (Cfa.sinks cfa)
      in
      let g_bwd = process B.process g in
      process forward_cfa g_bwd
    let make_registers () = Decoder.init_registers ()
end
