(*
    This file is part of BinCAT.
    Copyright 2014-2018 - Airbus

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

    type import_attrib_t = {
      mutable ia_name: string;
      mutable ia_addr: Z.t option;
      mutable ia_typing_rule: bool;
      mutable ia_tainting_rule: bool;
      mutable ia_stub: bool;
    }


    (** Control Flow Automaton *)
    module Cfa = Decoder.Cfa


    open Asm

    (* Hash table to know when a widening has to be processed, that is when the associated value reaches the threshold Config.unroll *)
    let unroll_tbl: ((Data.Address.t, int * D.t) Hashtbl.t) ref = ref (Hashtbl.create 1000)

    (* Hash table to store number of times a function has been analysed *)
    let fun_unroll_tbl: (Data.Address.t, int) Hashtbl.t = Hashtbl.create 10

    (* current unroll value *)
    (* None is for the default value set in Config *)
    let unroll_nb = ref None

    (** opposite the given comparison operator *)
    let inv_cmp (cmp: Asm.cmp): Asm.cmp =
      match cmp with
      | EQ  -> NEQ
      | NEQ -> EQ
      | LT  -> GEQ
      | GEQ -> LT
      | LEQ -> GT
      | GT  -> LEQ

    let restrict (d: D.t) (e: Asm.bexp) (b: bool): (D.t * Taint.t) =
      L.debug (fun p -> p "restrict: e=%s b=%B" (Asm.string_of_bexp e true) b);
      let rec process e b =
        match e with
        | BConst b'           -> if b = b' then d, Taint.U else D.bot, Taint.BOT
        | BUnOp (LogNot, e)       -> process e (not b)

        | BBinOp (LogOr, e1, e2)  ->
           let v1, taint1 = process e1 b in
           let v2, taint2 = process e2 b in
           let taint_sources =
             if b then Taint.logor taint1 taint2
             else Taint.logand taint1 taint2
           in
           if b then D.join v1 v2, taint_sources
           else D.meet v1 v2, taint_sources
             
        | BBinOp (LogAnd, e1, e2) ->
           let v1, taint1 = process e1 b in
           let v2, taint2 = process e2 b in
           let taint_sources =
             if b then Taint.logand taint1 taint2
             else Taint.logor taint1 taint2 in
           if b then D.meet v1 v2, taint_sources
           else D.join v1 v2, taint_sources

        | Asm.Cmp (cmp, e1, e2)   ->
           let cmp' = if b then cmp else inv_cmp cmp in
           D.compare d e1 cmp' e2
      in
      process e b


    (** widen the given state with all previous vertices that have the same ip as v *)
    let widen prev v =
      let join_v = D.join prev v.Cfa.State.v in
      v.Cfa.State.final <- true;
      v.Cfa.State.v <- D.widen prev join_v


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
           let n = f () in
           unroll_nb := Some n;
           L.analysis (fun p -> p "automatic loop unrolling detection. Computed value is 0x%x" n)
      with _ -> ()

    exception Jmp_exn

    type fun_stack_t = ((string * string) option * Data.Address.t * Cfa.State.t * (Data.Address.t, int * D.t) Hashtbl.t) list ref

    let rec process_value (d: D.t) (s: Asm.stmt) (fun_stack: fun_stack_t): D.t * Taint.t =
        L.debug2 (fun p -> p "process_value VVVVVVVVVVVVVVVVVVVVVVVVVVVVVV\n%s\n---------\n%s\n---------" (String.concat " " (D.to_string d)) (Asm.string_of_stmt s true));
      try
        let res, tainted =
            match s with
            | Nop                -> d, Taint.U
            | If (e, then_stmts, else_stmts) -> process_if d e then_stmts else_stmts fun_stack
            | Set (dst, src)         -> D.set dst src d
            | Directive (Remove r)       -> let d' = D.remove_register r d in Register.remove r; d', Taint.U
            | Directive (Forget lval)        -> D.forget_lval lval d, Taint.U
            | Directive (Unroll (e, bs)) ->
               begin
                 try
                   let f () = min ((Z.to_int (D.value_of_exp d e)) + 1) bs in
                   unroll_wrapper f
                 with _ -> ()
               end;
              d, Taint.U

            | Directive (Default_unroll) ->
               L.analysis (fun p -> p "set unroll parameter to its default value");
              unroll_nb := None;
              d, Taint.U

            | Asm.Directive (Asm.Unroll_until (addr, cmp, terminator, upper_bound, sz)) ->
               begin
                 try
                   let f () =
                     D.get_offset_from addr cmp terminator upper_bound sz d
                   in
                   unroll_wrapper f;
                 with _ -> ()
               end;
               d, Taint.U

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
                         match D.taint_sources c d with
                         | Taint.U -> d, Taint.U
                         | src -> D.span_taint_to_register r src d
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
                                match D.taint_sources c d with
                                | Taint.U -> d, Taint.U
                                | src -> D.span_taint_to_addr a src d
                           end
                        | _ -> raise Exit
                      with _ -> L.analysis (fun p -> p "Tainting directive ignored"); d, Taint.U
                    end
                 | _ -> L.analysis (fun p -> p "Tainting directive for %s ignored" (Asm.string_of_lval lv false)); d, Taint.U
               end
            | Directive (Type (lv, t)) -> D.set_type lv t d, Taint.U

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
                     let dd, tt = process_value d stmt fun_stack in
                     dd, Taint.logor t tt) (d', taint) cleanup_stmts
               in
               d', taint'
               
            | Directive (Stub (fun_name, call_conv)) as stub_statement ->
               L.info2(fun p -> p "Processing %s" fun_name);
              let d', taint', cleanup_stmts = Stubs.process d fun_name call_conv in
              let d', taint' = Log.Trace.trace (Data.Address.global_of_int (Z.of_int 0))  (fun p -> p "%s" (string_of_stmts (stub_statement :: cleanup_stmts) true));
                               List.fold_left (fun (d, t) stmt -> let dd, tt = process_value d stmt fun_stack in
                                                                  dd, Taint.logor t tt) (d', taint') cleanup_stmts in
              d', taint'
              
            | _ -> raise Jmp_exn
                 
        in
        L.debug2 (fun p -> p "end of process_value taint=%s ---------\n%s\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
                             (Taint.to_string tainted) (String.concat " " (D.to_string res)));
        res, tainted
      with Exceptions.Empty _ -> D.bot,Taint.U

    and process_if (d: D.t) (e: Asm.bexp) (then_stmts: Asm.stmt list) (else_stmts: Asm.stmt list) fun_stack =
      if has_jmp then_stmts || has_jmp else_stmts then
             raise Jmp_exn
           else
             let dt, bt = List.fold_left (fun (d, b) s -> let d', b' = process_value d s fun_stack in d', Taint.logor b b') (restrict d e true) then_stmts in
             let de, be = List.fold_left (fun (d, b) s -> let d', b' = process_value d s fun_stack in d', Taint.logor b b') (restrict d e false) else_stmts in
             D.join dt de, Taint.logor bt be


    let process_ret (fun_stack: fun_stack_t) v =
      try
        begin
          let d = v.Cfa.State.v in
          let d', ipstack, prev_unroll_tbl =
            let _f, ipstack, _v, prev_unroll_tbl = List.hd !fun_stack in
            fun_stack := List.tl !fun_stack;
            (* check and apply tainting and typing rules *)
            (* 1. check for assert *)
            (* 2. taint ret *)
            (* 3. type ret *)
            d, Some ipstack, prev_unroll_tbl
          in
        (* check whether instruction pointers supposed and effective do agree *)
          try
            let sp = Register.stack_pointer () in
            let ip_on_stack, taint_sources = D.mem_to_addresses d' (Asm.Lval (Asm.M (Asm.Lval (Asm.V (Asm.T sp)), (Register.size sp)))) in
            match Data.Address.Set.elements (ip_on_stack) with
            | [a] ->
               v.Cfa.State.ip <- a;
              begin
                match ipstack with
                | Some ip' ->
                   if not (Data.Address.equal ip' a) then
                     L.analysis (fun p -> p "computed instruction pointer %s differs from instruction pointer found on the stack %s at RET instruction"
                       (Data.Address.to_string ip') (Data.Address.to_string a))
                | None -> ()
              end;
              unroll_tbl := prev_unroll_tbl;
              Some v, taint_sources
            | _ -> raise Exit
          with
            _ -> L.abort (fun p -> p "computed instruction pointer at return instruction is either undefined or imprecise")
        end
      with Failure _ -> L.analysis (fun p -> p "RET without previous CALL at address %s" (Data.Address.to_string v.Cfa.State.ip)); None, Taint.U


    (** returns the result of the transfert function corresponding to the statement on the given abstract value *)
    let skip_or_import_call vertices a fun_stack =     
      (* will raise Not_found if no import or skip is found *)
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
                    List.fold_left (fun (d, t) stmt -> let d', t' = process_value d stmt fun_stack in d', Taint.logor t t') (v.Cfa.State.v, Taint.U) stmts
                in
                v.Cfa.State.v <- d';
                let addrs, _ = D.mem_to_addresses d' ret_addr_exp in
                let a = match Data.Address.Set.elements addrs with
                        | [a] -> a
                        | []  -> L.abort (fun p->p "no return address")
                        | _l  -> L.abort (fun p->p "multiple return addresses") in
                L.analysis (fun p -> p "returning from stub to %s" (Data.Address.to_string a));
                v.Cfa.State.ip <- a;
                Log.Trace.trace a (fun p -> p "%s"
                                              (Asm.string_of_stmts [ Asm.Jmp(R ret_addr_exp) ] true));
                Taint.logor t t') Taint.U vertices
        in
        vertices, t

    let process_stmts fun_stack g (v: Cfa.State.t) (ip: Data.Address.t): Cfa.State.t list =
        let fold_to_target (apply: Data.Address.t -> unit) (vertices: Cfa.State.t list) (target: Asm.exp) : (Cfa.State.t list * Taint.t) =
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
                              with Not_found -> v.Cfa.State.ip <- a; apply a; v::l, Taint.logor t taint_sources
                          end
                        | [] -> L.abort (fun p -> p "Unreachable jump target from ip = %s\n" (Data.Address.to_string v.Cfa.State.ip))
                        | l -> L.abort (fun p -> p "Please select between the addresses %s for jump target from %s\n"
                                              (List.fold_left (fun s a -> s^(Data.Address.to_string a)) "" l) (Data.Address.to_string v.Cfa.State.ip))
                    with
                    | Exceptions.Too_many_concrete_elements _ as e ->
                       L.exc_and_abort e (fun p -> p "Uncomputable set of address targets for jump at ip = %s\n" (Data.Address.to_string v.Cfa.State.ip))
                ) ([], Taint.U) vertices
            in
            if !import then fun_stack := List.tl !fun_stack;
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
        v'.Cfa.State.taint_sources <- Taint.U;
        if is_pred then
          Cfa.add_successor g v v'
        else
          Cfa.add_successor g (Cfa.pred g v) v';
        v'
      in


      let rec process_if_with_jmp (vertices: Cfa.State.t list) (e: Asm.bexp) (istmts: Asm.stmt list) (estmts: Asm.stmt list) =
        let process_branch stmts branch =
          let vertices', b = (List.fold_left (fun (l, b) v ->
            try
              let d, taint_sources = restrict v.Cfa.State.v e branch in
              if D.is_bot d then
                l, b
              else
                (copy v d (Some true) false)::l, Taint.logor b taint_sources
            with Exceptions.Empty "Interpreter.process_if_with_jmp" -> l, b) ([], Taint.U) vertices)
          in
          let vert, b' = process_list vertices' stmts in
          vert, Taint.logor b b'
        in
        let then', bt = process_branch istmts true in
        let else', be = process_branch estmts false in
        List.iter (fun v -> Cfa.remove_state g v) vertices;
        then' @ else', Taint.logor be bt


      and process_vertices (vertices: Cfa.State.t list) (s: Asm.stmt): (Cfa.State.t list * Taint.t) =
        try
          List.fold_left (fun (l, b) v -> let d, b' = process_value v.Cfa.State.v s fun_stack in
                                          v.Cfa.State.v <- d;
                                          let taint = Taint.logor b b' in
                                          (*v.Cfa.State.taint_sources <- taint;*)
                                          v::l, taint) ([], Taint.U) vertices
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
                    List.map (fun v -> v.Cfa.State.ip <- a; v) vertices, Taint.U
                end
               
             | Jmp (R target) ->
                fold_to_target (fun _a -> ()) vertices target
               
             | Call (A a) ->
                add_to_fun_stack a;
                begin
                  try
                    skip_or_import_call vertices a fun_stack
                  with Not_found ->
                    List.iter (fun v -> v.Cfa.State.ip <- a) vertices;
                    vertices, Taint.U
                end
             | Call (R target) -> fold_to_target add_to_fun_stack vertices target
                                
             | Return ->
                List.fold_left (fun (l, b) v ->
                    let v', b' = process_ret fun_stack v in
                    match v' with
                    | None -> l, Taint.logor b b'
                    | Some v -> v::l, Taint.logor b b') ([], Taint.U) vertices
               
             | _       -> vertices, Taint.U

      and process_list (vertices: Cfa.State.t list) (stmts: Asm.stmt list): Cfa.State.t list * Taint.t =
        match stmts with
        | s::stmts ->
           let new_vert, tainted =
             begin
               try
                 let (new_vertices: Cfa.State.t list), (t: Taint.t) = process_vertices vertices s in
                 let vert, t' = process_list new_vertices stmts in
                 vert, Taint.logor t t'
               with Exceptions.Bot_deref -> [], Taint.BOT (* in case of undefined dereference corresponding vertices are no more explored. They are not added to the waiting list neither *)
             end
           in

           new_vert, tainted
        | []       -> vertices, Taint.U
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
            List.iter (fun (_f, _ip, v, _tbl) -> v.Cfa.State.taint_sources <- Taint.logor v.Cfa.State.taint_sources taint) !fun_stack;
          with _ -> ()
        end;
        vertices
      else
        begin
          Log.Trace.trace v.Cfa.State.ip (fun p -> p "nop ; forced by config");
          L.analysis(fun p -> p "Instruction at address %s nopped by config"
                                (Data.Address.to_string v.Cfa.State.ip));
          [vstart]
        end


    (** [filter_vertices subsuming g vertices] returns vertices in _vertices_ that are not already in _g_ (same address and same decoding context and subsuming abstract value if subsuming = true) *)
    let filter_vertices (subsuming: bool) g vertices =
      (* predicate to check whether a new state has to be explored or not *)
      let same prev v' =
        Data.Address.equal prev.Cfa.State.ip v'.Cfa.State.ip &&
          prev.Cfa.State.ctx.Cfa.State.addr_sz = v'.Cfa.State.ctx.Cfa.State.addr_sz &&
            prev.Cfa.State.ctx.Cfa.State.op_sz = v'.Cfa.State.ctx.Cfa.State.op_sz &&
              (* fixpoint reached *)
              D.is_subset v'.Cfa.State.v prev.Cfa.State.v
      in
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
                Cfa.iter_state (fun prev ->
                  if v.Cfa.State.id = prev.Cfa.State.id then
                    ()
                  else
                    if same prev v then raise Exit
                ) g;
            v::l
          with
            Exit -> l
        ) [] vertices

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
            let region = if Register.is_stack_pointer reg then Data.Address.Stack else Data.Address.Global in
            let rule = rfun reg in
            Init_check.check_register_init reg rule;
            D.set_register_from_config reg region rule) rules
        in
        hash_add_or_append overrides ip rules'
      ) Config.reg_override;
      if L.log_info () then
        begin
          let empty_desc = {
              ia_name = "n/a";
              ia_addr = None;
              ia_typing_rule = false;
              ia_tainting_rule = false;
              ia_stub = false;
            } in
          let yesno b = if b then "YES" else "no" in
          let itbl = Hashtbl.create 5 in
          Hashtbl.iter (fun a (libname, fname) ->
            let func_desc = { empty_desc with
              ia_name = libname ^ "." ^ fname;
              ia_addr = Some a;
            } in
            Hashtbl.add itbl fname func_desc) Config.import_tbl;
          Hashtbl.iter (fun name _typing_rule ->
            let func_desc =
              try
                Hashtbl.find itbl name
              with Not_found -> { empty_desc with ia_name = "?." ^ name } in
            Hashtbl.replace itbl name { func_desc with ia_typing_rule=true })  Config.typing_rules;
          Hashtbl.iter (fun  (libname, name) (_callconv, _taint_ret, _taint_args) ->
            let func_desc =
              try
                Hashtbl.find itbl name
              with Not_found -> { empty_desc with ia_name = libname ^ "." ^ name } in
            Hashtbl.replace itbl name { func_desc with ia_tainting_rule=true })  Config.tainting_rules;
          Hashtbl.iter (fun name _ ->
            let func_desc =
              try
                Hashtbl.find itbl name
              with Not_found -> { empty_desc with ia_name = "?." ^ name } in
            Hashtbl.replace itbl name { func_desc with ia_stub=true })  Stubs.stubs;

          let addr_to_str x = match x with
            | Some a ->
               begin (* too bad we can't format "%%0%ix" to make a new format *)
                 match !Config.address_sz with
                 | 16 -> Printf.sprintf "%04x" (Z.to_int a)
                 | 32 -> Printf.sprintf "%08x" (Z.to_int a)
                 | 64 -> Printf.sprintf "%016x" (Z.to_int a)
                 | _ ->  Printf.sprintf "%x" (Z.to_int a)
               end
            | None -> "?"
          in
          L.info (fun p -> p "Dumping state of imports");
          Hashtbl.iter (fun _name func_desc ->
            L.info (fun p -> p "| IMPORT %-30s addr=%-16s typing=%-3s tainting=%-3s stub=%-3s"
              func_desc.ia_name (addr_to_str func_desc.ia_addr)
              (yesno func_desc.ia_typing_rule) (yesno func_desc.ia_tainting_rule) (yesno func_desc.ia_stub)))
            itbl;
          L.info (fun p -> p "End of dump");
        end;

    List.iter (fun (tbl, region) ->
        Hashtbl.iter (fun z rules ->
            let ip = Data.Address.of_int Data.Address.Global z !Config.address_sz in
            let rules' =
                List.map (fun ((addr, nb), rule) ->
                  L.analysis (fun p -> p "Adding override rule for address 0x%x" (Z.to_int addr));
                  Init_check.check_mem rule;
                  let addr' = Data.Address.of_int region addr !Config.address_sz in
                  match rule with
                       | (Some _, _) -> D.set_memory_from_config addr' Data.Address.Global rule nb
                       | (None, t) -> D.taint_address_mask addr' t
                ) rules
            in
            hash_add_or_append overrides ip rules'

        ) tbl)
        [(Config.mem_override, Data.Address.Global) ;
         (Config.stack_override, Data.Address.Stack) ; (Config.heap_override, Data.Address.Heap)];
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
            | Some (v, ip', d') ->
               Log.Trace.trace v.Cfa.State.ip (fun p -> p "%s" (Asm.string_of_stmts v.Cfa.State.stmts true));
               (* these vertices are updated by their right abstract values and the new ip                         *)
              let new_vertices = update_abstract_value g v (fun v -> v.Cfa.State.v) ip' (process_stmts fun_stack) in
            (* add overrides if needed *)
           let new_vertices =
         try
           let rules = Hashtbl.find overrides v.Cfa.State.ip in
           L.analysis (fun p -> p "applied tainting (%d) override(s)" (List.length rules));
           List.map (fun v ->
             let d', taint =
               List.fold_left (fun (d, taint) rule -> let d', taint' = rule d in d', Taint.logor taint taint'
               ) (v.Cfa.State.v, v.Cfa.State.taint_sources) rules
             in
             v.Cfa.State.v <- d';
             v.Cfa.State.taint_sources <- taint;
             v) new_vertices
         with
           Not_found -> new_vertices
           in
           (* among these computed vertices only new are added to the waiting set of vertices to compute       *)
           let vertices'  = filter_vertices true g new_vertices in
           List.iter (fun v -> waiting := Vertices.add v !waiting) vertices';
               (* udpate the internal state of the decoder *)
               d := d'
            | None -> ()
            end;
            Log.latest_finished_address := Some v.Cfa.State.ip;  (* v.Cfa.State.ip can change because of calls and jumps *)

          with
          | Exceptions.Too_many_concrete_elements _ as e -> L.exc e (fun p -> p "imprecision here"); dump g; L.abort (fun p -> p "analysis stopped (computed value too much imprecise)")
          | e             -> L.exc e (fun p -> p "Unexpected exception"); dump g; raise e
        end;
        (* boolean condition of loop iteration is updated *)
        continue := not (Vertices.is_empty !waiting);
      done;
      g


    (******************** BACKWARD *******************************)
    (*************************************************************)

    let shift_and_add shift len =
      let one = Const (Data.Word.one len) in
      let one' = Const (Data.Word.of_int (Z.of_int (len-1)) len) in
      let shifted_one = BinOp (Asm.Shl, one, one') in
      BinOp (Asm.Add, shift, shifted_one)
        
    let back_add_sub op dst e1 e2 d =
      match e1, e2 with
      | Lval lv1, Lval lv2 ->
        if Asm.equal_lval lv1 lv2 then
            if op = Asm.Sub then
             let len = Asm.lval_length lv1 in
             let shift = BinOp (Asm.Shr, Lval dst, Const (Data.Word.of_int (Z.of_int 1) len)) in
             let d', taint =
               try
                 if Z.compare Z.one (D.value_of_exp d (Decoder.overflow_expression())) = 0 then
                   D.set lv1 (shift_and_add shift len) d
                 else
                   D.set lv1 shift d
               with _ ->
                 let d1, taint1 = D.set lv1 shift d in
                 let d2, taint2 = D.set lv1 (shift_and_add shift len) d in 
                 D.join d1 d2, Taint.join taint1 taint2
             in
             if Asm.with_lval dst (Lval lv1) then
               d', taint
             else D.forget_lval dst d', taint
           else
             D.forget_lval dst d, Taint.TOP
         else
          if (Asm.with_lval dst e1) || (Asm.with_lval dst e2) then 
            D.set lv1 (BinOp (op, Lval dst, e2)) d
          else D.forget_lval dst d, Taint.TOP
            
      | Lval lv, Const c | Const c, Lval lv ->
         let d', taint = D.set lv (BinOp (op, Lval dst, Const c)) d in
         if Asm.with_lval dst (Lval lv) then
           d', taint
         else D.forget_lval dst d', taint
               
      | Lval lv, e | e, Lval lv ->
           if (Asm.with_lval dst e1) || (Asm.with_lval dst e2) then
             D.set lv (BinOp (op, Lval dst, e)) d
           else D.forget_lval dst d, Taint.TOP

      | _ ->  D.forget_lval dst d, Taint.TOP


    let back_set (dst: Asm.lval) (src: Asm.exp) (d: D.t): (D.t * Taint.t) =
      match src with
      | Lval lv ->
         let d', taint = D.set lv (Lval dst) d in
         if Asm.equal_lval lv dst then d', taint
         else D.forget_lval dst d', taint

      | UnOp (Not, Lval lv) ->
        let d', taint = D.set lv (UnOp (Not, Lval dst)) d in
        if Asm.equal_lval lv dst then d', taint
        else D.forget_lval dst d, taint
          
      | BinOp (Add, e1, e2)  -> back_add_sub Sub dst e1 e2 d
      | BinOp (Sub, e1, e2) -> back_add_sub Add dst e1 e2 d
         
      | _ -> D.forget_lval dst d, Taint.TOP

    (** backward transfert function on the given abstract value *)
    let backward_process (branch: bool option) (d: D.t) (stmt: Asm.stmt) : (D.t * Taint.t) =
      (* BE CAREFUL: this function does not apply to nested if statements *)
      let rec back d stmt =
        L.debug (fun p -> p "back of %s.........." (Asm.string_of_stmt stmt true));
        match stmt with
        | Call _
        | Return
        | Jmp _
        | Nop -> d, Taint.U
        | Directive (Forget _) -> d, Taint.U
        | Directive (Remove r) -> D.add_register r d, Taint.U
        | Directive (Taint _) -> D.forget d, Taint.TOP
        | Directive (Type _) -> D.forget d, Taint.U
        | Directive (Unroll _) -> d, Taint.U
        | Directive (Unroll_until _) -> d, Taint.U
        | Directive Default_unroll -> d, Taint.U
        | Directive (Stub _) -> d, Taint.U
        | Directive (Skip _) -> d, Taint.U
        | Set (dst, src) -> back_set dst src d
        | Assert (_bexp, _msg) -> d, Taint.U (* TODO *)
        | If (_e, istmts, estmts) ->
           match branch with
           | Some true -> List.fold_left (fun (d, b) s -> let d', b' = back d s in d', Taint.logor b b') (d, Taint.U) (List.rev istmts)
           | Some false -> List.fold_left (fun (d, b) s -> let d', b' = back d s in d', Taint.logor b b') (d, Taint.U) (List.rev estmts)
           | None -> D.forget d, Taint.U
      in
      back d stmt

    let back_update_abstract_value (g:Cfa.t) (v: Cfa.State.t) (ip: Data.Address.t) (pred: Cfa.State.t): Cfa.State.t list =
      let backward _g v _ip =
        let start_v =
          match v.Cfa.State.back_v with
          | Some d -> d
          | None -> raise (Exceptions.Empty "undefined abstract value used in backward mode")
        in
        let d', taint_sources =
          List.fold_left (fun (d, b) s ->
            let d', b' = backward_process v.Cfa.State.branch d s in
            d', Taint.logor b b'
          ) (start_v, Taint.U) (List.rev pred.Cfa.State.stmts)
        in
        let v' = D.meet pred.Cfa.State.v d' in
        begin
          match pred.Cfa.State.back_v, pred.Cfa.State.back_taint_sources with
          | None, None -> 
             pred.Cfa.State.back_v <- Some v';
            pred.Cfa.State.back_taint_sources <- Some taint_sources
          | Some v2, Some t2 -> 
             pred.Cfa.State.back_v <- Some (D.join v' v2);
            pred.Cfa.State.back_taint_sources <- Some (Taint.join t2 taint_sources)
          | _, _ -> 
             raise (Exceptions.Error "inconsistent state in backward mode")
        end;
        [pred]
      in
      let get_field v =
        match v.Cfa.State.back_v with
        | Some d -> d
        | None -> raise (Exceptions.Error "Illegal call to get_field in interpreter")
      in
      update_abstract_value g v get_field ip backward


    let back_unroll g v pred =
      if v.Cfa.State.final then
        begin
          v.Cfa.State.final <- false;
          let new_pred = Cfa.copy_state g v in
          new_pred.Cfa.State.back_loop <- true;
          Cfa.remove_successor g pred v;
          Cfa.add_state g new_pred;
          Cfa.add_successor g pred new_pred;
          Cfa.add_successor g new_pred v;
          new_pred
        end
      else
        pred

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


    let forward_process (d: D.t) (stmt: Asm.stmt) (branch: bool option): (D.t * Taint.t) =
      (* function stack *)
      let fun_stack = ref [] in
      let rec forward (d: D.t) (stmt: Asm.stmt): (D.t * Taint.t) =
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
        | Asm.Call (Asm.A _) -> d, Taint.U
        | Asm.Set (dst, src) -> D.set dst src d
        | Assert (_bexp, _msg) -> d, Taint.U (* TODO *)
        | Asm.If (e, istmts, estmts) ->
           begin
             try process_if d e istmts estmts fun_stack
             with Jmp_exn ->
               match branch with
               | Some true -> List.fold_left (fun (d, b) stmt -> let d', b' = forward d stmt in d', Taint.logor b b') (restrict d e true) istmts
               | Some false -> List.fold_left (fun (d, b) stmt -> let d', b' = forward d stmt in d', Taint.logor b b') (restrict d e false) estmts
               | None -> L.abort (fun p -> p "Illegal call to Interpreter.forward_process")
           end
        | Asm.Call (Asm.R _) -> D.forget d, Taint.TOP
        | Asm.Jmp (Asm.R _) -> D.forget d, Taint.TOP (* TODO may be more precise but check whether the target is really in the CFA. If not then go back to forward_bin for that branch *)
      in
      forward d stmt

    let forward_abstract_value (g:Cfa.t) (succ: Cfa.State.t) (ip: Data.Address.t) (v: Cfa.State.t): Cfa.State.t list =
      let forward _g v _ip =
        let d', taint_sources = List.fold_left (fun (d, b) s ->
          let d', b' = forward_process d s (succ.Cfa.State.branch) in
          d', Taint.logor b b') (v.Cfa.State.v, Taint.U) (succ.Cfa.State.stmts)
        in
        L.debug (fun p->p "forward_abstract_value taint : %s" (Taint.to_string taint_sources));
        succ.Cfa.State.v <- D.meet succ.Cfa.State.v d';
        succ.Cfa.State.taint_sources <- taint_sources;
        [succ]
      in
      update_abstract_value g v (fun v -> v.Cfa.State.v) ip forward

    (****************************)
    (* FIXPOINT ON CFA *)
    (****************************)
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
            let new_vertices = List.fold_left (fun l v' -> (update_abstract_value g v v'.Cfa.State.ip [v'])@l) [] v' in
            let new_vertices' = List.map (unroll g v) new_vertices in
            let vertices' = filter_vertices false g new_vertices' in
            List.iter (fun v -> waiting := Vertices.add v !waiting) vertices';
            continue := not (Vertices.is_empty !waiting)
          done;
          g
        with
        | Invalid_argument _ -> L.analysis (fun p -> p "entry node of the CFA reached"); g
        | e -> dump g; raise e

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
      let g_bwd = process backward g in
      process forward_cfa g_bwd
  end

