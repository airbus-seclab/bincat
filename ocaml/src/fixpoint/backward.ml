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


module L = Log.Make(struct let name = "backward" end)
open Asm
   
  
module Make(D: Domain.T)(Cfa: Cfa.T with type domain = D.t)(Decoder: Decoder.T)
         (Core:
            sig
              val cfa_iteration: (Cfa.t -> Cfa.State.t -> Data.Address.t -> Cfa.State.t list -> Cfa.State.t list) ->
                                 (Cfa.t -> Cfa.State.t -> Cfa.State.t list) ->
                                 (Cfa.t -> Cfa.State.t -> Cfa.State.t -> Cfa.State.t) ->
                                 Cfa.t -> Cfa.State.t -> (Cfa.t -> unit) -> Cfa.t
                
              val update_abstract_value: Cfa.t -> Cfa.State.t -> (Cfa.State.t -> D.t) ->
                                         Data.Address.t -> (Cfa.t -> Cfa.State.t -> Data.Address.t -> Cfa.State.t list) ->
                                         Cfa.State.t list
            end) =
struct
           
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
                 D.join d1 d2, Taint.Set.union taint1 taint2
             in
             if Asm.with_lval dst (Lval lv1) then
               d', taint
             else D.forget_lval dst d', taint
           else
             D.forget_lval dst d, Taint.Set.singleton Taint.TOP
         else
           if (Asm.with_lval dst e1) || (Asm.with_lval dst e2) then 
             D.set lv1 (BinOp (op, Lval dst, e2)) d
           else D.forget_lval dst d, Taint.Set.singleton Taint.TOP
        
      | Lval lv, Const c | Const c, Lval lv ->
         let d', taint = D.set lv (BinOp (op, Lval dst, Const c)) d in
         if Asm.with_lval dst (Lval lv) then
           d', taint
         else D.forget_lval dst d', taint
         
      | Lval lv, e | e, Lval lv ->
         if (Asm.with_lval dst e1) || (Asm.with_lval dst e2) then
           D.set lv (BinOp (op, Lval dst, e)) d
         else D.forget_lval dst d, Taint.Set.singleton Taint.TOP
        
      | _ ->  D.forget_lval dst d, Taint.Set.singleton Taint.TOP
            
            
    let back_set (dst: Asm.lval) (src: Asm.exp) (d: D.t): (D.t * Taint.Set.t) =
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
                             
      | _ -> D.forget_lval dst d, Taint.Set.singleton Taint.TOP
           
    (** backward transfert function on the given abstract value *)
    let process (branch: bool option) (d: D.t) (stmt: Asm.stmt) : (D.t * Taint.Set.t) =
      (* BE CAREFUL: this function does not apply to nested if statements *)
      let rec back d stmt =
        L.debug (fun p -> p "back of %s.........." (Asm.string_of_stmt stmt true));
        match stmt with
        | Call _
        | Return
        | Jmp _
        | Nop -> d, Taint.Set.singleton Taint.U
        | Directive (Forget _) -> d, Taint.Set.singleton Taint.U
        | Directive (Remove r) -> D.add_register r d None, Taint.Set.singleton Taint.U
        | Directive (Taint _) -> D.forget d, Taint.Set.singleton Taint.TOP
        | Directive (Type _) -> D.forget d, Taint.Set.singleton Taint.U
        | Directive (Unroll _) -> d, Taint.Set.singleton Taint.U
        | Directive (Unroll_until _) -> d, Taint.Set.singleton Taint.U
        | Directive Default_unroll -> d, Taint.Set.singleton Taint.U
        | Directive (Stub _) -> d, Taint.Set.singleton Taint.U
        | Directive (Skip _) -> d, Taint.Set.singleton Taint.U
        | Directive (Handler _) -> d, Taint.Set.singleton Taint.U
        | Set (dst, src) -> back_set dst src d
        | Assert (_bexp, _msg) -> d, Taint.Set.singleton Taint.U (* TODO *)
        | If (_e, istmts, estmts) ->
           match branch with
           | Some true ->
              List.fold_left (fun (d, b) s -> let d', b' = back d s in d', Taint.Set.union b b'
                ) (d, Taint.Set.singleton Taint.U) (List.rev istmts)
             
           | Some false ->
              List.fold_left (fun (d, b) s -> let d', b' = back d s in d', Taint.Set.union b b'
                ) (d, Taint.Set.singleton Taint.U) (List.rev estmts)

           | None -> D.forget d, Taint.Set.singleton Taint.U
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
              let d', b' = process v.Cfa.State.branch d s in
              d', Taint.Set.union b b'
            ) (start_v, Taint.Set.singleton Taint.U) (List.rev pred.Cfa.State.stmts)
        in
        let v' = D.meet pred.Cfa.State.v d' in
        begin
          match pred.Cfa.State.back_v, pred.Cfa.State.back_taint_sources with
          | None, None -> 
             pred.Cfa.State.back_v <- Some v';
             pred.Cfa.State.back_taint_sources <- Some taint_sources
             
          | Some v2, Some t2 -> 
             pred.Cfa.State.back_v <- Some (D.join v' v2);
             pred.Cfa.State.back_taint_sources <- Some (Taint.Set.union t2 taint_sources)

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
      Core.update_abstract_value g v get_field ip backward


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
      
      
    let from_cfa (g: Cfa.t) (s: Cfa.State.t) (dump: Cfa.t -> unit): Cfa.t =
      Core.cfa_iteration (fun g v ip vert -> back_update_abstract_value g v ip (List.hd vert))
        (fun g v -> [Cfa.pred g v]) back_unroll g s dump
      


  end
