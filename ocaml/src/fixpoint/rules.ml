let typing_rule_stmts name callconv =
  if Hashtbl.mem Config.typing_rules name then
    begin
      let rule = Hashtbl.find Config.typing_rules name in
      let prologue =
        match fst rule with
        | None -> []
        | Some args ->
           List.mapi (fun i (typ,_name) -> Asm.Directive (Asm.Type (callconv.Asm.arguments i, Types.typ_of_npk typ))) args in
      let epilogue =  [ Asm.Directive (Asm.Type (callconv.Asm.return,
                                                 Types.typ_of_npk (snd rule))) ] in
      prologue, epilogue
    end
  else [], []


let tainting_rule_stmts libname name get_callconv =
  if Hashtbl.mem Config.tainting_rules (libname,name) then
    begin
      let cc,ret,args = Hashtbl.find Config.tainting_rules (libname,name) in
      let callconv = get_callconv cc in
      let one_taint (l, i) arg =
       match arg with
       | Config.No_taint -> l, i+1
       | Config.Addr_taint -> (Asm.Directive (Asm.Taint (None, callconv.Asm.arguments i)))::l, i+1
       | Config.Buf_taint ->
          let lv = Asm.M (Asm.Lval (callconv.Asm.arguments i), !Config.operand_sz) in
            (Asm.Directive (Asm.Taint (None, lv)))::l, i+1
      in
      let taint_ret_stmts = 
        match ret with
        | None -> []
        | Some t' ->
           match t' with
           | Config.No_taint -> []
           | Config.Addr_taint -> [Asm.Directive (Asm.Taint (None, callconv.Asm.return))]
           | Config.Buf_taint -> [Asm.Directive (Asm.Taint (None, Asm.M(Asm.Lval (callconv.Asm.return), !Config.operand_sz)))]
      in
      let taint_args_stmts = List.rev (fst (List.fold_left one_taint ([], 0) args)) in
      taint_args_stmts, taint_ret_stmts, Some callconv
    end
  else [], [], None
