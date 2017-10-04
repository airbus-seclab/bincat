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

let tainting_rule_stmts libname name _callconv =
  if Hashtbl.mem Config.tainting_rules (libname,name) then
    begin
      let _callconv,ret,args = Hashtbl.find Config.tainting_rules (libname,name) in
      let taint_arg taint =
        match taint with
        | Config.No_taint -> []
        | Config.Buf_taint -> [ ]
        | Config.Addr_taint -> [ ]
      in
      let taint_ret_stmts =
        match ret with
        | None -> []
        | Some t -> taint_arg t
      in
      let _taint_args_stmts =
        List.fold_left (fun l arg -> (taint_arg arg)@l) [] args
      in
      [], taint_ret_stmts @ taint_ret_stmts
    end
  else [], []
