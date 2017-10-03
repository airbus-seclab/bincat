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
