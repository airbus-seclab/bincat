val init_tbls: unit -> unit

val declare_new_type: BareSyntax.var_modifier -> unit

val is_type: string -> bool

val normalize_decl: BareSyntax.decl -> string option
