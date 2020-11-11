open Ast_mapper
open Asttypes
open Parsetree
open Ast_convenience


(* str.split(',') -> list *)
let opc2fields str =
    let comma = Str.regexp "," in
    let fields = Str.split comma str in
    fields

(* generate the AST for
   (var lsr f_end) land (2^(f_start-fend)-1)
*)
let do_shift_mask var f_start f_end =
    let end_int = Ast_convenience.int f_end in
    let mask_int = Ast_convenience.int ((2 lsl (f_start-f_end))-1) in
    let shifted = (app (evar "lsr") [var; end_int]) in
    app (evar "land") [shifted; mask_int]

(* generate the AST from
    start_bit:end_bit_name:flag:val *)
let field2ast insn fld body =
    let insn_var = (evar insn) in
    let colon = Str.regexp ":" in
    let field_def = Array.of_list (Str.split colon fld) in
    let f_start =  int_of_string (Array.get field_def 0) in
    let f_end = int_of_string (Array.get field_def 1) in
    let f_name = Printf.sprintf "%s_v" (String.lowercase_ascii (Array.get field_def 2)) in
    let _f_split = Array.get field_def 3 in
    let _f_val = Array.get field_def 4 in
    if f_name = "__v" then begin
        (* TODO: generate validation of unamed parts *)
        body
    end
    else begin
        let val_exp = do_shift_mask insn_var f_start f_end in
        let_in [Ast_helper.Vb.mk (pvar f_name) val_exp ] body
    end


(*
parse_let gets the AST corresponding to the
 'let%decode VAR1 = VAR2 "spec" in'
code and extracts VAR2 and "spec"

AST:
Pexp_let (Nonrecursive,
 [{pvb_pat =
    {ppat_desc =
      Ppat_var {txt = "insn'"}};
   pvb_expr =
    {pexp_desc =
      Pexp_apply
       ({pexp_desc =
          Pexp_ident
           {txt = Lident "insn"}},
       [("",
         {pexp_desc =
           Pexp_constant
            (Const_string
              ("31:31:sf:F:0,30:30:op:F:0,29:29:S:F:0,28:24:_:F:10001,23:22:shift:F:xx,21:10:imm12:F:xxxxxxxxxxxx,9:5:Rn:F:xxxxx,4:0:Rd:F:xxxxx",
              None))})])}}],
*)
let parse_let loc let_spec =
    let spec = match let_spec with
        | a::_ -> a
        | [] ->
          raise (Location.Error (
              Location.error ~loc "let%decode syntax is invalid"))
    in
    match spec with
    | { pvb_pat = { ppat_desc = Ppat_var { txt = new_insn }};
        (* fugly code to deal with AST changes *)
        #if OCAML_VERSION < (4, 03, 0)
        pvb_expr = { pexp_desc = Pexp_apply( {pexp_desc = Pexp_ident{txt = Longident.Lident insn_ident } },
                        [(_, {pexp_desc = Pexp_constant (Const_string (opc, None))})]) } } -> insn_ident, opc
        #elif OCAML_VERSION < (4, 11, 0)
        pvb_expr = { pexp_desc = Pexp_apply( {pexp_desc = Pexp_ident{txt = Longident.Lident insn_ident } },
                        [(_, {pexp_desc = Pexp_constant (Pconst_string (opc, None))})]) } } -> insn_ident, opc
        #else
        pvb_expr = { pexp_desc = Pexp_apply( {pexp_desc = Pexp_ident{txt = Longident.Lident insn_ident } },
                        [(_, {pexp_desc = Pexp_constant (Pconst_string (opc, _, None))})]) } } -> insn_ident, opc
        #endif
    | _ ->
      raise (Location.Error (
          Location.error ~loc "let%decode syntax is invalid"))

let decode_mapper _argv =
    { default_mapper with
      expr = fun mapper expr ->
          match expr with
          | { pexp_desc =
                  (* Should have name "decode". *)
                  Pexp_extension ({ txt = "decode"; loc }, pstr)} ->
            begin match pstr with
                    (* the expected syntax is :
                       let%decode new_insn = insn "decodestring" in let_body*)
                    PStr [{ pstr_desc =
                                Pstr_eval ({ pexp_loc  = loc;
                                             pexp_desc = Pexp_let (_, let_spec, let_body)}, _)}] ->
                      (* extract info from the let_spec *)
                      let insn_ident, opc = parse_let loc let_spec in
                      (* decode the opcode spec *)
                      let fields = opc2fields opc in
                      (* create the sequence of let var = in *)
                      List.fold_left (fun body field -> field2ast insn_ident field body) let_body fields
                | _ ->
                  raise (Location.Error (
                      Location.error ~loc "let%decode syntax is invalid"))
            end
          (* Delegate to the default mapper. *)
          | x -> default_mapper.expr mapper x;
    }

let () = register "decode" decode_mapper
