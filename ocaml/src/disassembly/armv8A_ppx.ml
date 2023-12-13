open Ppxlib

module GhostAst = Ast_builder.Make(struct let loc = Location.none end)

(* str.split(',') -> list *)
let opc2fields str =
    let comma = Str.regexp "," in
    let fields = Str.split comma str in
    fields


(* generate the AST for
   (var lsr f_end) land (2^(f_start-fend)-1)
*)
let do_shift_mask var f_start f_end =
    let end_int = GhostAst.pexp_constant(Pconst_integer (string_of_int f_end, None)) in
    let mask_int = GhostAst.pexp_constant(Pconst_integer (string_of_int ((2 lsl (f_start-f_end))-1), None)) in
    let shifted = GhostAst.eapply (GhostAst.evar "lsr") [var; end_int] in
    GhostAst.eapply (GhostAst.evar "land") [shifted; mask_int]

(* generate the AST from
    start_bit:end_bit_name:flag:val *)
let field2ast insn body fld =
    let insn_var = (GhostAst.evar insn) in
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
    else
      let pat = GhostAst.pvar f_name in
      let expr = do_shift_mask insn_var f_start f_end in
      GhostAst.pexp_let
        Nonrecursive
        [ GhostAst.value_binding ~pat ~expr ]
        body


let raise_error loc msg =
  Location.raise_errorf ~loc "ARMV8A decode error: %s" msg


let parse_let loc expr =
  match expr.pexp_desc with
  | Pexp_let(_rec_flag, variable_bindings, tail) -> begin
      match variable_bindings with
      | variable_binding :: [] -> begin
          match variable_binding.pvb_expr.pexp_desc with
          | Pexp_apply(lambda, args) ->
             let insn_ident = match lambda.pexp_desc with
               | Pexp_ident(insn_ident) -> Longident.name insn_ident.txt
               | _ -> raise_error lambda.pexp_loc "unexpected lambda expression ('let%decode _ = <here>')"
             in
             begin match args with
             | (_arg_label, expr) :: [] -> begin
                 match expr.pexp_desc with
                 | Pexp_constant(Pconst_string(to_decode, _loc, _)) -> (insn_ident, to_decode, tail)
                 | _ -> raise_error expr.pexp_loc "lambda application of let%decode expects exactly one string argument ('let%decode _ = _ \"<here>\"')"
               end
             | _ -> raise_error loc "too many parameters ('let%decode _ = _ \"...\" <here>')"
             end

          | _ ->
             begin
               Printf.printf "DEBUG: %s\n" (Ppxlib_ast.Pprintast.string_of_expression expr) ;
               raise_error expr.pexp_loc "unexpected right expression ('let%decode _ = <here>')"
             end
        end

      | _ -> raise_error loc "unsupported multiple variable binding"

    end

  | _ -> raise_error loc "unsupported expression: supported pattern is 'let%decode _ = _ \"...\" in'"


let expand ~ctxt expr =
  let loc = Expansion_context.Extension.extension_point_loc ctxt in
  let (insn_ident, to_decode, tail) = parse_let loc expr in
  let fields = opc2fields to_decode in
  let res = List.fold_left (field2ast insn_ident) tail fields in
  (*
  Printf.printf "\n\n\n=======================================\n" ;
  Printf.printf "BEFORE\n%s\n" (Ppxlib.Pprintast.string_of_expression expr);
  Printf.printf "=======================================\n" ;
  Printf.printf "AFTER:\n%s\n" (Ppxlib.Pprintast.string_of_expression res);
  Printf.printf "=======================================\n" ;
   *)
  res

let decode_extension =
  Extension.V3.declare
       "decode"
       Extension.Context.expression
       Ast_pattern.(single_expr_payload __)
       expand

let rule = Context_free.Rule.extension decode_extension

let () = Driver.register_transformation ~rules:[ rule ] "armv8A_decode"
