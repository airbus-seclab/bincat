/*
  C2Newspeak: compiles C code into Newspeak. Newspeak is a minimal language 
  well-suited for static analysis.
  Copyright (C) 2007  Charles Hymans, Olivier Levillain
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.
  
  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.
  
  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

  Charles Hymans
  EADS Innovation Works - SE/CS
  12, rue Pasteur - BP 76 - 92152 Suresnes Cedex - France
  email: charles.hymans@penjili.org
*/

%{

open Csyntax
module Bare = BareSyntax
open Lexing
(* TODO: should return the bare tree without doing any normalization, simplifications error reporting other than parsing errors *)

let gen_struct_id = 
  let struct_cnt = ref 0 in
  let gen_struct_id () =
    incr struct_cnt;
    "anon_struct"^(string_of_int !struct_cnt)
  in
    gen_struct_id
  
(* TODO: write checks for all the syntax that is thrown away in these functions
   !! *)

let get_loc () =
  let pos = Parsing.symbol_start_pos () in
    (pos.pos_fname, pos.pos_lnum, pos.pos_cnum-pos.pos_bol)

let declare_new_type (_, m) =
  let build_vdecl ((v, _), _) = Synthack.declare_new_type v in
    List.iter build_vdecl m
     
let flatten_field_decl (b, x) = List.map (fun (v, i) -> (b, v, i)) x

(* TODO: simplify and put in synthack so as to optimize?? *)
(* TODO: put in Bare2C??? think about it *)
let build_funparams params types =
  let has_name x d =
    match Synthack.normalize_decl d with
	Some y when x = y -> true
      | _ -> false
  in
  let add_param_type x = List.find (has_name x) types in
    List.map add_param_type params

let report_asm tokens =
  let loc = "NpkParser.report_asm" in
  let tokens = ListUtils.to_string (fun x -> x) "' '" tokens in
  let msg = "assembly directive '"^tokens^"'" in
    Npkcontext.report_ignore_warning loc msg Npkcontext.Asm

(*
 * build_ptrto n t =
 *    PtrTo (PtrTo (... t))
 *      \_____________/
 *          n times
 *)
let rec build_ptrto n t =
  if n < 0 then invalid_arg "build_ptrto"
  else if n = 0 then t
  else Bare.PtrTo (build_ptrto (n-1) t)

%}

%token BREAK CONST CONTINUE CASE DEFAULT DO ELSE ENUM STATIC 
%token EXTERN FOR IF REGISTER NORETURN AUTO RETURN VOLATILE
%token SWITCH TYPEDEF WHILE GOTO
%token CHAR DOUBLE FLOAT INT SHORT LONG STRUCT UNION SIGNED UNSIGNED VOID
%token ELLIPSIS COLON COMMA DOT LBRACE RBRACE 
%token LBRACKET RBRACKET LPAREN RPAREN NOT 
%token EQEQ NOTEQ
%token EQ OREQ SHIFTLEQ SHIFTREQ MINUSEQ PLUSEQ STAREQ DIVEQ MODEQ BXOREQ AMPERSANDEQ
%token SEMICOLON
%token AMPERSAND ARROW AND OR MINUS DIV MOD PLUS MINUSMINUS QMARK
%token PLUSPLUS STAR LT LTEQ GT GTEQ
%token SHIFTL SHIFTR BXOR BOR BNOT
%token ATTRIBUTE EXTENSION VA_LIST CDECL LABEL
%token INLINE ASM RESTRICT 
%token BUILTIN_CONSTANT_P
%token FUNNAME 
%token OFFSETOF SIZEOF TYPEOF
%token EOF

%token <Csyntax.assertion> NPK
%token <char> SYMBOL

%token <string> IDENTIFIER
%token <string> TYPEDEF_NAME
%token <string> STRING
%token <string option * string * char option * string option> INTEGER
%token <int> CHARACTER
%token <string * char option> FLOATCST

%nonassoc below_ELSE
%nonassoc ELSE

%right    EQ PLUSEQ MINUSEQ STAREQ DIVEQ MODEQ OREQ AMPERSANDEQ SHIFTLEQ SHIFTREQ BXOREQ
%right    QMARK
%left     OR
%left     AND
%left     BOR
%left     BXOR
%left     AMPERSAND
%left     EQEQ NOTEQ
%left     GT GTEQ LT LTEQ
%left     SHIFTL SHIFTR
%left     PLUS MINUS
%left     STAR DIV MOD
%nonassoc prefix_OP
%right    PLUSPLUS MINUSMINUS
%left     DOT ARROW
%left     LPAREN LBRACKET

%type <BareSyntax.t> parse
%start parse

%type <Csyntax.assertion> assertion
%start assertion

%%
/* TODO: simplify code by generalizing!!! 
try to remove multiple occurence of same pattern: factor as much as possible
*/
// carefull not to have any empty rule: this deceives line number location

// TODO: simplify parser and link it to C standard sections!!!

parse:
  translation_unit EOF                      { $1 }
;;

translation_unit:
  NPK translation_unit                      { (Bare.GlbUserSpec $1, get_loc ())::$2 }
| external_declaration translation_unit     { $1@$2 }
| SEMICOLON translation_unit                { (Bare.GlbSkip, get_loc ())::$2 }
|                                           { [] }
;;

function_prologue:
  declaration_specifiers
  function_declarator                       { ($1, $2) }
;;


function_declarator:
  declarator                               { $1 }
| pointer direct_declarator 
  LPAREN identifier_list RPAREN
  old_parameter_declaration_list           { 
    Npkcontext.report_accept_warning "NpkParser.declarator"
      "deprecated style of function definition" Npkcontext.DirtySyntax;
    ($1, Bare.Function ($2, build_funparams $4 $6))
  }
| direct_declarator 
  LPAREN identifier_list RPAREN
  old_parameter_declaration_list           { 
    Npkcontext.report_accept_warning "NpkParser.declarator"
      "deprecated style of function definition" Npkcontext.DirtySyntax;
    (0, Bare.Function ($1, build_funparams $3 $5))
  }
;;

function_definition:
  function_prologue compound_statement      { ($1, $2) }
;;

declaration:
  declaration_specifiers 
  init_declarator_list                      { ($1, $2) }
;;

init_declarator_list:
                                            { (((0, Bare.Abstract), []), None)::[] }
| non_empty_init_declarator_list            { $1 }
;;


non_empty_init_declarator_list:
  init_declarator COMMA 
  non_empty_init_declarator_list            { $1::$3 }
| init_declarator                           { $1::[] }
;;


init_declarator:
  attr_declarator                           { ($1, None) }
| attr_declarator EQ init                   { ($1, Some $3) }
;;


attr_declarator:
  declarator extended_attribute_list        { ($1, $2) }
;;

declarator:
  pointer direct_declarator                 { 
    let (ptr, decl) = $2 in
      (ptr+$1, decl)
  }
| direct_declarator                         { $1 }
;;

direct_declarator:
  ident_or_tname                           { (0, Bare.Variable ($1, get_loc ())) }
| LPAREN declarator RPAREN                 { $2 }
| direct_declarator LBRACKET 
      expression_sequence RBRACKET         { (0, Bare.Array ($1, Some $3)) }
| direct_declarator LBRACKET 
      type_qualifier_list RBRACKET         { (0, Bare.Array ($1, None)) }
| direct_declarator 
  LPAREN parameter_list RPAREN             { (0, Bare.Function ($1, $3)) }
| direct_declarator LPAREN RPAREN          { (0, Bare.Function ($1, [])) }
;;

identifier_list:
  IDENTIFIER COMMA identifier_list         { $1::$3 }
| IDENTIFIER                               { $1::[] }
;;

struct_declarator_list:
  struct_declarator COMMA 
  struct_declarator_list                   { $1::$3 }
| struct_declarator                        { $1::[] }
;;

struct_declarator:
  declarator                               { ($1, None) }
| declarator COLON expression              { ($1, Some $3) }
| COLON expression                         { 
    Npkcontext.report_accept_warning "NpkParser.struct_declarator"
      "anonymous field declaration in structure" Npkcontext.DirtySyntax;
    ((0, Bare.Abstract), Some $2) 
  }
;;

old_parameter_declaration_list:
  old_parameter_declaration 
  old_parameter_declaration_list            { $1@$2 }
| old_parameter_declaration                 { $1 }
;;

old_parameter_declaration:
  declaration SEMICOLON                     { 
    let (b, m) = $1 in
    let normalize_param ((m, attr), init) =
      match init with
	  None when attr = [] -> (b, m)
	| _ -> 
	    Npkcontext.report_error "NpkParser.old_parameter_declaration"
	      "parameter can not be initialized"
    in
      List.map normalize_param m
  }
;;

// TODO: careful, this is a bit of a hack
parameter_declaration:
  declaration_specifiers declarator        { ($1, $2) }
| declaration_specifiers 
  abstract_declarator                      { ($1, $2) }
| declaration_specifiers                   { ($1, (0, Bare.Abstract)) }
;;

type_name:
  declaration_specifiers                   { ($1, (0, Bare.Abstract)) }
| declaration_specifiers
  abstract_declarator                      { ($1, $2) }
;;

// TODO: this part should be rewritten!!!, using for instance
// the grammar from here http://www.quut.com/c/ANSI-C-grammar-y.html
declaration_specifiers:
  type_qualifier_list type_specifier 
  type_qualifier_list                      { $2 }

;;

type_qualifier_list:
  type_qualifier type_qualifier_list       { }
|                                          { }
;;

compound_statement:
  LBRACE statement_list RBRACE             { $2 }
;;

statement_list:
  statement statement_list                 { $1@$2 }
|                                          { [] }
;;

statement:
  bare_statement                           { [$1, get_loc ()] }
;;

bare_statement:
  IDENTIFIER COLON statement               { Bare.LabeledStmt ($1, $3) }
| IF LPAREN expression_sequence RPAREN statement
  else_branch_option                       { Bare.If ($3, $5, $6) }
| switch_stmt                              { Bare.CSwitch $1 }
| iteration_statement                      { $1 }
| NPK                                      { Bare.UserSpec $1 }
| compound_statement                       { Bare.Block $1 }
| simple_statement SEMICOLON               { $1 }
;;  

else_branch_option:
  ELSE statement                           { $2 }
|                         %prec below_ELSE { [] }
;;
  
simple_statement:
  declaration_modifier declaration         { Bare.LocalDecl ($1, $2) }
| TYPEDEF declaration                      { 
    declare_new_type $2;
    Bare.Typedef $2
  }
| RETURN expression_sequence               { Bare.Return (Some $2) }
| RETURN                                   { Bare.Return None }
| expression_sequence                      { Bare.Exp $1 }
| BREAK                                    { Bare.Break }
| CONTINUE                                 { Bare.Continue }
| GOTO IDENTIFIER                          { Bare.Goto $2 }
| asm                                      { Bare.Asm }
|                                          { Bare.Skip }
;;

declaration_modifier:
                                           { (false, false) }
| STATIC                                   { (true, false) }
| EXTERN                                   { (false, true) }
;;

asm:
  ASM volatile_option 
  LPAREN asm_statement_list RPAREN         { report_asm $4 }
| ASM GOTO
  LPAREN asm_statement_list RPAREN         { report_asm $4 }
;;

asm_statement_list:
  asm_statement                            { $1::[] }
| asm_statement COLON asm_statement_list   { $1::$3 }
| COLON asm_statement_list                 { $2 }
| asm_statement COMMA asm_statement_list   { $1::$3 }
;;

asm_statement:
  string_literal                           { $1 }
| string_literal LPAREN expression RPAREN  { $1 } 
| LBRACKET ident_or_tname RBRACKET 
  string_literal LPAREN expression RPAREN  { $2^" "^$4 }
| ident_or_tname                           { $1 }
;;

iteration_statement:
  FOR 
  LPAREN assignment_expression_list_option SEMICOLON 
         expression_option SEMICOLON
         assignment_expression_list_option RPAREN
  statement                                { Bare.For ($3, $5, $9, $7) }
| WHILE LPAREN expression_sequence RPAREN 
  statement                                { Bare.While ($3, $5) }
| DO statement
  WHILE LPAREN expression_sequence 
  RPAREN SEMICOLON                         { Bare.DoWhile ($2, $5) }
;;

assignment_expression_list_option:
  assignment_expression_list               { $1 }
|                                          { [] }
;;

switch_stmt:
  SWITCH LPAREN expression_sequence RPAREN LBRACE
    case_list
  RBRACE                                   { ($3, $6) }
;;

case_list:
  CASE expression_sequence COLON statement_list 
  case_list                                { 
    let (cases, default) = $5 in
      (($2, $4, get_loc ())::cases, default)
  }
| DEFAULT COLON statement_list case_list   { 
    let (cases, _) = $4 in
      if cases <> [] then begin
	Npkcontext.report_accept_warning "NpkParser.case_list" 
	  "switch with default case in intermediary position" 
	  Npkcontext.DirtySyntax
      end;
      (cases, $3)
  }
|                                          { ([], []) }
;;

assignment_expression_list:
  expression COMMA 
  assignment_expression_list               { (Bare.Exp $1, get_loc ())::$3 }
| expression                               { (Bare.Exp $1, get_loc ())::[] }
;;

// TODO: put these function in BareSyntax rather than Csyntax
constant:
  CHARACTER                                { Csyntax.char_cst_of_lexeme $1 }
| INTEGER                                  { Csyntax.int_cst_of_lexeme $1 }
| FLOATCST                                 { Csyntax.float_cst_of_lexeme $1 }
;;

string_literal:
  STRING                                   { $1 }
| STRING string_literal                    { $1^$2 }
;;

expression:
  IDENTIFIER                               { Bare.Var $1 }
| constant                                 { Bare.Cst $1 }
| string_literal                           { Bare.Str $1 }
| FUNNAME                                  { Bare.FunName }
| LPAREN expression_sequence RPAREN        { $2 }
| LPAREN compound_statement RPAREN         { 
    Npkcontext.report_accept_warning "NpkParser.relational_expression"
      "block within expression" Npkcontext.DirtySyntax;
    Bare.BlkExp $2
  }
| expression 
  LBRACKET expression_sequence RBRACKET    { Bare.Index ($1, $3) }
| expression 
  LPAREN argument_expression_list RPAREN   { Bare.Call ($1, $3) }
| expression DOT ident_or_tname            { Bare.Field ($1, $3) }
| expression ARROW ident_or_tname          { 
    Bare.Field (Bare.Index ($1, Bare.exp_of_int 0), $3) 
  }
| expression PLUSPLUS                      { Bare.OpExp (Plus, $1, true) }
| expression MINUSMINUS                    { Bare.OpExp (Minus, $1, true) }
// GNU C
| BUILTIN_CONSTANT_P 
  LPAREN expression_sequence RPAREN        { 
     Npkcontext.report_warning "NpkParser.assignment_expression"
       "__builtin_constant_p ignored, assuming value 0";
    BareSyntax.exp_of_int 0
  }
| OFFSETOF 
  LPAREN type_name COMMA 
  offsetof_member RPAREN                   { Bare.Offsetof ($3, $5) }
// TODO: factor all these cases => prefix_operator
| PLUSPLUS   expression    %prec prefix_OP { Bare.OpExp (Plus, $2, false) }
| MINUSMINUS expression    %prec prefix_OP { Bare.OpExp (Minus, $2, false) }
| AMPERSAND  expression    %prec prefix_OP { Bare.AddrOf $2 }
| STAR       expression    %prec prefix_OP { 
    Bare.Index ($2, BareSyntax.exp_of_int 0) 
  }
// TODO: factor these with unop non-terminal
| BNOT       expression    %prec prefix_OP { Bare.Unop (BNot, $2) }
| NOT        expression    %prec prefix_OP { Bare.Unop (Not, $2) }
| MINUS      expression    %prec prefix_OP { Bare.neg $2 }
| PLUS       expression                    { $2 }
| SIZEOF     expression    %prec prefix_OP { Bare.SizeofE $2 }
| SIZEOF LPAREN type_name RPAREN 
                           %prec prefix_OP { Bare.Sizeof $3 }
| EXTENSION expression     %prec prefix_OP { $2 }
| LPAREN type_name RPAREN expression
                           %prec prefix_OP { Bare.Cast ($4, $2) }
| LPAREN type_name RPAREN composite        { 
(* TODO: remove get_loc, use npkcontext.get_loc rather *)
    Bare.LocalComposite ($2, $4, get_loc ())
  }
// TODO: factor these as binop non-terminal??
| expression STAR      expression          { Bare.Binop (Mult, $1, $3) }
| expression DIV       expression          { Bare.Binop (Div, $1, $3) }
| expression MOD       expression          { Bare.Binop (Mod, $1, $3) }
| expression PLUS      expression          { Bare.Binop (Plus, $1, $3) }
| expression MINUS     expression          { Bare.Binop (Minus, $1, $3) }
| expression SHIFTL    expression          { Bare.Binop (Shiftl, $1, $3) }
| expression SHIFTR    expression          { Bare.Binop (Shiftr, $1, $3) }
| expression GT        expression          { Bare.Binop (Gt, $1, $3) }
| expression GTEQ      expression          { Bare.Unop (Not, Bare.Binop (Gt, $3, $1)) }
| expression LT        expression          { Bare.Binop (Gt, $3, $1) }
| expression LTEQ      expression          { Bare.Unop (Not, Bare.Binop (Gt, $1, $3)) }
| expression EQEQ      expression          { Bare.Binop (Eq, $1, $3) }
| expression NOTEQ     expression          { Bare.Unop (Not, Bare.Binop (Eq, $1, $3)) }
| expression AMPERSAND expression          { Bare.Binop (BAnd, $1, $3) }
| expression BXOR      expression          { Bare.Binop (BXor, $1, $3) }
| expression BOR       expression          { Bare.Binop (BOr, $1, $3) }
| expression AND       expression          { Bare.And ($1, $3) }
| expression OR expression                 { Bare.Or ($1, $3) }
// TODO: factor the two rules for QMARK
| expression QMARK expression_sequence
    COLON expression           %prec QMARK {
	Npkcontext.report_strict_warning "NpkParser.expression"
	  "conditional expression";
      Bare.IfExp ($1, Some $3, $5)
  }
| expression QMARK 
  COLON expression   %prec QMARK           { Bare.IfExp ($1, None, $4)}
| expression assignment_operator
                   expression     %prec EQ { Bare.Set ($1, $2, $3) }
| AND IDENTIFIER { Npkcontext.report_warning
                     "NpkParser.expression"
                     "ignoring address of label, parsing as NULL instead";
                    Bare.Cst (Cir.CInt (Newspeak.Nat.zero), Csyntax.Ptr Csyntax.Void)
                   }
;;

aux_offsetof_member:
  IDENTIFIER                               { Bare.OffComp $1 }
| aux_offsetof_member DOT IDENTIFIER       { Bare.OffField ($1, $3) }

offsetof_member:
  IDENTIFIER                               { Bare.OIdent $1 }
| aux_offsetof_member DOT IDENTIFIER       { Bare.OField ($1, $3) }
| aux_offsetof_member DOT IDENTIFIER 
  LBRACKET expression RBRACKET             { Bare.OArray ($1, $3, $5) }
;;

expression_sequence:
  expression                               { $1 }
| expression_sequence COMMA expression     { 
    Npkcontext.report_accept_warning "NpkParser.expression"
      "comma in expression" Npkcontext.DirtySyntax;
    let loc = get_loc () in
      Bare.BlkExp ((Bare.Exp $1, loc)::(Bare.Exp $3, loc)::[])
  }
;;

assignment_operator:
| EQ                                       { None }
| assignment_op_operator                   { Some $1 }
;;

assignment_op_operator:
  PLUSEQ                                   { Plus }
| MINUSEQ                                  { Minus }
| STAREQ                                   { Mult }
| DIVEQ                                    { Div }
| MODEQ                                    { Mod }
| OREQ                                     { BOr }
| AMPERSANDEQ                              { BAnd }
| SHIFTLEQ                                 { Shiftl }
| SHIFTREQ                                 { Shiftr }
| BXOREQ                                   { BXor }
;;

argument_expression_list:
                                           { [] }
| nonempty_argument_expression_list        { $1 }
;;

nonempty_argument_expression_list:
  expression                               { $1::[] }
| expression 
  COMMA nonempty_argument_expression_list  { $1::$3 }
;;

init:
  expression                               { Bare.Data $1 }
| composite                                { Bare.Sequence $1 }
;;

composite:
  LBRACE init_list RBRACE                  { $2 }
| LBRACE named_init_list RBRACE            { $2 }
| LBRACE indexed_init_list RBRACE          { $2 }
;;

named_init_list:
  named_init COMMA named_init_list         { $1::$3 }
| named_init                               { $1::[] }
| named_init COMMA                         { $1::[] }
;;

named_init:
  DOT IDENTIFIER EQ init                   { (InitField $2, $4) }
;;

indexed_init_list:
  indexed_init COMMA indexed_init_list     { $1::$3 }
| indexed_init                             { $1::[] }
| indexed_init COMMA                       { $1::[] }
;;

indexed_init:
  LBRACKET expression RBRACKET EQ init     { (InitIndex $2, $5) }
;;

init_list:
  init COMMA init_list                     { (InitAnon, $1)::$3 }
| init                                     { (InitAnon, $1)::[] }
|                                          {
    Npkcontext.report_strict_warning "NpkParser.init_list"
      "comma terminated initializer";
  []
  }
;;

abstract_declarator:
  pointer                                  { ($1, Bare.Abstract) }
| direct_abstract_declarator               { $1 }
| pointer direct_abstract_declarator       { 
    let (ptr, decl) = $2 in
      ($1+ptr, decl) 
  }
;;

// TODO: try to factor cases more
direct_abstract_declarator:
  LPAREN abstract_declarator RPAREN        { $2 }
| LBRACKET type_qualifier_list RBRACKET    { (0, Bare.Array ((0, Bare.Abstract), None)) }
| LBRACKET expression_sequence RBRACKET    { 
    (0, Bare.Array ((0, Bare.Abstract), Some $2)) 
  }
| direct_abstract_declarator 
  LBRACKET expression_sequence RBRACKET    { (0, Bare.Array ($1, Some $3)) }
| direct_abstract_declarator 
  LPAREN parameter_list RPAREN             { (0, Bare.Function ($1, $3)) }
| direct_abstract_declarator LPAREN RPAREN { (0, Bare.Function ($1, [])) }
;;

pointer:
  STAR type_qualifier_list                 { 1 }
| STAR type_qualifier_list pointer         { $3 + 1 }
;;

field_list:
  gnuc_field_declaration SEMICOLON 
  field_list                               { $1@$3 } 
| gnuc_field_declaration SEMICOLON         { $1 }
;;

parameter_list:
  parameter_declaration COMMA 
  parameter_list                           { $1::$3 }
| parameter_declaration                    { $1::[] }
| ELLIPSIS                                 {
    let loc = get_loc () in
      (Bare.Va_arg, (0, Bare.Variable ("__builtin_newspeak_va_arg", loc)))::[] 
  }
;;

/*
From ANSI C norm
4 There are five standard signed integer types, designated as signed 
char, short int, int, long int, and long long int. (These and other 
types may be designated in several additional ways, as described in 
6.7.2.)
*/
ityp:
| SHORT INT                              { !Conf.size_of_short }
| INT                                    { !Conf.size_of_int }
| LONG INT                               { !Conf.size_of_long }
| LONG LONG INT                          { !Conf.size_of_longlong }
| SHORT                                  { 
    Npkcontext.report_strict_warning "NpkParser.ityp" 
      "'short' is not normalized: use 'short int' instead";
    !Conf.size_of_short
  }
| LONG                                   { 
    Npkcontext.report_strict_warning "NpkParser.ityp" 
      "'long' is not normalized: use 'long int' instead";
    !Conf.size_of_long
  }
| LONG LONG                              { 
    Npkcontext.report_strict_warning "NpkParser.ityp" 
      "'long long' is not standard: use 'long long int' instead";
    !Conf.size_of_longlong
  }
;;


// ident_or_tname necessary because the namespace of structure and typedefs
// are not disjoint
ident_or_tname:
  IDENTIFIER                             { $1 }
| TYPEDEF_NAME                           {
    Npkcontext.report_warning "NpkParser.ident_or_tname" 
      ("identifier "^$1^" is defined as a type, avoid using it for "
	^"another purpose");
    $1 
  }
;;

enum_list:
  enum                                   { $1::[] }
| enum COMMA enum_list                   { $1::$3 }
| enum COMMA                             { 
    Npkcontext.report_strict_warning "NpkParser.enum_list"   
      "unnecessary comma";  
    $1::[] 
  }
;;

enum:
  IDENTIFIER                             { ($1, None) }
| IDENTIFIER EQ expression               { ($1, Some $3) }
;;

field_blk:
  LBRACE field_list RBRACE               { $2 }
| LBRACE RBRACE                          { 
    Npkcontext.report_accept_warning "NpkParser.field_blk"
      "empty struct or union" Npkcontext.DirtySyntax;
    [] 
  }
;;

ftyp:
  FLOAT                                   { !Conf.size_of_float }
| DOUBLE                                  { !Conf.size_of_double }
| LONG DOUBLE                             { !Conf.size_of_longdouble }
;;

type_specifier:
  VOID                                    { Bare.Void }
| CHAR                                    { Bare.Integer (Newspeak.char_kind ()) }
| ityp                                    { Bare.Integer (Newspeak.Signed, $1) }
| SIGNED CHAR                             { Bare.Integer (Newspeak.Signed, !Conf.size_of_char) }
| SIGNED ityp                             {
    Npkcontext.report_strict_warning "NpkParser.type_specifier" 
      "signed specifier not necessary";
    Bare.Integer (Newspeak.Signed, $2)
  }
| UNSIGNED CHAR                           { Bare.Integer (Newspeak.Unsigned, !Conf.size_of_char) }
| LONG LONG UNSIGNED INT                  {
    Npkcontext.report_strict_warning "NpkParser.type_specifier"
      ("'long long unsigned int' is not normalized : "
      ^"use 'unsigned long long int' instead");
    Bare.Integer (Newspeak.Unsigned, !Conf.size_of_longlong)
  }
| UNSIGNED ityp                           { Bare.Integer (Newspeak.Unsigned, $2) }
| UNSIGNED                                { 
    Npkcontext.report_strict_warning "NpkParser.type_specifier"
      "unspecified integer kind";
    Bare.Integer (Newspeak.Unsigned, !Conf.size_of_int)
  }

| LONG SIGNED INT                         {
  Npkcontext.report_strict_warning "NpkParser.type_specifier" 
      ("'long signed int' is not normalized: "
       ^"use 'signed long int' instead");
    Bare.Integer (Newspeak.Signed, !Conf.size_of_long)
  }

| LONG SIGNED                             {
  Npkcontext.report_strict_warning "NpkParser.type_specifier" 
      ("'long signed' is not normalized: "
       ^"use 'signed long int' instead");
    Bare.Integer (Newspeak.Signed, !Conf.size_of_long)
  }

| LONG UNSIGNED INT                        {
  Npkcontext.report_strict_warning "NpkParser.type_specifier" 
      ("'long unsigned int' is not normalized: "
       ^"use 'unsigned long int' instead");
    Bare.Integer (Newspeak.Unsigned, !Conf.size_of_long)
  }

| LONG UNSIGNED                            {
  Npkcontext.report_strict_warning "NpkParser.type_specifier" 
      ("'long unsigned' is not normalized: "
       ^"use 'unsigned long int' instead");
    Bare.Integer (Newspeak.Unsigned, !Conf.size_of_long)
  }

| SHORT SIGNED INT                         {
  Npkcontext.report_strict_warning "NpkParser.type_specifier" 
      ("'short signed int' is not normalized: "
       ^"use 'signed short int' instead");
    Bare.Integer (Newspeak.Signed, !Conf.size_of_short)
  }

| SHORT SIGNED                             {
  Npkcontext.report_strict_warning "NpkParser.type_specifier" 
      ("'short signed' is not normalized: "
       ^"use 'signed short int' instead");
    Bare.Integer (Newspeak.Signed, !Conf.size_of_short)
  }

| SHORT UNSIGNED INT                       {
  Npkcontext.report_strict_warning "NpkParser.type_specifier" 
      ("'short unsigned int' is not normalized: "
       ^"use 'unsigned short int' instead");
    Bare.Integer (Newspeak.Unsigned, !Conf.size_of_short)
  }

| SHORT UNSIGNED                           {
  Npkcontext.report_strict_warning "NpkParser.type_specifier" 
      ("'short unsigned' is not normalized: "
       ^"use 'unsigned short int' instead");
    Bare.Integer (Newspeak.Unsigned, !Conf.size_of_short)
  }

| ftyp                                     { Bare.Float $1 }
| struct_or_union composite_arguments      { Bare.Composite ($1, $2) }
| TYPEDEF_NAME                             { Bare.Name $1 }
| ENUM enum_arguments                      { Bare.Enum $2 }
| VA_LIST                                  { Bare.Va_arg }
| TYPEOF LPAREN type_specifier RPAREN      { $3 }
| TYPEOF
    LPAREN type_specifier pointer RPAREN   { build_ptrto $4 $3 }
| TYPEOF
    LPAREN type_specifier
      LBRACKET expression RBRACKET
    RPAREN                                 { Bare.ArrayOf ($3, $5) }
| TYPEOF
    LPAREN
      expression
    RPAREN                                 { Bare.TypeofExpr $3 }
| LABEL                                    { Npkcontext.report_warning
                                               "NpkParser.type_specifier"
                                               "accepting local label";
                                             Bare.Label
                                           }
;;

struct_or_union:
  STRUCT                                   { true }
| UNION                                    { false }
;;

composite_arguments:
  field_blk                                { (gen_struct_id (), Some $1) }
| ident_or_tname                           { ($1, None) }
| ident_or_tname field_blk                 { ($1, Some $2) }
;;

enum_arguments:
  enum_values                              { $1 }
| IDENTIFIER                               { None }
| IDENTIFIER enum_values                   { $2 }
;;

enum_values:
  LBRACE enum_list RBRACE                  { Some $2 }
;;

//Section that is dependent on version of the compiler (standard ANSI or GNU)
//TODO: find a way to factor some of these, possible!!!
external_declaration:
  function_definition                      { (Bare.FunctionDef (false, $1), get_loc ())::[] }
| STATIC function_definition               { (Bare.FunctionDef (true, $2), get_loc ())::[] }
| INLINE STATIC function_definition        { (Bare.FunctionDef (true, $3), get_loc ())::[] }
| ATTRIBUTE LPAREN LPAREN attribute_name_list 
  RPAREN RPAREN STATIC function_definition { (Bare.FunctionDef (true, $8), get_loc ())::[] }
| extension_option
  EXTERN function_definition               {
    Npkcontext.report_ignore_warning "NpkParser.external_declaration" 
      "extern function definition" Npkcontext.ExternFunDef;
    let ((b, m), _) = $3 in
      (Bare.GlbDecl ((false, false), (b, ((m, []), None)::[])), get_loc ())::[]
  }
| global_declaration SEMICOLON             { $1 }
;;

global_declaration:
  STATIC declaration                       { (Bare.GlbDecl ((true, false), $2), get_loc ())::[] }
| EXTENSION declaration                    { (Bare.GlbDecl ((false, false), $2), get_loc ())::[] }
| declaration                              { (Bare.GlbDecl ((false, false), $1), get_loc ())::[] }
| extension_option EXTERN declaration      { (Bare.GlbDecl ((false, true), $3), get_loc ())::[] }
| extension_option TYPEDEF declaration     { 
    declare_new_type $3;
    (Bare.GlbTypedef $3, get_loc ())::[] 
  }
| asm                                      { [] }
;;

attribute_list:
  attribute attribute_list                 { $1@$2 }
|                                          { [] }
;;

extended_attribute_list:
  attribute extended_attribute_list        { $1@$2 }
| asm extended_attribute_list              { $2 }
|                                          { [] }
;;

type_qualifier:
  CONST                                    { }
| attribute                                { }
| VOLATILE                                 { 
    Npkcontext.report_ignore_warning "NpkParser.type_qualifier" 
      "type qualifier 'volatile'" Npkcontext.Volatile;
    }
| AUTO                                     { }
| REGISTER                                 { }
;;

gnuc_field_declaration:
// GNU C extension
  extension_option field_declaration       { $2 }
;;

field_declaration:
  declaration_specifiers
  struct_declarator_list attribute_list    { flatten_field_decl ($1, $2) }
| declaration_specifiers                   { 
    Npkcontext.report_accept_warning "NpkParser.field_declaration"
      "anonymous field declaration in structure" Npkcontext.DirtySyntax;
    flatten_field_decl ($1, ((0, Bare.Abstract), None)::[]) 
  }
;;

attribute:
  ATTRIBUTE LPAREN LPAREN attribute_name_list 
  RPAREN RPAREN                            { $4 }
| INLINE                                   { [] }
| CDECL                                    { [] }
| RESTRICT                                 { [] }
| NORETURN                                 { [] }
;;

attribute_name_list:
  attribute_name COMMA attribute_name_list { $1@$3 }
| attribute_name                           { $1 }
;;

attribute_name:
  IDENTIFIER                               { 
    begin match $1 with
	"aligned" | "__aligned__" | "__cdecl__" | "__cdecl" | "noreturn" | "__noreturn" | "__noreturn__"
      | "__always_inline__" | "always_inline"  | "__nothrow__" 
      | "__pure__" | "pure" | "__gnu_inline__"
      | "__deprecated__" | "deprecated" | "__malloc__" 
      | "__warn_unused_result__" | "warn_unused_result"
      | "__unused__" | "unused" | "__used__"
      | "no_instrument_function"
      | "__artificial__" | "__cold__" | "cold"
          -> ()
      | "dllimport" -> 
	  Npkcontext.report_warning "NpkParser.attribute" 
	    "ignoring attribute dllimport"
      | "packed" | "__packed__" -> 
	  Npkcontext.report_ignore_warning "NpkParser.attribute_name" 
	    "packed attribute" Npkcontext.Pack
      | "__transparent_union__" -> 
	  Npkcontext.report_accept_warning "NpkParser.attribute_name" 
	    "transparent union" Npkcontext.TransparentUnion
      | "weak" | "__weak__" ->
	  Npkcontext.report_warning "NpkParser.attribute" 
	    "ignoring attribute weak"
      | _ -> raise Parsing.Parse_error
    end;
    [] 
  }
| IDENTIFIER LPAREN string_list RPAREN               {
  match $1 with
  | "alias" ->
      begin
        Npkcontext.report_warning "NpkParser.attribute"
        ("ignoring attribute alias");
        []
      end
  | "warning"
  | "__warning__"
  | "__error__"
  | "__section__"
  | "section"
    -> []
  | _ -> raise Parsing.Parse_error
  }
| IDENTIFIER LPAREN integer_list RPAREN    { 
    match ($1, $3) with
	(("__format_arg__" | "aligned" | "__regparm__" | "regparm"), _::[]) -> []
      | (("packed" | "__packed__"), _::[]) -> 
	  Npkcontext.report_ignore_warning "NpkParser.attribute_name" 
	    "packed attribute" Npkcontext.Pack;
	  []
      | (("__nonnull__" | "__nonnull"), _) -> []
      | _ -> raise Parsing.Parse_error
  }
| IDENTIFIER LPAREN SIZEOF LPAREN type_name RPAREN RPAREN
  {
    match $1 with
	"aligned" -> []
      | _ -> raise Parsing.Parse_error
  }
| IDENTIFIER LPAREN LPAREN LPAREN INTEGER RPAREN
  SHIFTL INTEGER RPAREN RPAREN    {
    match $1 with
	"aligned" -> []
      | _ -> raise Parsing.Parse_error
  }
| IDENTIFIER LPAREN LPAREN INTEGER SHIFTL
  LPAREN INTEGER RPAREN RPAREN RPAREN    {
    match $1 with
	"__aligned__" -> []
      | _ -> raise Parsing.Parse_error
  }
| IDENTIFIER LPAREN INTEGER SHIFTL
  LPAREN INTEGER RPAREN RPAREN    {
    match $1 with
	"__aligned__" -> []
      | _ -> raise Parsing.Parse_error
  }
| IDENTIFIER LPAREN LPAREN 
      IDENTIFIER LPAREN type_name RPAREN 
      RPAREN RPAREN                         { 
	if $1 <> "aligned" then raise Parsing.Parse_error;
	if $4 <> "__alignof__" then raise Parsing.Parse_error;
	[]
      }
| IDENTIFIER LPAREN 
    IDENTIFIER COMMA INTEGER COMMA INTEGER 
  RPAREN                                   {
(* TODO: instead of comparing all the possibilities __format__, format...
   maybe have a treatment that trims the __ first and then compares
   and do that in an uniform way??
*)
    if $1 <> "__format__" && $1 <> "format" then raise Parsing.Parse_error;
    begin match $3 with
	"__printf__" | "printf" | "__scanf__" | "scanf"
      | "__strftime__" | "strftime" | "__strfmon__" | "strfmon"-> ()
      | _ -> raise Parsing.Parse_error
    end;
    [] 
  }
| IDENTIFIER LPAREN IDENTIFIER RPAREN           { 
    if $1 <> "__mode__" && $1 <> "mode" then raise Parsing.Parse_error;
    let imode =
      match $3 with
          "__QI__" | "QI" -> !Conf.size_of_byte
	| "__HI__" | "HI" -> !Conf.size_of_byte*2
	| "__SI__" | "SI" | "__word__" -> !Conf.size_of_byte*4
	| "__DI__" | "DI" -> !Conf.size_of_byte*8
	| "__TI__" | "TI" -> !Conf.size_of_byte*16
	| _ -> raise Parsing.Parse_error
    in
      imode::[]
  }
| CONST                                    { [] }
;;

string_list:
  STRING                                   { () }
| STRING string_list                       { () }
;;

integer_list:
  INTEGER                                  { $1::[] }
| INTEGER COMMA integer_list               { $1::$3 }
;;

// Newspeak assertion language
assertion:
  SYMBOL assertion                         { (SymbolToken $1)::$2 }
| IDENTIFIER assertion                     { (IdentToken $1)::$2 }
| constant assertion                       { (CstToken $1)::$2 }
| EOF                                      { [] }
;;

extension_option:
  EXTENSION                                { }
|                                          { }
;;

volatile_option:
  VOLATILE                                 { }
|                                          { }
;;

expression_option:
  expression_sequence                      { Some $1 }
|                                          { None }
;;


