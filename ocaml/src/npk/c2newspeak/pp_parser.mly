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
open Pp_syntax
%}

%token PRAGMA SHARP IDENTIFIER PUNCTUATOR NEW_LINE 
// TODO: section introduced to handle gcc preprocessor output
// it has <built-in> and <command line> in directives
// is this a valid hack??
%token SECTION
%token <string> STRING
%token <int> INTEGER
%type <Pp_syntax.t> parse
%start parse

%%

parse:
  SHARP PRAGMA pp_token_list NEW_LINE   { Pragma }
| SHARP INTEGER STRING 
  integer_list NEW_LINE                 { Line ($3, $2) }
| SHARP INTEGER SECTION integer_list 
  NEW_LINE                              { Non_directive }
;;

pp_token_list:
  pp_token pp_token_list                { }
|                                       { }
;;

pp_token:
  INTEGER                               { }
| STRING                                { }
| SECTION                               { }
| IDENTIFIER                            { }
| PUNCTUATOR                            { }
;;

integer_list:
  INTEGER integer_list                  { }
|                                       { }
;;
