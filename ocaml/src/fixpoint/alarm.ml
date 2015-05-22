type t =
  Top
| Empty
| Undef
| Unknown
| Concretization of string

exception E of t

let stop = "Analysis stopped for this context:"

let error_msg a =
  match a with
    Top                 -> Printf.printf "%s too much imprecise" stop
  | Empty 		-> Printf.printf "%s dead code reached" stop
  | Undef               -> Printf.printf "%s undefined opcode" stop
  | Unknown             -> Printf.printf "%s unknown opcode (not decoded for the while)" stop
  | Concretization dom  -> Printf.printf "%s too much imprecise (%s) " stop dom
