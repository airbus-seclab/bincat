(** abstract domain of type reconstruction *)

(** abstract data type *)
type t =
  | TChar (* Char on 8 bits *)
  | TWord (* 16 bits *)
  | TDWord (* 32 bits *)
  | TInt of int (* integer on n bits *)
  | TUnknown (* no type information *)

(** string conversion *)
let to_string t =
  match t with
  | TChar -> "char8"
  | TWord -> "char16"     
  | TDWord -> "char32"
  | TInt n -> "int"^(string_of_int n)
  | TUnknown -> ""

(** comparison *)
let leq t1 t2 =
  match t1, t2 with
  | TChar, TChar
  | TWord, TWord
  | TDWord , TDWord -> true
  | _, TUnknown -> true
  | TInt n1, TInt n2 when n1 = n2 -> true
  | _, _ -> false
  
