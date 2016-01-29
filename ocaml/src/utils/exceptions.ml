(** raised when a concretization computes a too large result the first string *)
(** is the module name that generated the exception ; the second string is an explanation on the origin *)
exception Enum_failure of string * string

(** raised when the address to compute has an unexpected format *)
exception Illegal_address                
