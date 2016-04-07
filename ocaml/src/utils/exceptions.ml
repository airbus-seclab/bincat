(** raised when a concretization computes a too large result *)
exception Enum_failure

(** raised when the address to compute has an unexpected format *)
exception Illegal_address                

(** raised when a concretization fails *)
exception Concretization

(** raised when an abstract operation produces an empty value *)
exception Empty

(** raised when an unexpected behavior happens (undefined decoding, etc.) *)
exception Error of string

