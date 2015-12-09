(** Utilities like exceptions, common data structures, etc. *)

(** raised whenever a computed abstract value is bottom *)
exception Bottom

(** raised whenever the concretization of an address is a too long list *)
exception Enum_failure

(** raised whenever an address is not legal (out of code string, etc.) *)
exception Illegal_address
