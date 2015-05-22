(** Utilities *)

(** raised whenever a computed abstract value is bottom *)
exception Bottom

(** raised whenever the concretization of an address is a too long list *)
exception Enum_failure

(** raised whenever an empty abstract state/domain value is computed *)
exception Emptyset
