(** Alarm printing *)
type t =
  Top
| Empty
| Undef
| Unknown
| Concretization of string (** raised whenever a domain (name is the string) has too imprecise result *)

exception E of t

val error_msg: t -> unit
