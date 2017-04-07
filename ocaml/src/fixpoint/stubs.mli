(** functor to generate transfer functions on the given abstract value that simulates the behavior of common library functions *)

module Make: functor (D: Domain.T) ->
sig

  (** [process d fun args] applies to the abstract value [d] the tranfer function corresponding to the call to the function library named [fun] with arguments [args]. 
It returns also a boolean true whenever the result is tainted. *) 
  val process : D.t -> string -> Asm.exp list -> D.t * bool
end
