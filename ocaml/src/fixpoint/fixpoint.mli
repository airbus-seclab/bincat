
module Make: functor (Data: Data.T) ->
	     (** Fixpoint engine *)
sig

  module Cfa: Cfa.T
		
  (** the integer is the offset to add to address to start decoding *)
  val process: Data.Code.t ->  Cfa.t -> Cfa.t
end

