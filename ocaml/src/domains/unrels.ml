(* k-set of Unrel *)
module Make(D: T) =
  (struct
    module U = Unrel.Make(D)
    module USet = Set.Make(struct type t = U.t let compare = U.compare end)
    type = USet.t
  end: Domain.T)
