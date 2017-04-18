(***********************************************************************)
(*                                                                     *)
(*                                OCaml                                *)
(*                                                                     *)
(*            Xavier Leroy, projet Cristal, INRIA Rocquencourt         *)
(*                                                                     *)
(*  Copyright 1996 Institut National de Recherche en Informatique et   *)
(*  en Automatique.  All rights reserved.  This file is distributed    *)
(*  under the terms of the GNU Library General Public License, with    *)
(*  the special exception on linking described in file COPYING-LGPL    *)
(*                                                                     *)
(*  Modifications by Airbus Group - Copyright 2014-2017                *)
(*                                                                     *)
(***********************************************************************)

(** Association tables over ordered types.

   This module implements applicative association tables, also known as
   finite maps or dictionaries, given a total ordering function
   over the keys.
   All operations over maps are purely applicative (no side-effects).
   The implementation uses balanced binary trees, and therefore searching
   and insertion take time logarithmic in the size of the map. 
    
*)

module type OrderedType = 
sig
  
  (** The type of the map keys. *)
  type t 
  
  (** A total ordering function over the keys.
      This is a two-argument function [f] such that
      [f e1 e2] is zero if the keys [e1] and [e2] are equal,
      [f e1 e2] is strictly negative if [e1] is smaller than [e2],
      and [f e1 e2] is strictly positive if [e1] is greater than [e2]. *)
  val compare: t -> t -> int 
  
end


(** Functor building an implementation of the map structure
    given a totally ordered type. *)
module Make (Ord: OrderedType): 
sig
  type key = Ord.t
    (** The type of the map keys. *)
    
  type (+'a) t
    (** The type of maps from type [key] to type ['a]. *)
    
  val empty: 'a t
    (** The empty map *)
    
  val is_empty: 'a t -> bool
    (** Test whether a map is empty or not. *)

  val add: key -> 'a -> 'a t -> 'a t
    (** [add x y m] returns a map containing the same bindings as
	[m], plus a binding of [x] to [y]. If [x] was already bound
	in [m], its previous binding disappears. *)

  val find: key -> 'a t -> 'a
    (** [find x m] returns the current binding of [x] in [m],
	or raises [Not_found] if no such binding exists. *)

  val find_key: (key -> int) -> 'a t -> key * 'a
  (** [find_key p x] returns the key k and its associated value in [x] that satisfies predicate [p k = 0] or raises [Not_found] if no such binding exists
   if several keys satisfy the predicate then the first uncountered one is returned *)

  val find_all_keys: (key -> bool) -> 'a t -> (key * 'a) list
  (** [find_all_keys p x] returns the list of k and associated values in [x] that satisfy predicate p
  order in returned keys is left branch keys <= current key <= right branch keys *)
						       
  val remove: key -> 'a t -> 'a t
    (** [remove x m] returns a map containing the same bindings as
	[m], except for [x] which is unbound in the returned map.
	Raises [Not_found] if no such binding exists. *)

  val replace: key -> 'a -> 'a t -> 'a t
    (** [replace x d m] returns a map containing the same bindings as
	[m], except for [x] which is bound to [d] in the returned map.
    	Raises [Not_found] if no such binding exists. 
	Prefer this function to add whenever possible. Since it is more
	efficient. *)

  val update: key -> ('a -> 'a) -> 'a t -> 'a t
    (** [update x f m] updates the value [v] found at [x] by [f v].
	Raises [Not_found] if no such binding exists. 
    *)

  val mem: key -> 'a t -> bool
    (** [mem x m] returns [true] if [m] contains a binding for [x],
	and [false] otherwise. *)

  val iter: ('a -> unit) -> 'a t -> unit
    (** [iter f m] applies [f] to all bindings in map [m].
	[f] receives the associated value
	as argument.  The bindings are passed to [f] in increasing
	order with respect to the ordering over the type of the keys.
	Only current bindings are presented to [f]:
	bindings hidden by more recent bindings are not passed to [f]. *)

  val iteri: (key -> 'a -> unit) -> 'a t -> unit
    (** [iter f m] applies [f] to all bindings in map [m].
	[f] receives the key as first argument, and the associated value
	as second argument.  The bindings are passed to [f] in increasing
	order with respect to the ordering over the type of the keys.
	Only current bindings are presented to [f]:
	bindings hidden by more recent bindings are not passed to [f]. *)


  val iter_from: key -> (key -> 'a -> unit) -> 'a t -> unit

  val iter2: ('a -> 'b -> unit) -> 'a t -> 'b t -> unit
    (** [iter2 f m1 m2] applies [f] to all bindings in maps [m1] and [m2].
	Raise [Invalid_argument] if the two  maps have different domains.
	[f] receives the associated values
	in m1 and m2 as first and second arguments respectively.
	The bindings are passed to [f] in increasing
	order with respect to the ordering over the type of the keys.
	Only current bindings are presented to [f]:
	bindings hidden by more recent bindings are not passed to [f]. *)
   
  val iteri2: (key -> 'a -> 'b -> unit) -> 'a t -> 'b t -> unit
    (** [iteri2 f m1 m2] applies [f] to all bindings in maps [m1] and [m2].
	Raise [Invalid_argument] if the two  maps have different domains.
	[f] receives the key as first argument, and the associated values
	in m1 and m2 as second and third arguments respectively.
	The bindings are passed to [f] in increasing
	order with respect to the ordering over the type of the keys.
	Only current bindings are presented to [f]:
	bindings hidden by more recent bindings are not passed to [f]. *)

  val map: ('a -> 'b) -> 'a t -> 'b t
    (** [map f m] returns a map with same domain as [m], where the
	associated value [a] of all bindings of [m] has been
	replaced by the result of the application of [f] to [a].
	The bindings are passed to [f] in increasing order
	with respect to the ordering over the type of the keys. *)

  val map2: ('a -> 'a -> 'a) -> 'a t -> 'a t -> 'a t
    (** [map2 f m] returns a map with same domain as [m1] (or [m2]),
	so that every binding of [m1] (or [m2]) is associated to [f] [a] [b],
	where [a] and [b] are the associated values by [m1] and [m2]
	respectively. The bindings are passed to [f] in increasing order
	with respect to the ordering over the type of the keys.
	Raise [Invalid_argument] if the two maps have different domains. *)

  val mapi: (key -> 'a -> 'b) -> 'a t -> 'b t    
    (** Same as {!MapOpt.S.map}, but the function receives as arguments both the
	key and the associated value for each binding of the map. *)

  val mapi2: (key -> 'a -> 'a -> 'a) -> 'a t -> 'a t -> 'a t
    (** Same as {!MapOpt.S.map2}, but the function receives as arguments both the
	key and the associated values for each binding of the both maps. *)

  val fold: (key -> 'a -> 'b -> 'b) -> 'a t -> 'b -> 'b
    (** [fold f m a] computes [(f kN dN ... (f k1 d1 a)...)],
	where [k1 ... kN] are the keys of all bindings in [m]
	(in increasing order), and [d1 ... dN] are the associated data. *)

  val fold2: (key -> 'a -> 'b -> 'c -> 'c) -> 'a t -> 'b t -> 'c -> 'c
    (** [fold f m1 m2 a] computes [(f kN dN dN' ... (f k1 d1 d1' a)...)],
	where [k1 ... kN] are the keys of all bindings in [m1] (or [m2])
	(in increasing order), and [d1 ... dN] and [d1' ... dN'] are the 
	associated data in [m1] and [m2] respectively. 
	Raise [Invalid_argument] if the two maps have different domains. *)

  val for_all: ('a -> bool) -> 'a t -> bool
    (** [for_all p m] checks if all elements of the image of [m] satisfies 
	the predicate p. *)

  val for_all2: ('a -> 'a -> bool) -> 'a t -> 'a t -> bool
    (** [for_all2 p m1 m2] checks if, for all binding [v] in [m1] (or [m2]), 
	[p a1 a2] is satified, where [a1] and [a2] denote the associated data
	to [v] in [m1] and [m2] respectively.
	Raise [Invalid_argument] if the two maps have different domains. *)

  val exists: ('a -> bool) -> 'a t -> bool
    (** [exists p m] checks if at least one element of the image of [m] 
	satisfies predicate [p]. 
	In other words, it returns [(p d1) || ... || (p dn)]. *)

  val compare: ('a -> 'a -> int) -> 'a t -> 'a t -> int
    (** Total ordering between maps.  The first argument is a total ordering
        used to compare data associated with equal keys in the two maps. *)

  val equal: ('a -> 'a -> bool) -> 'a t -> 'a t -> bool
    (** [equal cmp m1 m2] tests whether the maps [m1] and [m2] are
	equal, that is, contain equal keys and associate them with
	equal data.  [cmp] is the equality predicate used to compare
	the data associated with the keys. *)

  val concat :  'a t ->  'a t -> 'a t 
    (** Concatenates two maps *)

  val max_key : 'a t -> key
    (** returns the largest key stored in the map. O(log(n)).
	Raises Not_found when map is empty. *)

  val min_key : 'a t -> key
    (** returns the smallest key stored in the map. O(log(n)).
	Raises Not_found when map is empty. *)

  val cardinal : 'a t -> int
    (** returns the number of elements in the support of the map. O(n). *)

end

