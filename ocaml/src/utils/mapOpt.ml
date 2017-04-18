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


module type OrderedType =
sig
  type t
  val compare: t -> t -> int
end

module Make(Ord: OrderedType) = struct
    type key = Ord.t

    type 'a t =
        Empty
(* left tree, key, value, right tree, height of whole tree *)
      | Node of ('a t * key * 'a * 'a t * int)

    let height = function
        Empty -> 0
      | Node(_, _, _, _,h) -> h

    let create l x d r =
      let hl = height l and hr = height r in
      Node(l, x, d, r, (if hl >= hr then hl + 1 else hr + 1))

    let bal l x d r =
      let hl = height l and hr = height r in
      if hl > hr + 2 then begin
        match l with
          Empty -> invalid_arg "MapOpt.bal"
        | Node(ll, lv, ld, lr, _) ->
            if height ll >= height lr then
              create ll lv ld (create lr x d r)
            else begin
              match lr with
                Empty -> invalid_arg "MapOpt.bal"
              | Node(lrl, lrv, lrd, lrr, _)->
                  create (create ll lv ld lrl) lrv lrd (create lrr x d r)
            end
      end else if hr > hl + 2 then begin
        match r with
          Empty -> invalid_arg "MapOpt.bal"
        | Node(rl, rv, rd, rr, _) ->
            if height rr >= height rl then
              create (create l x d rl) rv rd rr
            else begin
              match rl with
                Empty -> invalid_arg "MapOpt.bal"
              | Node(rll, rlv, rld, rlr, _) ->
                  create (create l x d rll) rlv rld (create rlr rv rd rr)
            end
      end else
        Node(l, x, d, r, (if hl >= hr then hl + 1 else hr + 1))

    let empty = Empty

    let is_empty = function Empty -> true | _ -> false

    let rec add x data = function
        Empty ->
          Node (Empty, x, data, Empty, 1)
      | Node(l, v, d, r, h) ->
          let c = Ord.compare x v in
          if c = 0 then
            Node (l, x, data, r, h)
          else if c < 0 then
            bal (add x data l) v d r
          else
            bal l v d (add x data r)

    let rec max_key x =
      match x with
	  Empty -> raise Not_found
	| Node (_, v, _, Empty, _) -> v
	| Node (_, _, _, r, _) -> max_key r

    let rec min_key x =
      match x with
	  Empty -> raise Not_found
	| Node (Empty, v, _, _, _) -> v
	| Node (l, _, _, _, _) -> min_key l

    let find_key p x =
      let rec find x =
	match x with
	| Empty -> raise Not_found
	| Node (l, k, v, r, _) ->
	   if p k = 0 then k, v
	   else if p k < 0 then find l
	   else find r
      in
      find x

    let find_all_keys p x =
      let rec find x =
	match x with
	| Empty -> []
	| Node (l, k, v, r, _) ->
	   let l' = find l in
	   let r' = find r in
	   l' @ (if p k then (k, v)::r' else r')
      in
      find x
		      
    let rec mem x = function
        Empty ->
          false
      | Node(l, v, _, r, _) ->
          let c = Ord.compare x v in
          c = 0 || mem x (if c < 0 then l else r)

    let rec min_binding = function
        Empty -> raise Not_found
      | Node (Empty, x, d, _, _) -> (x, d)
      | Node (l, _, _, _, _) -> min_binding l

    let rec remove_min_binding = function
        Empty -> invalid_arg "MapOpt.remove_min_elt"
      | Node (Empty, _, _, r, _) -> r
      | Node (l, x, d, r, _) -> bal (remove_min_binding l) x d r

    let merge t1 t2 =
      match (t1, t2) with
          (Empty, t) -> t
	| (t, Empty) -> t
	| (_, _) ->
            let (x, d) = min_binding t2 in
              bal t1 x d (remove_min_binding t2)
		
    let rec remove x = function
        Empty -> Empty
      | Node(l, v, d, r, _) ->
          let c = Ord.compare x v in
          if c = 0 then merge l r
          else if c < 0 then bal (remove x l) v d r
          else bal l v d (remove x r)

   
    let rec find x = function
        Empty ->
          raise Not_found
      | Node(l, v, d, r, _) ->
          let c = Ord.compare x v in
          if c = 0 then d
          else find x (if c < 0 then l else r)

    let rec update x f m =
      match m with
	  Empty -> raise Not_found 
	| Node (l, v, d, r, h) -> 
	    let c = Ord.compare x v in
	      if c = 0 then Node (l, v, f d, r, h)
	      else if c < 0 then Node (update x f l, v, d, r, h)
	      else Node (l, v, d, update x f r, h)
      

	
    let rec replace x data = function
	Empty -> raise Not_found
      | Node (l, v, d, r, h) ->
	  let c = Ord.compare x v in
            if c = 0 then Node (l, v, data, r, h)
(* important not: there is no need to balance the tree here, since
   we are replacing a node and not changing the structure of the tree at all 
*)
	    else if c < 0 then Node (replace x data l, v, d, r, h)
	    else Node (l, v, d, replace x data r, h)

    let rec iteri f x =
      match x with 
	Empty -> ()
      | Node (l, v, d, r, _) ->
	iteri f l; f v d; iteri f r


    let rec iter f = function
        Empty -> ()
      | Node(l, _, d, r, _) ->
          iter f l; f d; iter f r

    
    let iter_from x f t =
      let rec iter_from t =
	match t with
	    Node (l, v, d, r, _) -> 
	      let c = Ord.compare x v in
		if c < 0 then iter_from l;
		if c <= 0 then f v d;
		iter_from r
	  | Empty -> ()
      in
	iter_from t

    let rec iter2 f m1 m2 =
      match (m1,m2) with
	| (Empty, Empty) -> ()
	| (Node(l1, v1, d1, r1, _), Node(l2, v2, d2, r2, _)) 
	    when Ord.compare v1 v2 = 0 ->
	    iter2 f l1 l2; f d1 d2; iter2 f r1 r2
	| _ -> invalid_arg "MapOpt.iter2"

    let rec iteri2 f m1 m2 =
      match (m1,m2) with
	| (Empty, Empty) -> ()
	| (Node(l1, v1, d1, r1, _), Node(l2, v2, d2, r2, _)) 
	    when Ord.compare v1 v2 = 0 ->
	    iteri2 f l1 l2; f v1 d1 d2; iteri2 f r1 r2
	| _ -> invalid_arg "MapOpt.iter2"


    let rec map f = function
        Empty               -> Empty
      | Node(l, v, d, r, h) -> Node(map f l, v, f d, map f r, h)

   
    let rec mapi f = function
        Empty               -> Empty
      | Node(l, v, d, r, h) -> Node(mapi f l, v, f v d, mapi f r, h)

    (* Carefull set_root does not preserve the balancing
       + the height may be incorrect *)
    let rec set_root k (l, v, d, r, h) =
      match (l, r) with
	  _ when v = k -> (l, v, d, r, h)
	| (Node n, _) when Ord.compare k v < 0 ->
	    let (ll, _, ld, lr, lh) = set_root k n in
	      (ll, k, ld, Node (lr, v, d, r, h), lh)
	| (_, Node n) ->
	    let (rl, _, rd, rr, rh) = set_root k n in
	      (Node (l, v, d, rl, h), k, rd, rr, rh)
	| _ -> invalid_arg "MapOpt.set_root"


    (* f must be such that f d d = d
       m1 and m2 should have the same set of keys *)
    let rec map2 f m1 m2 =
      match (m1, m2) with
	  _ when (m1 == m2) -> m1
	| (Node (l1, v1, d1, r1, h1), Node (l2, v2, d2, r2, _))
	    when (Ord.compare v1 v2 = 0) ->
	    Node (map2 f l1 l2, v1, f d1 d2, map2 f r1 r2, h1)

	| (Node (_, v, _, _, _), Node n) -> 
	    map2 f m1 (Node (set_root v n))

	| _ -> invalid_arg "MapOpt.map2_opt"

    let rec mapi2 f m1 m2 =
      match (m1, m2) with
	  _ when (m1 == m2) -> m1
	| (Node (l1, v1, d1, r1, h1), Node (l2, v2, d2, r2, _))
	    when (Ord.compare v1 v2 = 0) ->
	    Node (mapi2 f l1 l2, v1, f v1 d1 d2, mapi2 f r1 r2, h1)

	| (Node (_, v, _, _, _), Node n) -> 
	    mapi2 f m1 (Node (set_root v n))

	| _ -> invalid_arg "MapOpt.mapi2"

    
    let rec for_all p m =
      match m with
	Empty -> true
      | Node (l, _, d, r, _) -> p d && (for_all p l) && (for_all p r)

    (* p must be such that p m m = true *)
    let rec for_all2 p m1 m2 = 
      match (m1,m2) with
	  _ when m1 == m2 -> true
	| (Node(l1, v1, d1, r1, _), Node(l2, v2, d2, r2, _)) 
	    when (Ord.compare v1 v2 = 0) ->
	    (p d1 d2) && (for_all2 p l1 l2) && (for_all2 p r1 r2)
	| (Node (_, v, _, _, _), Node n) -> 
	    for_all2 p m1 (Node (set_root v n))
	| _ ->  invalid_arg "MapOpt.for_all2"

    
    
		  
    let rec fold f m accu =
      match m with
        Empty -> accu
      | Node(l, v, d, r, _) ->
          fold f l (f v d (fold f r accu))

    let rec fold2 f m1 m2 accu =
      match (m1,m2) with
	| (Empty,Empty) -> accu
	| (Node(l1, v1, d1, r1, h1),Node(l2, v2, d2, r2, h2)) 
	    when (h1 = h2) && (Ord.compare v1 v2 = 0) ->
	    fold2 f l1 l2 (f v1 d1 d2 (fold2 f r1 r2 accu))
	| _ ->  invalid_arg "MapOpt.fold2"

    

   

    let rec exists p m = 
      match m with
	  Empty -> false
	| Node (l, _, d, r, _) -> (p d) || (exists p l) || (exists p r)

    type 'a enumeration = End | More of key * 'a * 'a t * 'a enumeration

    let rec cons_enum m e =
      match m with
        Empty -> e
      | Node(l, v, d, r, _) -> cons_enum l (More(v, d, r, e))

    let compare cmp m1 m2 =
      let rec compare_aux e1 e2 =
          match (e1, e2) with
          (End, End) -> 0
        | (End, _)  -> -1
        | (_, End) -> 1
        | (More(v1, d1, r1, e1), More(v2, d2, r2, e2)) ->
            let c = Ord.compare v1 v2 in
            if c <> 0 then c else
            let c = cmp d1 d2 in
            if c <> 0 then c else
            compare_aux (cons_enum r1 e1) (cons_enum r2 e2)
      in compare_aux (cons_enum m1 End) (cons_enum m2 End)

    let equal cmp m1 m2 =
      let rec equal_aux e1 e2 =
          match (e1, e2) with
          (End, End) -> true
        | (End, _)  -> false
        | (_, End) -> false
        | (More(v1, d1, r1, e1), More(v2, d2, r2, e2)) ->
            Ord.compare v1 v2 = 0 && cmp d1 d2 &&
            equal_aux (cons_enum r1 e1) (cons_enum r2 e2)
      in equal_aux (cons_enum m1 End) (cons_enum m2 End)

    let concat m1 m2 =
      let result = ref m1 in
      let add key data = result := add key data !result in
	iteri add m2;
	!result


    let rec cardinal m =
      match m with
	| Node (l, _, _, r, _) -> cardinal l + cardinal r + 1
	| Empty -> 0

end
