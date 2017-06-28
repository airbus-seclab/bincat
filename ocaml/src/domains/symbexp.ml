(*
  This file may eventually be part of BinCAT.

  Copyright 2017 - Frédéric Besson - Inria
*)

(** Abstract domain operations are sometimes costly to compute.  The
   following abstract domain functor delays evaluation and instead
   construct a symbolic expression.

   For efficiency, it is necessary to ensure that an expression is
   only evaluated once. For this purpose, expression are mutable and
   the result of an evaluation is stored by side-effect.  Tough the
   implementation has side-effect, the exposed interface should be
   functional.

   The current implementation is straightforward.  Most operations are
   implemented by simply evaluating the expressions and calling the
   relevant Vector operation. This might not always be the best option
   and it may be worth considering more symbolic computations.

   [In general, symbolic expressions are also valuable to improve
   transfer functions for non-relational domains.  In particular, to
   transfer information through conditionals.  This is not
   implemented...  ]

   [Implementation notes.
   The meet, join and widen could be more symbolic,
   Yet, this imposes stronger requirements over the base domain
   and has an impact on precision.
   More precisely, the requirements are
   - the Vector.binary and Vector.unary need to be monotonic.
     This is a classic requirement for AI that is sometimes relaxed.
   - There is a loss of precision
     if Vector.binary and Vector.unary are not distributive functions.

   Relational symbolic expressions, those using variables,
   are immune to this problem...
   ]
 *)

(** Signature of vector - borrowed from vector.ml *)
module type T = 
sig
    (** abstract data type *)
    type t

    (** top on sz bit-width *)
    val top: int -> t

    (** returns length *)
    val size: t -> int

    (** forgets the content while preserving the taint *)
    val forget: t -> (int * int) option -> t
    (** the forget operation is bounded to bits from l to u if the second parameter is Some (l, u) *)

    (** returns true whenever at least one bit may be tainted *)
    val is_tainted: t -> bool

    (** value conversion. May raise an exception *)
    val to_z: t -> Z.t

    (** char conversion. May raise an exception *)
    val to_char: t -> char

    (** abstract join *)
    val join: t -> t -> t

    (** abstract meet *)
    val meet: t -> t -> t

    (** widening *)
    val widen: t -> t -> t

    (** string conversion *)
    val to_string: t -> string

    (** string conversion (value string, taint string) *)
    val to_strings: t -> string * string

    (** binary operation *)
    val binary: Asm.binop -> t -> t -> t

    (** unary operation *)
    val unary: Asm.unop -> t -> t

    (** untaint *)
    val untaint: t -> t

    (** taint *)
    val taint: t -> t

    (** span taint *)
    val span_taint: t -> Tainting.t -> t

    (** conversion from word *)
    val of_word: Data.Word.t -> t

    (** comparison *)
    val compare: t -> Asm.cmp -> t -> bool

    (** conversion to a set of addresses *)
    val to_addresses: Data.Address.region -> t -> Data.Address.Set.t

    (** check whether the first argument is included in the second one *)
    val is_subset: t -> t -> bool
      
    (** conversion from a config value.
    The integer parameter is the size in bits of the config value *)
    val of_config: Config.cvalue -> int -> t
      
    (** conversion from a tainting value.
    The value option is a possible previous init *)
    val taint_of_config: Config.tvalue -> int -> t option -> t

    (** [combine v1 v2 l u] computes v1[l, u] <- v2 *)
    val combine: t -> t -> int -> int -> t

    (** return the value corresponding to bits l to u may raise an exception if range bits exceeds the capacity of the vector *)
    val extract: t -> int -> int -> t

    (** [from_position v i len] returns the sub-vector v[i]...v[i-len-1] may raise an exception if i > |v| or i-len-1 < 0 *)
    val from_position: t -> int -> int -> t

    (** [of_repeat_val v v_len nb] returns the concatenation of pattern v having length v_len, nb times *)
    val of_repeat_val: t -> int -> int -> t

    (** returns the concatenation of the two given vectors *)
    val concat: t -> t -> t

    (** returns the minimal taint value of the given parameter *)
    val get_minimal_taint: t -> Tainting.t
end

exception IncompatibleSizeError
  
module Make(Vector : T) : T =
  struct
    open Data

    (** Symbolic expressions built from [Asm.exp].
        [It might be valuable to enrich 
        the symbolic expression datatype with for instance:
        - conditional expressions
        - combine, extract, from_position, of_repeat_val, concat vector operations. 
     *)
       
    type t = { mutable exp : t_ }
    and  t_ = 
      | Aval  of Vector.t (* evaluated expression *)
      | Const of Word.t
      | Binop of Asm.binop * t * t
      | Unop of Asm.unop * t


    let of_aval v =
      { exp = Aval v}

    let of_expr v =
      { exp = v}

      
    let rec output_exp o v =
      match v.exp with 
      | Const w -> Printf.fprintf o "Const %s" (Word.to_string w)
      | Aval  v -> Printf.fprintf o "Aval %s" (Vector.to_string v)
      | Binop(b,v1,v2) -> Printf.fprintf o "(%a %s %a)" output_exp v1 (Asm.string_of_binop b) output_exp v2
      | Unop(b,v) -> Printf.fprintf o "%s %a" (Asm.string_of_unop b true) output_exp v

              
    let top i =
      let tp = Vector.top i in
      of_aval tp

    (** [size] is computed recursively.
        @raise [IncompatibleSizeError] *)
    let rec size  e =
      match e.exp with
      | Const w -> Word.size w
      | Aval v  -> Vector.size v
      | Binop(_,e1,e2) ->
         let s1 = size e1 in
         let s2 = size e2 in
         if s1 == s2 
         then s1
         else raise IncompatibleSizeError
      | Unop(_,e) -> size e

  (** [eval_exp] evaluates the expression using Vector operations.
      For efficency, it is essential to also record the evaluation result.
   *)
    let rec eval_exp e =
      match e.exp with
      | Const w -> let v = Vector.of_word w in
                   e.exp <- (Aval v) ; v
      | Aval v  -> v
      | Binop(b,e1,e2) ->
            let v1 = eval_exp e1 in
            let v2 = eval_exp e2 in
            e1.exp <- Aval v1 ;
            e2.exp <- Aval v2 ; 
            Vector.binary b v1 v2
         | Unop(b,e)      ->
            let v = eval_exp e in
            e.exp <- Aval v;
            Vector.unary b v

 (* The following code only records the evaluated value at top level.
    Experiments are needed to evaluated which alternative is better.

    let rec eval_exp e =
      match e.exp with
      | Const w -> Vector.of_word w 
      | Aval v  -> v
      | Binop(b,e1,e2) ->
            let v1 = eval_exp e1 in
            let v2 = eval_exp e2 in
            Vector.binary b v1 v2
         | Unop(b,e)      ->
            let v = eval_exp e in
            Vector.unary b v

    let eval_exp e =
      let v = eval_exp e in
      e.exp <- Aval v ;
      v
  *)

    let forget v s =
      of_aval (Vector.forget (eval_exp v) s)

    let is_tainted v = Vector.is_tainted (eval_exp v)

    let to_z v = Vector.to_z (eval_exp v)      
    let to_char v = Vector.to_char (eval_exp v)

                  

    let map2 d2 v v' =
      if v == v' then v
      else d2 v v'

    (* A recursive [map2]  is less precise if base operations are not distributive.
    let  map2 d2 v v' =
      let rec xmap2 v v' =
        if v == v' then v
        else
        match v.exp , v'.exp with
        | Const w1 , Const w2 -> if Word.equal w1 w2
                                 then v
                                 else d2 v v'
        | Aval _ , Aval _   -> d2 v v'
      | Binop(b,v1,v2) , Binop(b',v1',v2') ->
         if b = b'
         then of_expr (Binop(b,xmap2 v1 v1',xmap2 v2 v2'))
         else d2 v v'
      | Unop(b,v1) , Unop(b',v1') ->
         if b = b'
         then of_expr (Unop(b,xmap2 v1 v1'))
         else d2 v v'
      |   _ -> d2 v v'
      in
      xmap2 v v'
     *)
      
    let lift f v v' = 
      of_aval (f (eval_exp v) (eval_exp v'))
      
    let join  = map2 (lift Vector.join) 
               
    let  meet  = map2 (lift Vector.meet) 

    let widen  = map2 (lift Vector.widen) 

    let to_string v  = Vector.to_string (eval_exp v)

      
    let to_strings v = Vector.to_strings (eval_exp v)


    (** [binary b v1 v2] constructs a symbolic expression *)
    let binary b v1 v2 =
      of_expr (Binop(b,v1,v2))
      
    (** [unary b v] constructs a symbolic expression *)
    let unary b v = of_expr (Unop(b,v))

    (* [untaint] , [taint] and [span_taint] are symbolic.
       This is not entirely clear whether this makes sense. *)

    let map f v =
      let rec xmap  e = 
        match e.exp with
        | Const w1 -> of_expr (Const w1)
        | Aval v1  -> of_aval (f v1)
        | Binop(b,v1,v2) -> of_expr (Binop(b,xmap v1,xmap v2))
        | Unop(b,v1) -> of_expr (Unop(b,xmap v1)) in
      xmap v

    let untaint = map Vector.untaint

    let taint = map Vector.taint

    let span_taint v t = map (fun v -> Vector.span_taint v t) v

    let of_word w = of_expr (Const w)

    (* More symbolic ? *)
    let compare v c v' =
      Vector.compare (eval_exp v) c (eval_exp v')

    let to_addresses r v =
      Vector.to_addresses r (eval_exp v)

    let dis_subset v v' =
      Vector.is_subset (eval_exp v) (eval_exp v')

    (** [is_subset] may be proved symbolically.
        Yet, if this does not work, 
        it needs to resort to evaluating the expressions.
        Remember that evaluation may occur (at ant time) 
        and dynamically change the expression *)
      
    let rec is_subset v v' = 
      if v == v' then true
      else
        match v.exp , v'.exp with
        | Const w1 , Const w2 -> Word.equal w1 w2
        | Aval v1 , Aval v2   -> Vector.is_subset v1 v2
        | Binop(o,v1,v2) , Binop(o',v1',v2') ->
           if o = o'
           then
             if is_subset v1 v1' && is_subset v2 v2' 
             then true
             else dis_subset v v'                   
           else dis_subset v v'
        | Unop(o,v1) , Unop(o',v1') ->
           if o = o'
           then if is_subset v1 v1'
                then true
                else dis_subset v v'
           else dis_subset v v'
        |   _ -> dis_subset v v'
        
      
    let of_config c i = of_aval (Vector.of_config c i)
      
    let taint_of_config t i o =
      let o = match o with
        | None -> None
        | Some e -> Some (eval_exp e) in
      of_aval (Vector.taint_of_config t i o)

    (* Combine could be symbolic *)
    let combine v1 v2 l u = of_aval (Vector.combine (eval_exp v1) (eval_exp v2) l u)

    (* extract coudl also be symbolic *)
    let extract v i j = of_aval (Vector.extract (eval_exp v) i j)

    let from_position t i j =
      of_aval (Vector.from_position (eval_exp t) i j)

      
    let of_repeat_val t i j =
      of_aval (Vector.of_repeat_val (eval_exp t) i j)

    let concat v1 v2 =
      of_aval(Vector.concat (eval_exp v1) (eval_exp v2))

    let get_minimal_taint v =
      Vector.get_minimal_taint (eval_exp v)
  end
