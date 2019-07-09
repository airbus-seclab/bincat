(*
    This file is part of BinCAT.
    Copyright 2014-2019 - Airbus

    BinCAT is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or (at your
    option) any later version.

    BinCAT is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with BinCAT.  If not, see <http://www.gnu.org/licenses/>.
*)

module L = Log.Make(struct let name = "byte_interval" end)

type t = {l: Z.t; u: Z.t; sz: int} (* l=lower bound; u=upper bound; sz=width in bits *)
  
let lbound: Z.t = Z.zero

let ubound (sz: int): Z.t = Z.sub (Z.shift_left Z.one sz) Z.one (* TODO: optimize with memoization ?*)

let top (sz: int): t = {l=lbound; u=ubound sz; sz=sz}

let size (v: t): int = v.sz
             
let forget (v: t) _opt: t =
  (*TODO: could be more precise by pattern mathcing opt argument *) top v.sz
             
let of_word (w: Data.Word.t): t =
  let z = Data.Word.to_int w in 
  let sz = Data.Word.size w in
  {l=z; u=z; sz=sz}

let check_size (i1: t) (i2: t): unit=
  if i1.sz <> i2.sz then
    raise (Exceptions.Error "illegal binary operation different interval widths")
   
let join (i1: t) (i2: t): t =
  check_size i1 i2;
  let l = Z.min i1.l i2.l in
  let u = Z.max i1.u i2.u in
  { l=l; u=u;  sz=i1.sz}

let widen i1 i2 =
  check_size i1 i2;
  let l' = if Z.compare i2.l i1.l < 0 then lbound else i2.l in
  let u' = if Z.compare i1.u i2.u < 0 then ubound i2.sz else i2.u in
  { l=l'; u=u'; sz=i1.sz }

let is_singleton i = Z.compare i.l i.u = 0
                     
let to_z i =
  if is_singleton i then i.l else
    raise (Exceptions.Analysis (Exceptions.Too_many_concrete_elements "to_z: non singleton interval"))

let to_char i =
  if is_singleton i then Char.chr (Z.to_int i.l)
  else
    raise (Exceptions.Analysis (Exceptions.Too_many_concrete_elements "to_char: non singleton interval or too large"))
         
let meet i1 i2 =
  check_size i1 i2;
  let l = Z.max i1.l i2.l in
  let u = Z.min i1.u i2.u in
  if Z.compare l u > 0 then raise (Exceptions.Analysis (Exceptions.Empty "meet"))
  else {l=l; u=u; sz=i1.sz}

let is_subset i1 i2 = Z.compare i1.l i2.l <= 0 && Z.compare i1.u i2.u <= 0 

let to_string i =
     if Z.compare i.l i.u = 0 then Z.to_string i.l
     else "["^(Z.to_string i.l)^", "^(Z.to_string i.u)^"]"

let shift_left i n = {l=Z.shift_left i.l n; u=Z.shift_left i.u n; sz=i.sz+n}
                     
let concat (i1: t) (i2: t): t =
  (* the check on size is performed by shift_left *)
  let i' = shift_left i1 i2.sz in
     {l=Z.add i'.l i2.l; u=Z.add i'.u i2.u; sz=i'.sz}

let val_of_sign_extend first last =
  let rec acc n =
    if n = first then Z.shift_left Z.one first
    else
      let n' = acc (n-1) in
      Z.add n' (Z.shift_left n' 1)
  in
  acc (last-1)
       
let unary op i =
  match op with
  | Asm.Not ->
     { l=Z.lognot i.u; u=Z.lognot i.l; sz=i.sz }     

  | Asm.ZeroExt n ->
     if i.sz >= n then i
     else { i with sz=n }

  | Asm.SignExt n ->
        if i.sz >= n then i  
        else
          if is_singleton i then
            let nz = Z.shift_left (Z.of_int 2) (i.sz-1) in
            if Z.compare i.u nz < 0 then
              (* sign is zero *)
              { i with sz=n }
            else
              if Z.compare i.l nz > 0 then
                (* sign is one *)
                let nz' = val_of_sign_extend i.sz n in
                { l=Z.add nz' i.l; u=Z.add nz' i.u; sz=n } 
              else top i.sz
          else top i.sz

let bounds i = i.l, i.u
             
let mul i1 i2 =
  let l = Z.mul i1.l i2.l in
  let u = Z.mul i1.u i2.u in
  { l = l; u = u; sz = Z.numbits }

let div_cst i c =
  let l, u = bounds i in
  if Z.compare c Z.zero = 0 then
    raise (Exceptions.Analysis Exceptions.DivByZero);
  if Z.compare l u = 0 then
    let d = Z.div l c in
    d, d
  else
      Z.div l c, Z.div u c 
    
let div i1 i2 =
  let l1, u1 = bounds i1 in
  let l2, u2 = bounds i2 in
  let l, u = 
    if Z.compare l2 u2 = 0 then
      div_cst i1 l2 
    else 
        Z.div l1 l2, Z.div u1 l2
  in
  { l = l; u = u; sz = i1.sz }
  
let rec binary op i1 i2 =
  match op with
  | Asm.Add ->
     let l = Z.add i1.l i2.l in
     let u = Z.add i1.u i2.u in
     let sz = max (Z.numbits l) (Z.numbits u) in
     { l = l ; u = u ; sz = sz }

  | Asm.Sub ->
     let i2' = {l = Z.neg i2.u; u = Z.neg i2.l; sz = i2.sz } in
     binary Asm.Add i1 i2'

  | Asm.Mul -> mul i1 i2
  | Asm.Div -> div i1 i2
  | Asm.IMul -> 
  | Asm.IDiv ->
  | Asm.Mod -> 
  | Asm.IMod -> 
  | Asm.And -> 
  | Asm.Or -> 
  | Asm.Xor -> 
  | Asm.Shr -> 
  | Asm.Shl -> 
  | _ ->
     let sz = 2 * (max i1.sz i2.sz) in
     top sz

let rec compare i1 cmp i2 =
  match cmp with
  | Asm.EQ | Asm.LEQ | Asm.LT ->
     Z.compare i1.l i2.l <= 0 && Z.compare i2.l i2.l <= 0
    
  | Asm.GEQ -> compare i2 Asm.LEQ i1
  | Asm.GT -> compare i2 Asm.LT i1
  | Asm.NEQ -> not (is_subset i1 i2)

let to_addresses r i =
  let rec process z =
    if Z.compare z i.u = 0 then
      Data.Address.Set.singleton (r, Data.Word.of_int z i.sz)
    else
      let addresses = process (Z.add z Z.one) in
      let a = Data.Address.of_int r z i.sz in
      Data.Address.Set.add a addresses
  in
  process i.l

let extract i low up =
  let l' = max i.l (Z.shift_left Z.one low) in
  let u' = min i.u (Z.shift_left Z.one up) in
  if Z.compare l' u' > 0 then
    raise (Exceptions.Error "illegal extract operation on intervals");
  { l = l'; u = u'; sz = i.sz }

let combine i1 i2 low up =
  (* TODO: factorize these checks with Vector.combine *)
  if i2.sz <> up-low+1 then
        L.abort (fun p -> p "combine: source is %d bits while it is supposed to fit into %d bits (from bit %i to %i)"
                            i2.sz (up-low+1) low up);
  
  if low > up then L.abort (fun p -> p "combine : low=%i > up=%i" low up);     if up >= i1.sz then
            L.abort (fun p -> p "combine : writing out of v1: up=%i >= length(v1)=%i" up i1.sz);
  let l' =
    if Z.compare i1.l (Z.shift_left Z.one low) <= 0 then i1.l
    else i2.l
  in
  let u' =
    if Z.compare i1.u (Z.shift_left Z.one up) > 0 then i1.u
    else i2.u
  in
  { l = l'; u = u'; sz = i1.sz }

let of_repeat_val i len nb =
  { l = i.l ; u = Z.mul i.u (Z.shift_left Z.one nb); sz = len*nb }

let from_position i l len =
  let lbound = Z.shift_left Z.one l in
  let ubound = Z.shift_left Z.one (l+len) in
  let l' = if Z.compare i.l lbound < 0 then lbound else i.l in
  let u' = if Z.compare i.u ubound < 0 then i.u else ubound in
  { l = l'; u = u'; sz = i.sz } 
  
let of_config c n =
  match c with
  | Config.Bytes (_, b) ->
     let z = Z.of_string_base 16 b in
     {l=z; u=z; sz = n}
     
  | Config.Bytes_Mask ((_, _), _) -> (* TODO: could be more precise *) top n
     
  | Config.Content (_, c) -> {l=c; u=c; sz=n}  
     
  | Config.CMask ((_, _c), _) -> (* TODO: could be more precise *) top n

