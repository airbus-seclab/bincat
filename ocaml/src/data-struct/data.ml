(*
    This file is part of BinCAT.
    Copyright 2014-2017 - Airbus Group

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


(** Word data type *)
module Word =
  struct
    type t = Z.t * int (* the integer is the size in bits *)
		     
    (* TODO print leading zeros *)
    let to_string w = Z.format "%#x" (fst w)
		     
    let size w = snd w
		     
    let compare (w1, sz1) (w2, sz2) = 
      let n = Z.compare w1 w2 in
      if n = 0 then sz1 - sz2 else n
				     
    let equal v1 v2 = compare v1 v2 = 0
					
    let zero sz	= Z.zero, sz
			    
    let one sz = Z.one, sz
			  
    let add w1 w2 =
      let w' = Z.add (fst w1) (fst w2) in
      w', max (Z.numbits w') (max (size w1) (size w2))
	      
    let sub w1 w2 =
      let w' = Z.sub (fst w1) (fst w2) in
      w', max (Z.numbits w') (max (size w1) (size w2))
	      
	      
    let of_int v sz = v, sz
			   
    let to_int v = fst v
		       
    let of_string v n =
        try
          let v' = Z.of_string v in
          if Z.numbits v' > n then
            raise (Exceptions.Error (Printf.sprintf "word %s too large to fit into %d bits" v n))
          else
            v', n
        with _ -> raise (Exceptions.Error (Printf.sprintf "Illegal conversion from Z.t to word of %s" v))
			
    let hash w = Z.hash (fst w)
			
    let size_extension (v, sz) n = 
        if sz >= n then (v, sz)
        else 
            (v, n)

    (** returns the lowest n bit of the given int *)
    let truncate_int i n =
        Z.logand i (Z.sub (Z.shift_left Z.one n) Z.one)

    (** [truncate w n] returns the lowest n bits of w *)
    let truncate (w, sz) n =
        if sz < n then
            w, sz
        else
            truncate_int w n, n

    (** binary operation on words supposed to have the same size
	result is truncated to have size of the operands *)
    let binary op (w1, sz) (w2, _) =
        truncate_int (op w1 w2) sz, sz

    let unary op (w, sz) =
        truncate_int (op w) sz, sz

    let shift_left (w, sz) i = Z.shift_left w i, sz-i
    let shift_right (w, sz) i = Z.shift_right w i, sz-i
    let neg (w, sz) = Z.neg w, sz			
end

(** Address Data Type *)
module Address =
struct

    module A = struct

        (* these memory regions are supposed not to overlap *)
        type region =
          | Global (** abstract base address of global variables and code *)
          | Stack  (** abstract base address of the stack *)
          | Heap   (** abstract base address of a dynamically allocated memory block *)


        let char_of_region r =
            match r with
            | Global -> 'G'
            | Stack  -> 'S'
            | Heap   -> 'H'

        type t = region * Word.t

        let compare_region r1 r2 =
            match r1, r2 with
            | Global, Global -> 0
            | Global, _ -> -1
            | Stack, Stack -> 0
            | Stack, Global -> 1
            | Stack, Heap -> -1
            | Heap, Heap -> 0
            | Heap, Global -> 1
            | Heap, Stack -> 1

        let compare (r1, w1) (r2, w2) =
            let n = compare_region r1 r2 in
            if n <> 0 then
                n
            else
                Word.compare w1 w2

        let equal (r1, w1) (r2, w2) =
            let b = r1 = r2 in
            if b then Word.equal w1 w2
            else
                false

        let of_string r a n =
            if !Config.mode = Config.Protected then 
                let w = Word.of_string a n in
                if Word.compare w (Word.zero n) < 0 then
                    raise (Exceptions.Error "Tried to create negative address")
                else
                    r, w
            else
                raise (Exceptions.Error "Address generation for this memory mode not yet managed")

        let to_string (r, w) = Printf.sprintf "%c%s" (char_of_region r) (Word.to_string w)

        (** returns the offset of the address *)
        let to_int (_r, w) = Word.to_int w

        let of_int r i o = r, (i, o)

        let of_word w = Global, w

        let size a = Word.size (snd a)


        let add_offset (r, w) o' =
            let n = Word.size w in
            let w' = Word.add w (Word.of_int o' n) in
            if Word.size w' > n then
                begin
                    r, Word.truncate w' n
                end
            else
                r, w'

        let dec (r, w) = add_offset (r, w) (Z.minus_one)
        let inc (r, w) = add_offset (r, w) (Z.one)

        let to_word (_r, w) sz =
            if Word.size w >= sz then
                w
            else
                raise (Exceptions.Error "overflow when tried to convert an address to a word")

        let sub v1 v2 =
            match v1, v2 with
            | (r1, w1), (r2, w2)  when r1 = r2 ->
              let w = Word.sub w1 w2 in
              if Word.compare w (Word.zero (Word.size w1)) < 0 then
                raise (Exceptions.Error (Printf.sprintf "invalid address substraction: %s - %s" (to_string v1) (to_string v2)))
              else
                  Word.to_int w
            | _, _ 	-> raise (Exceptions.Error (Printf.sprintf "invalid address substraction: %s - %s" (to_string v1) (to_string v2)))

        let binary op ((r1, w1): t) ((r2, w2): t): t =
            let r' =
                match r1, r2 with
                | Global, r | r, Global -> r
                | r1, r2                ->
                  if r1 = r2 then r1 else raise (Exceptions.Error "Invalid binary operation on addresses of different regions")
            in
            r', Word.binary op w1 w2

        let unary op (r, w) = r, Word.unary op w

        let size_extension (r, w) sz = r, Word.size_extension w sz

        let shift_left (r, w) i = r, Word.shift_left w i
        let shift_right (r, w) i = r, Word.shift_right w i
        let neg (r, w) = r, Word.neg w
    end
    include A
    module Set = Set.Make(A)

end

