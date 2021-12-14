(*
    This file is part of BinCAT.
    Copyright 2014-2018 - Airbus

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

    let compare_value (w1, _) (w2, _) =
        Z.compare w1 w2

    let equal v1 v2 = compare v1 v2 = 0

    let zero sz = Z.zero, sz

    let is_zero (z, _) = Z.compare z Z.zero = 0
                  
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

    let rec i_to_bytes (z: Z.t) (nb: int) (max: int): t list =
      if nb < max then
        (Z.logand z (Z.of_int 0xFF), 8)::(i_to_bytes (Z.shift_left z 8) (nb+1) max)
      else
        []
          
    let to_bytes ((w, sz): t): t list =
      if sz = 8 then
        [w, sz]
      else
        if sz mod 8 <> 0 then
          raise (Invalid_argument "Word: incompatible size for byte splitting")
        else
          let nb = sz / 8 in
          i_to_bytes w 0 nb
          
  end

(** Address Data Type *)
module Address =
struct

    module A = struct

      type heap_id_t = int
      type pos = int option
        
      (* these memory regions are supposed not to overlap *)
      type region =
        | Global 
        | Heap of heap_id_t * Z.t (* first int is the id ; second int is the size in bits *)
            

      type t = region * Word.t (* valid address *)
          
        let heap_id = ref 0

        let heap_tbl = Hashtbl.create 5

            
        let new_heap_region sz =
          let id = !heap_id in 
          let region = Heap (id, sz) in
          Hashtbl.add heap_tbl id sz;
          heap_id := !heap_id + 1;
          region, id

        let get_heap_region id =
          let sz = Hashtbl.find heap_tbl id in
          Heap (id, sz), sz
               
        let size_of_heap_region id = Hashtbl.find heap_tbl id
          
        let string_of_region r =
            match r with
            | Global -> ""
            | Heap (id, _)  -> "H"^(string_of_int id) ^ "-"

        let of_null () = Global, Word.of_int !Config.null_cst !Config.address_sz    

        let is_null (r, w) = r = Global && Word.is_zero w

        let region_from_config c =
          match c with
          | Config.G -> Global
          | Config.H -> fst (new_heap_region !Config.default_heap_size) 


        let compare_region r1 r2 =
          match r1, r2 with
            | Global, Global -> 0
            | Global, _ -> -1
            | Heap (id1, _), Heap (id2, _) -> id1 - id2
            | Heap _, Global -> 1

        let equal_region r1 r2 = compare_region r1 r2 = 0
                                                                              
        let compare (r1, w1) (r2, w2) =
             let n = compare_region r1 r2 in
             if n <> 0 then
               n
             else
               Word.compare_value w1 w2
        let to_string (r, w) = Printf.sprintf "%s%s" (string_of_region r) (Word.to_string w)
                             
        let equal (r1, w1) (r2, w2) =
            if equal_region r1 r2 then Word.equal w1 w2
            else false

        let of_string r a n =
            let w = Word.of_string a n in
            if Word.compare w (Word.zero n) < 0 then
              raise (Exceptions.Error "Tried to create negative address")
            else r, w



        (** returns the offset of the address *)
        let to_int (_, w) =  Word.to_int w

        let of_int r i o = r, (i, o)

        let global_of_int i = of_int Global i !Config.address_sz

        let of_word w = Global, w

        let size a = Word.size (snd a)


        let add_offset (r, w) o' =
            let n = Word.size w in
            let w' = Word.add w (Word.of_int o' n) in
            if Word.size w' > n then
                    r, Word.truncate w' n
            else r, w'

        let dec a = add_offset a (Z.minus_one)
        let inc a = add_offset a (Z.one)

        let to_word (_, w) sz =
            if Word.size w >= sz then w
            else
                raise (Exceptions.Error "overflow when tried to convert an address to a word")

        let sub a1 a2 =
          match a1, a2 with
          |  (r1, w1), (r2, w2) when equal_region r1 r2 ->
             let w = Word.sub w1 w2 in
             if Word.compare w (Word.zero (Word.size w1)) < 0 then
               raise (Exceptions.Error (Printf.sprintf "invalid address substraction: %s - %s" (to_string a1) (to_string a2)))
             else
               Word.to_int w
          | _, _  -> raise (Exceptions.Error (Printf.sprintf "invalid address substraction: %s - %s" (to_string a1) (to_string a2)))

        let binary op (r1, w1) (r2, w2): t =
               let r' =
                 match r1, r2 with
                 | Global, r | r, Global -> r
                 | r1, r2                ->
                    if equal_region r1 r2 then r1 else raise (Exceptions.Error "Invalid binary operation on addresses of different regions")
               in
               r', Word.binary op w1 w2

        let unary op (r, w) = r, Word.unary op w

        let size_extension (r,  w) sz = r, Word.size_extension w sz

        let shift_left (r, w) i = r, Word.shift_left w i
                        
        let shift_right (r, w) i = r, Word.shift_right w i
                        
        let neg (r, w) = r, Word.neg w
    end
    include A
    module Set = Set.Make(A)

end

