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
module Word: sig

    (** abstract data type *)
    type t

    (** returns the size in bits of the word *)
    val size: t -> int

    (** returns zero if the two parameters are equal
    a negative integer if the first one is less than the second one
    a positive integer otherwise *)
    val compare: t -> t -> int

    (** comparison *)
    val equal: t -> t -> bool

    (** [zero sz] is zero represented on _sz_ bits *)
    val zero: int -> t

    (** [one sz] is one represented on _sz_ bits *)
    val one: int -> t

    (** word addition *)
    val add: t -> t -> t

    (** word substraction *)
    val sub: t -> t -> t

    (** string representation *)
    val to_string: t -> string

    (** [of_int v sz] generates the value corresponding to the integer _v_ with _sz_ bit-width *)
    val of_int: Z.t -> int -> t

    (** integer conversion *)
    val to_int: t -> Z.t

    (** [of_string v n] generates the word corresponding to _v_ on _n_ bits *)
    val of_string: string -> int -> t

    (** hash function *)
    val hash: t -> int

    (** [sign_extension w n] sign extends _w_ to be on _n_ bits *)
    val size_extension: t -> int -> t

  (** returns the list of byte-size words constituting the given word. LSB first *)
    val to_bytes: t -> t list
      
  end

(** Address Data Type *)
module Address: sig

  (** unique identifier type of a heap chunk *)
  type heap_id_t = int

  (** trick to ensure that address into the heap have the same size as in global and stack region *)
  type pos = int option (** None means an address that can be used as a key in any environment 
                            Some n represents the symbolic nth byte of a heap address *)
    
  (** these memory regions are supposed not to overlap *)
  type region =
    | Global (** abstract base address of global variables and code *)
    | Heap of heap_id_t * Z.t (** abstract base address of a dynamically allocated memory block. The Z.t integer is the size in bits of the allocation *)

  (** conversion from Config.region to region *)
  val region_from_config: Config.region -> region
    
  (** string conversion of a region *)
  val string_of_region: region -> string
    
  (** data type of an address *)
  type t = region * Word.t

  (** value of the NULL address *)
  val of_null: unit -> t

  (** returns true whenever the given address is the NULL address *)
  val is_null: t -> bool
    
  (** returns zero if the two parameters are equal
      a negative integer if the first one is less than the second one
      a positive integer otherwise *)
  val compare: t -> t -> int

  (** comparison *)
  val equal: t -> t -> bool

  (** [of_string r a n] generates the address whose basis is _r_, offset is _a_ and size in bits is _n_ *)
  val of_string: region -> string -> int -> t

  (** string representation *)
  val to_string: t -> string

  (** returns the offset of the address *)
  val to_int: t -> Z.t

  (** generation from a given region, offset of type Z.t and size in bits *)
  val of_int: region -> Z.t -> int -> t

  (** generation from global region, offset of type Z.t and size from Config.address_sz *)
  val global_of_int: Z.t -> t

  (** generation from a given word *)
  val of_word: Word.t -> t

  (** returns the size in bits needed to the store the given address *)
  val size: t -> int

  (** add an offset to the given address *)
  val add_offset: t -> Z.t -> t

  (** add one to the given address *)
  val inc: t -> t

  (** substract one to the given address *)
  val dec: t -> t

  (** conversion to a word whose size is given by the integer parameter *)
  val to_word: t -> int -> Word.t

  (** returns the distance between two addresses into the same region *)
  val sub: t -> t -> Z.t

  (** [binary op w1 w2] return the result of w1 op w2 with op expressed as a Z operator *)
  val binary: (Z.t -> Z.t -> Z.t) -> t -> t -> t

  (** [unary op w] return the result of op w with op expressed as a Z operator *)
  val unary: (Z.t -> Z.t) -> t -> t

  (** left shift *)
  val shift_left: t -> int -> t

  (** right shift *)
  val shift_right: t -> int -> t

  (** negation *)
  val neg: t -> t

  (** extends the size in bits of the given address *)
  val size_extension: t -> int -> t

  (** returns a fresh heap region of the given size (in bits). The id of the new region is also returned *)
  val new_heap_region: Z.t -> region * int

  (** returns the heap region associated to the given heap id. The size of the region is also returned *)
  val get_heap_region: int -> region * Z.t

  (** returns the size of the heap region in bits *)
  val size_of_heap_region: int -> Z.t
  (** may raise Not_found *)
 
  (** set of addresses *)
  module Set: (Set.S with type elt = t)

end


