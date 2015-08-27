(** Data module type *)
module type T = sig
  (** hypothesis :
      - able to represent addresses range from 0 to 2^32 - 1
      - some operations may raise Underflow or Overflow
  *)
    
  
  (** Segment selector data type *)
  module Segment: sig

      (** abstract data type of a segment *)
      type t
      (** initial value of the cs segment *)
      val cs: t
      (** initial value of the ds segment *)
      val ds: t
      (** initial value of the ss segment *)
      val ss: t
      (** initial value of the es segment *)
      val es: t
      (** initial value of the fs segment *)
      val fs: t
      (** initial value of the gs segment *)
      val gs: t

      (** logical left shift *)
      val shift_left: t -> int -> t
    end
  (** *)

  (** Stack data type *)
  module Stack: sig
    val width: unit -> int
    end
  (** *)

  (** Word data type *)
  module Word : sig
    type t
    val default_size: unit -> int (** default size in bits *)
    val size: t -> int (** size in bits *)
    val compare: t -> t -> int
    val zero: int -> t (** [zero n] returns 0 on _n_ bits *)
    val one: int -> t (** [one n] returns 1 on _n_ bits *)
    val of_int: int -> int -> t (** [of_int v sz] returns the conversion of _v_ on _sz_ bits *)
    val to_int: t -> int (** may raise Overflow *)
    val of_string: string -> int -> t (** string conversion *)
    val sign_extend: t -> int -> t (** sign extension. The integer is the width of the data *)
    end

  (** Offset on a base address *)
  module Offset: sig
      type t
      (** converts an integer to an offset *)
      val of_int: int -> t
      (** may raise an exception *)

      (** string conversion *)
      val to_string: t -> string

      (** returns 0 if the two offests are equal *) 
      val compare: t -> t -> int
      (** a negative integer if the first parameter is less than the second one ; a positive integer otherwise *)
    end
		   
  (** type of an address *)
  module Address: sig
      type t
      (** default size in bits *)  
      val default_size: unit -> int

      (** size in bits *)
      val size: t -> int 
		       
      (** Int64 conversion *)
      val to_int64: t -> Int64.t
			   
      (** string conversion *)
      val to_string: t -> string
			    
      (** [of_string a sz] returns the address _a_ on _sz_ bits *)
      val of_string: string -> int -> t
      (** in Segmented memory models _a_ is supposed to be of the form se:offset *)
      (** may raise Invalid if the given string is not a valid *)
      (** representation of an offset wrt to the size given by the int parameter *)

      (** creates an address from a segment and an offset on it *)
      val make: Segment.t -> Offset.t -> int -> t
      (** the integer is the size in bits of the address *)
					   
      (** comparison of the two arguments *)
      val compare: t -> t -> int
      (** returns 0 if arguments are equal ; *)
      (** a positive number if the first argument is greater ; *)
      (** a negative number otherwise *)
			       
      (** returns true whenever the two arguments are equal *)
      val equal: t -> t -> bool
			     
      val add_offset: t -> Offset.t -> t
      (** [add_offset v o] add offset [o] to the address [v] *)
      (** may raise Invalid_argument if the result overflows or underflows *)
				    
      val to_word: t -> int -> Word.t
				 
      val hash: t -> int
		       
      val sub: t -> t -> Int64.t
      (** returns the distance between the two addresses *)
      (** may raise an exception if the size of the addresses are not the same *)
			   
      module Set: Set.S with type elt = t
    end

 
  end
