(*
    This file is part of BinCAT.
    Copyright 2014-2021 - Airbus

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

(** Signature of abstract domains *)

module type T =
    sig

      (** type of abstract values *)
      type t

      (** returns the initial value *)
      val init: unit -> t

      (** bottom value *)
      val bot: t

      (** make all computed dimensions to top *)
      val forget: t -> t

      (** comparison to bottom *)
      val is_bot: t -> bool

      (** returns true whenever the concretization of the first argument is included in the concretization of the second argument ;
    false otherwise *)
      val is_subset: t -> t -> bool

      (** remove the given register from the given abstract value *)
      val remove_register: Register.t -> t -> t

      (** forget the value of the given lvalue (ie set to top) *)
      val forget_lval: Asm.lval -> t -> t

      (** add the given register to the given abstract value with an optional initial value *)
      val add_register: Register.t -> t -> Data.Word.t option -> t

      (** string conversion. The int parameter is an id to be added to the generated string *)
      val to_string: t -> int -> string list

      (** int conversion of the given register.
      May raise an exception if this kind of operation is not a singleton or is undefined for the given domain *)
      val value_of_register: t -> Register.t -> Z.t

      (** string conversion of a register *)
      val string_of_register: t -> Register.t -> string list

      (** int conversion of the given expression.
      May raise an exception if this kind of operation is not a singleton or is undefined for the given domain *)
      val value_of_exp: t -> Asm.exp -> Z.t

      (** assignment into the given left value of the given expression.
      Returns also the taint of the given expression *)
      val set: Asm.lval -> Asm.exp -> t -> t * Taint.Set.t

      (** set the given left value to the given list of addresses. The asssociated string a short message explaining the origin of these addresses *)
      val set_lval_to_addr: Asm.lval -> (Data.Address.t * string) list -> t -> t * Taint.Set.t
        
      (** joins the two abstract values *)
      val join: t -> t -> t

      (** meets the two abstract values *)
      val meet: t -> t -> t

      (** widens the two abstract values *)
      val widen: t -> t -> t

      (** [set_memory_from_config a c nb m] update the abstract value in _m_ with the value configuration _c_ (pair content * tainting value ) for the memory location _a_
      The integer _nb_ is the number of consecutive configurations _c_ to set . The computed taint is also returned *)
      val set_memory_from_config: Data.Address.t -> Config.cvalue option * Config.tvalue list -> int -> t -> t * Taint.Set.t

      (** [set_register_from_config r c nb m] update the abstract value _m_ with the value configuration (pair content * tainting value) for register _r_.
      The integer _nb_ is the number of consecutive configuration _t_ to set. The computed taint is also returned *)
      val set_register_from_config: Register.t -> Config.cvalue option * Config.tvalue list -> t -> t * Taint.Set.t

      (** apply the given taint mask to the given register. The computed taint is also returned *)
      val taint_register_mask: Register.t -> Config.tvalue -> t -> t * Taint.Set.t

      (** applies the given taint to the given lvalue *)
      val taint_lval: Asm.lval -> Taint.t -> t -> t * Taint.Set.t

     
        
      (** apply the given taint to the given register *)
      val span_taint_to_register: Register.t -> Taint.t -> t -> t * Taint.Set.t


      (** apply the given taint mask to the given memory address.
          The computed taint is also returned *)
      val taint_address_mask: Data.Address.t -> Config.tvalue list -> t -> t * Taint.Set.t

      (** apply the given taint mask to the given memory address *)
      val span_taint_to_addr: Data.Address.t -> Taint.t -> t -> t * Taint.Set.t

      (** comparison. Returns also the taint value of the comparison *)
      val compare: t -> Asm.exp -> Asm.cmp -> Asm.exp -> t * Taint.Set.t

      (** returns the set of addresses pointed by the given expression.
      May raise an exception.
      The taint of the pointer expression is also returned *)
      val mem_to_addresses: t -> Asm.exp -> Data.Address.Set.t * Taint.Set.t

      val taint_sources: Asm.exp -> t -> Taint.Set.t

      (** [set_type lv t m] type the left value lv with type t *)
      val set_type: Asm.lval -> Types.t -> t -> t


      (** [get_address_of addr terminator upper_bound sz m] scans memory to get
      the lowest offset o <= upper_bound from address addr such that (sz)[addr+o] cmp terminator is true.
      May raise an exception if not found or memory too much imprecise *)
      val get_offset_from: Asm.exp -> Asm.cmp -> Asm.exp -> int -> int -> t -> int

      (** [get_bytes e cmp terminator term_sz length_bound d]
      return the byte sequence b1...bn from address e such that
      n is the minimal index <= length_bound with M[e+i] cmp
      terminator is true in d
      size of terminator is 8-bit width
      raise Not_found if no such sequence exists
      the return integer is the length of the return string wrt to the given terminator *)
      val get_bytes: Asm.exp -> Asm.cmp -> Asm.exp -> int -> int -> t -> int * Bytes.t

      (** [copy d dst arg sz] copy the first sz bits of arg into dst. May raise an exception if dst is undefined in d *)
      val copy: t -> Asm.exp -> Asm.exp -> int -> t

      (** [print d arg sz] prints the first sz bits of arg. May raise an exception if dst is undefined in d *)
      val print: t -> Asm.exp -> int -> t

    (** [copy_hex d dst arg sz is_hex pad_char pad_left word_sz] copy the first sz bits of arg into dst. May raise an exception if dst is undefined in d or arg cannot be concretised; If is_hex is true then letters are capitalized ; pad_char is the character to pad if sz <> !Config.operand_sz / 8 ; padding is done on the left if pad_left is true otherwise it is padded on the right
number of copied bytes is returned *)
      val copy_hex: t -> Asm.exp -> Asm.exp -> int -> bool -> (char * bool) option -> int -> t * int

      val copy_int: t -> Asm.exp -> Asm.exp -> int -> bool -> (char * bool) option -> int -> t * int

        (** [print_hex d arg sz is_hex pad_char pad_left word_sz] copy the first sz bits of arg into stdout. May raise an exception if dst is undefined in d or arg cannot be concretised; If is_hex is true then letters are capitalized ; pad_char is the character to pad if sz <> !Config.operand_sz / 8 ; padding is done on the left if pad_left is true otherwise it is padded on the right. Returns also the number of printed bytes *)
      val print_hex: t -> Asm.exp -> int -> bool -> (char * bool) option -> int -> t * int

      val print_int: t -> Asm.exp -> int -> bool -> (char * bool) option -> int -> t * int
        
    (** [copy_until d dst arg term term_sz bound with_exception pad_options] copy the bits of arg into address dst until the first occurence of term is found into arg. This occurence may be at most at address [arg+bound] raise an exception if the with_exception=true and upper bound is exceeded of dst is undefined in d
    it returns also the number of copied bits. If the length to copy is shorter than the specified bound and pad_options is Some (pad_char, pad_left) then it is left padded with pad_char if pad_left=true itherwise it is right padded *)
      val copy_until: t -> Asm.exp -> Asm.exp -> Asm.exp -> int -> int -> bool -> (char * bool) option -> int * t

    (** [print_until d arg term term_sz bound with_exception pad_options] print the bits of arg until the first occurence of term is found into arg. This occurence may be at most at address [arg+bound] raise an exception if the with_exception=true and upper bound is exceeded of dst is undefined in d
    it returns also the number of copied bits. If the length to copy is shorter than the specified bound and pad_options is Some (pad_char, pad_left) then it is left padded with pad_char if pad_left=true itherwise it is right padded *)
      val print_until: t -> Asm.exp -> Asm.exp -> int -> int -> bool -> (char * bool) option -> int * t

      (** [copy_chars d dst src nb pad_options] copy from src into dst until nb bytes are copied or null byte is found. If it found before nb bytes
      are copied then if pad_options = Some (pad_char, pad_left) it is padded with the char pad_char on the left if pad_left = true otherwise on the right *)
      val copy_chars: t -> Asm.exp -> Asm.exp -> int -> (char * bool) option -> t

    (** [print_chars d src nb pad_options]
      print src until nb bytes are copied or null byte is found. If it found before nb bytes
      are copied then if pad_options = Some (pad_char, pad_left) it is padded with the char pad_char on the left if pad_left = true otherwise on the right *)
      val print_chars: t -> Asm.exp -> int -> (char * bool) option -> t * int

      (** [copy_register r dst src] returns dst with value of register r being replaced by its value in src *)
      val copy_register: Register.t -> t -> t -> t

    (** [allocate_on_heap d id] allocate the id heap chunk into d *)
      val allocate_on_heap: t -> Data.Address.heap_id_t -> t

    (** [deallocate d a] allocate the heap memory chunk at address a *)
      val deallocate: t -> Data.Address.heap_id_t -> t

      (** [deallocate d addrs] weake allocate the heap memory chunks at addresses addrs *)
      val weak_deallocate: t -> Data.Address.heap_id_t list -> t

                                                                 (** return the taint of the given left value *)
        val get_taint: Asm.lval -> t -> Taint.t
    end

