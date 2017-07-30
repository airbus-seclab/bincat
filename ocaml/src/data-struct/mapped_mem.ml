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

(* mapped memory loaded from disk *)

module L = Log.Make(struct let name = "mapped_mem" end)

type array_t =
  ((int, Bigarray.int8_unsigned_elt, Bigarray.c_layout) Bigarray.Array1.t)

type section_t = {
  virt_addr : Data.Address.t ;
  virt_addr_end : Data.Address.t ;
  virt_size : Z.t ;
  raw_addr : Z.t ;
  raw_size : Z.t ;
  raw_addr_end : Z.t ;
  name : string
}

type t = {
  mapped_file : array_t ;
  sections : section_t list ;
  entrypoint : Data.Address.t ;
}

let current_mapping : t option ref = ref None

(* utilities *)

let (--) i j = 
  let rec aux n acc =
    if n < i then acc else aux (n-1) (n :: acc)
  in aux j [] ;;

let string_of_chars chars = 
  let buf = Buffer.create (List.length chars) in
  List.iter (Buffer.add_char buf) chars;
  Buffer.contents buf

(* functions *)

let map_file filename : array_t =
  let bin_fd = Unix.openfile filename [Unix.O_RDONLY] 0 in
  let mapped_file = Bigarray.Array1.map_file
    bin_fd ~pos:Int64.zero Bigarray.int8_unsigned Bigarray.c_layout false (-1) in
  Unix.close bin_fd;
  mapped_file


let is_in_section vaddr section =
  (Data.Address.compare vaddr section.virt_addr >= 0) &&
    (Data.Address.compare vaddr section.virt_addr_end < 0)

(** find the first section in a section list that contains vaddr *)
let find_section section_list vaddr =
  try
    List.find (fun section_info -> is_in_section vaddr section_info) section_list
  with 
  | Not_found as e -> L.exc e (fun p -> p "vaddr=%s" (Data.Address.to_string vaddr)); raise e


(** return Some byte from mapped mem at vaddr or None if it is out of the file and raises Not_found if not in any section*)
let read mapped_mem vaddr =
  let section = find_section mapped_mem.sections vaddr in
  let offset = Data.Address.sub vaddr section.virt_addr in
  let file_offset = Z.add section.raw_addr offset in
  (* check if we're out of the section's raw data *)
  if Z.compare file_offset section.raw_addr_end >= 0 then
    None
  else
    Some (Data.Word.of_int
            (Z.of_int
               (Bigarray.Array1.get mapped_mem.mapped_file (Z.to_int file_offset)))
            8)

let string_from_addr mapped_mem vaddr len =
  let sec = find_section mapped_mem.sections vaddr in
  let raddr = Z.to_int (Z.add sec.raw_addr (Data.Address.sub vaddr sec.virt_addr)) in
  L.debug (fun p -> p "Reading at vaddr=%s paddr=%08x len=%i" (Data.Address.to_string vaddr) raddr len);
  if raddr >= (Z.to_int sec.raw_addr_end) then
    None
  else
    let last_raddr = (min (raddr + len) (Z.to_int sec.raw_addr_end))-1 in
    let addrs = raddr -- (last_raddr) in
    let bytes = List.map
      (fun addr -> Char.chr (Bigarray.Array1.get mapped_mem.mapped_file addr))
      addrs in
    Some (string_of_chars bytes)

