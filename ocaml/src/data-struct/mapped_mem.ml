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
  mapped_file_name : string ;
  mapped_file : array_t ;
  name : string ;
  virt_addr : Data.Address.t ;
  virt_addr_end : Data.Address.t ;
  virt_size : Z.t ;
  raw_addr : Z.t ;
  raw_size : Z.t ;
  raw_addr_end : Z.t ;
}

type t = {
  sections : section_t list ;
  entrypoint : Data.Address.t ;
}

let current_mapping : t option ref = ref None


(* functions *)

let map_file filename : array_t =
  let bin_fd = Unix.openfile filename [Unix.O_RDONLY] 0 in
#if OCAML_VERSION < (4, 06, 0)
  let mapped_file = Bigarray.Array1.map_file
    bin_fd ~pos:Int64.zero Bigarray.int8_unsigned Bigarray.c_layout false (-1) in
#else
  let mapped_file = Bigarray.array1_of_genarray (Unix.map_file
                       bin_fd ~pos:Int64.zero Bigarray.int8_unsigned Bigarray.c_layout false [|-1|]) in
#endif
  Unix.close bin_fd;
  L.info2 (fun p -> p "Mapped file [%s]. Array size=%i" filename (Bigarray.Array1.dim mapped_file));
  mapped_file

let section_to_string section =
  (Printf.sprintf "%-25s: vaddr=%s-%s <- paddr=%s-%s"
     ((Filename.basename section.mapped_file_name) ^ "." ^ section.name)
     (Data.Address.to_string section.virt_addr)
     (Data.Address.to_string section.virt_addr_end)
     (Z.format "%08x" section.raw_addr) (Z.format "%08x" section.raw_addr_end))

let is_in_section vaddr section =
  (Data.Address.compare vaddr section.virt_addr >= 0) &&
    (Data.Address.compare vaddr section.virt_addr_end < 0)

(** find the first section in a section list that contains vaddr *)
let find_section section_list vaddr =
  try
    List.find (fun section_info -> is_in_section vaddr section_info) section_list
  with
  | Not_found -> raise (Exceptions.Error
                          (Printf.sprintf "No mapped section at vaddr=%s"
                                          (Data.Address.to_string vaddr)))

(** return Some byte from mapped mem at vaddr or None if it is out of the file and raises Not_found if not in any section*)
let read mapped_mem vaddr =
  L.debug2 (fun p -> p "Reading byte at vaddr=%s" (Data.Address.to_string vaddr));
  let section = find_section mapped_mem.sections vaddr in
  let offset = Data.Address.sub vaddr section.virt_addr in
  let file_offset = Z.to_int (Z.add section.raw_addr offset) in
  L.debug2 (fun p -> p "Section found [%s:%s], reading at paddr=%08x"
                       section.mapped_file_name section.name file_offset);
  (* check if we're out of the section's raw data *)
  let byte = if file_offset >= (Z.to_int section.raw_addr_end) then
      begin
        L.debug2 (fun p -> p "paddr=%08x is out of the section on disk" (file_offset));
        0
      end
    else
      Bigarray.Array1.get section.mapped_file file_offset in
  L.debug(fun p -> p "read byte %02x" byte);
  Data.Word.of_int (Z.of_int byte) 8


let string_from_addr mapped_mem vaddr len =
  L.debug2 (fun p -> p "Reading string at vaddr=%s len=%i" (Data.Address.to_string vaddr) len);
  let sec = find_section mapped_mem.sections vaddr in
  let raddr = Z.to_int (Z.add sec.raw_addr (Data.Address.sub vaddr sec.virt_addr)) in
  L.debug2 (fun p -> p "Section found [%s:%s], reading at paddr=%08x"
                       sec.mapped_file_name sec.name raddr);
  if raddr >= (Z.to_int sec.raw_addr_end) then
    begin
      L.debug2 (fun p -> p "paddr=%08x is out of the section on disk" raddr);
      None
    end
  else
    let last_raddr = (min (raddr + len) (Z.to_int sec.raw_addr_end))-1 in
    let addrs = Misc.seq raddr last_raddr in
    let bytes = List.map
      (fun addr -> Char.chr (Bigarray.Array1.get sec.mapped_file addr))
      addrs in
    L.debug (fun p -> p "read %i bytes at %s: [%s]"
      len (Data.Address.to_string vaddr)
      (String.concat " " (List.map (fun b -> Printf.sprintf "%02x" (Char.code b)) bytes)));
    Some (Misc.string_of_chars bytes)

