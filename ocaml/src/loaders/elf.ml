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

(* loader for ELF binaries *)


open Mapped_mem
open Elf_core

module L = Log.Make(struct let name = "elf" end)

let make_mapped_mem () =
  let entrypoint = Data.Address.global_of_int !Config.ep (* elf.hdr.e_entry *) in
  let mapped_file = map_file !Config.binary in
  let elf = Elf_core.to_elf mapped_file in
  if L.log_debug () then
    begin
      L.debug(fun p -> p "HDR: %s" (hdr_to_string elf.hdr));
      List.iter (fun ph -> L.debug(fun p -> p "PH: %s" (ph_to_string ph))) elf.ph;
      List.iter (fun sh -> L.debug(fun p -> p "SH: %s" (sh_to_string sh))) elf.sh;
      List.iter (fun rel -> L.debug(fun p -> p "REL: %s" (rel_to_string rel))) elf.rel;
      List.iter (fun rela -> L.debug(fun p -> p "RELA: %s" (rela_to_string rela))) elf.rela;
      List.iter (fun dyn -> L.debug(fun p -> p "DYNAMIC: %s" (dynamic_to_string dyn))) elf.dynamic;
      List.iter (fun sym -> L.debug(fun p -> p "SYMTAB: %s" (sym_to_string sym))) elf.symtab;
    end;
  let rec sections_from_ph phlist =
    match phlist with
    | [] -> []
    | ph :: tail ->
       match ph.p_type with
       | PT_LOAD ->
          let section = {
            virt_addr = Data.Address.global_of_int ph.p_vaddr ;
            virt_addr_end = Data.Address.global_of_int (Z.add ph.p_vaddr ph.p_memsz) ;
            virt_size = ph.p_memsz ;
            raw_addr = ph.p_offset ;
            raw_addr_end = Z.add ph.p_offset ph.p_filesz ;
            raw_size = ph.p_filesz ;
            name = Elf_core.p_type_to_string ph.p_type ;
          } in
          L.debug(fun p -> p "ELF loading: %s" (section_to_string section));
          section :: (sections_from_ph tail)
       | _ -> sections_from_ph tail in
  let sections = sections_from_ph elf.ph in
  let max_addr = List.fold_left (fun mx sec -> Z.max mx (Data.Address.to_int sec.virt_addr_end)) Z.zero sections in
  let reloc_end_addr = List.fold_left (fun addr (rel:e_rel_t) ->
    let sym_name = rel.p_r_sym.Elf_core.p_st_name in
    L.debug (fun p -> p "Relocate %s at %08x ; patch address %08x"
        sym_name (Z.to_int addr) (Z.to_int rel.r_offset)) ;
    patch_rel mapped_file rel addr elf ;
    Hashtbl.replace Config.import_tbl addr ("all", sym_name) ;
    Z.(addr + ~$4)) max_addr elf.rel in
  let reloc_sec = {
    virt_addr = Data.Address.global_of_int max_addr ;
    virt_addr_end = Data.Address.global_of_int reloc_end_addr ;
    virt_size = Z.(reloc_end_addr - max_addr) ;
    raw_addr = Z.zero ;
    raw_addr_end = Z.zero ;
    raw_size = Z.zero ;
    name = "relocations" ;
  } in
  {
    mapped_file = mapped_file ;
    sections  = sections @ [ reloc_sec ] ;
    entrypoint = entrypoint ;
  }
