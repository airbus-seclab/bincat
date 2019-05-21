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

(* loader for ELF coredumps *)


open Mapped_mem
open Elf_core

module L = Log.Make(struct let name = "elf_coredump" end)


let make_coredump_mapped_mem filepath =
  let mapped_file = map_file filepath in
  let elf = Elf_core.to_elf mapped_file in
  let regs = Elf_core.elf_to_coredump_regs elf in
  Config.registers_from_dump := List.append !Config.registers_from_dump regs ;
  if L.log_debug2 () then
    begin
      L.debug2(fun p -> p "Parsing ELF coredump file [%s]" filepath);
      L.debug2(fun p -> p "HDR: %s" (hdr_to_string elf.hdr));
      List.iter (fun ph -> L.debug2(fun p -> p "PH: %s" (ph_to_string ph))) elf.ph;
      List.iter (fun sh -> L.debug2(fun p -> p "SH: %s" (sh_to_string sh))) elf.sh;
      List.iter (fun rel -> L.debug2(fun p -> p "REL: %s" (rel_to_string rel))) elf.rel;
      List.iter (fun rela -> L.debug2(fun p -> p "RELA: %s" (rela_to_string rela))) elf.rela;
      List.iter (fun dyn -> L.debug2(fun p -> p "DYNAMIC: %s" (dynamic_to_string dyn))) elf.dynamic;
      List.iter (fun sym -> L.debug2(fun p -> p "SYMTAB: %s" (sym_to_string sym))) elf.symtab;
      L.debug2(fun p -> p "Parsing PT_NOTE headers from coredump file [%s]" filepath);
      List.iter (fun note -> L.debug2(fun p -> p "NOTE: %s" (note_to_string note))) elf.notes;
      L.debug2(fun p -> p "Parsing registers from PRSTATUS PT_NOTE header from coredump file [%s]" filepath);
      List.iter (fun (name,(content, _taints)) ->
          L.debug2(fun p -> p "Coredump PRSTATUS: %s=%s"
                              name
                              (match content with
                               | Some Config.Content x -> (Log.zaddr_to_string (snd x))
                               | _ -> "??") ))
        regs;
    end;
  let rec sections_from_ph phlist =
    match phlist with
    | [] -> []
    | ph :: tail ->
       match ph.p_type with
       | PT_LOAD ->
          (* we make sure the section in memory is not bigger than the section on
             disk because, as a coredump, it could hide parts of sections from the
             binary. Exemple of problematic PH coredump entry, on ARM:
             Type   Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
             LOAD   0x001000 0x00010000 0x00000000 0x00000 0x77000 R E 0x1000
             that overloads the executable PH:
             LOAD   0x000000 0x00010000 0x00010000 0x76320 0x76320 R E 0x10000
           *)
          let sec_size = Z.min ph.p_filesz ph.p_memsz in
          let section = {
            mapped_file = mapped_file ;
            mapped_file_name = filepath ;
            virt_addr = Data.Address.global_of_int ph.p_vaddr ;
            virt_addr_end = Data.Address.global_of_int (Z.add ph.p_vaddr sec_size) ;
            virt_size = sec_size ;
            raw_addr = ph.p_offset ;
            raw_addr_end = Z.add ph.p_offset ph.p_filesz ;
            raw_size = ph.p_filesz ;
            name = Elf_core.p_type_to_string ph.p_type ;
          } in
          L.debug(fun p -> p "ELF loading: %s" (section_to_string section));
          section :: (sections_from_ph tail)
       | _ -> sections_from_ph tail in
  let sections = sections_from_ph elf.ph in
  {
    sections  = sections ;
    entrypoint = (Data.Address.global_of_int Z.zero) ;
  }

let rec add_coredumps the_map corelist =
  match corelist with
  | [] -> the_map
  | x :: y ->
     let coremap = make_coredump_mapped_mem x in
     let newmap = {
         entrypoint  = the_map.entrypoint ;
         sections = List.append coremap.sections the_map.sections ;
       } in
     add_coredumps newmap y

