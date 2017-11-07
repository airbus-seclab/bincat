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

let reloc_external_addr = ref Z.zero

let make_mapped_mem () =
  let entrypoint = Data.Address.global_of_int !Config.ep (* elf.hdr.e_entry *) in
  let mapped_file = map_file !Config.binary in
  let elf = Elf_core.to_elf mapped_file in
  if L.log_debug2 () then
    begin
      L.debug2(fun p -> p "HDR: %s" (hdr_to_string elf.hdr));
      List.iter (fun ph -> L.debug2(fun p -> p "PH: %s" (ph_to_string ph))) elf.ph;
      List.iter (fun sh -> L.debug2(fun p -> p "SH: %s" (sh_to_string sh))) elf.sh;
      List.iter (fun rel -> L.debug2(fun p -> p "REL: %s" (rel_to_string rel))) elf.rel;
      List.iter (fun rela -> L.debug2(fun p -> p "RELA: %s" (rela_to_string rela))) elf.rela;
      List.iter (fun dyn -> L.debug2(fun p -> p "DYNAMIC: %s" (dynamic_to_string dyn))) elf.dynamic;
      List.iter (fun sym -> L.debug2(fun p -> p "SYMTAB: %s" (sym_to_string sym))) elf.symtab;
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
  reloc_external_addr := max_addr;

  let jump_slot_reloc sym offset _addend =
    let sym_name = sym.Elf_core.p_st_name in
    let addr = offset in
    let value = !reloc_external_addr in
    L.debug (fun p -> p "REL JUMP_SLOT: write %08x at %08x to relocate %s"
      (Z.to_int value) (Z.to_int addr) sym_name);
    patch_elf elf mapped_file addr value;
    Hashtbl.replace Config.import_tbl !reloc_external_addr ("all", sym_name) ;
    reloc_external_addr := Z.add !reloc_external_addr  (Z.of_int (!Config.address_sz/8)) in

  let glob_dat_reloc sym offset addend =
    let sym_name = sym.Elf_core.p_st_name in
    let addr = offset in
    let sym_value = sym.Elf_core.st_value in
    let value =
      if sym_value = Z.zero then
        begin
          let value = !reloc_external_addr in
          Hashtbl.replace Config.import_tbl !reloc_external_addr ("all", sym_name);
          reloc_external_addr := Z.add !reloc_external_addr  (Z.of_int (!Config.address_sz/8));
          value
        end
      else Z.(sym_value + addend) in
    L.debug (fun p -> p "REL GLOB_DAT: write %08x at %08x to relocate %s"
      (Z.to_int value) (Z.to_int offset) sym_name);
    patch_elf elf mapped_file addr value in

  let get_reloc_func = function
    | R_ARM_JUMP_SLOT | R_386_JUMP_SLOT | R_AARCH64_JUMP_SLOT -> jump_slot_reloc
    | R_ARM_GLOB_DAT | R_386_GLOB_DAT | R_AARCH64_GLOB_DAT -> glob_dat_reloc
    | R_386_RELATIVE -> (fun _ _ _ -> ())
    | rt -> L.abort (fun p -> p "Unsupported relocation type [%s]" (reloc_type_to_string rt)) in

  (* Relocate REL entries *)
  List.iter (fun (rel:e_rel_t) ->
    let reloc_fun = get_reloc_func rel.r_type in
    reloc_fun  rel.p_r_sym rel.r_offset Z.zero
  ) elf.rel;

  (* Relocate RELA entries *)
  List.iter (fun (rela:e_rela_t) ->
    let reloc_fun = get_reloc_func rela.r_type in
    reloc_fun  rela.p_r_sym rela.r_offset rela.r_addend
  ) elf.rela;

  let reloc_sec = {
    virt_addr = Data.Address.global_of_int max_addr ;
    virt_addr_end = Data.Address.global_of_int !reloc_external_addr ;
    virt_size = Z.(!reloc_external_addr - max_addr) ;
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
