(*
    This file is part of BinCAT.
    Copyright 2014-2022 - Airbus

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


let vaddr_to_paddr vaddr sections =
  let sec = try
      List.find
        (fun s ->
          let svaddr = Data.Address.to_int s.virt_addr in
          (Z.leq svaddr vaddr) && (Z.lt vaddr (Z.add svaddr s.raw_size)))
        sections
    with
    | Not_found -> L.abort (fun p -> p "Could not convert vaddr=%08x to file offset"
                                   (Z.to_int vaddr)) in
  Z.(sec.raw_addr + vaddr - (Data.Address.to_int sec.virt_addr))


let patch_elf elf s sections vaddr value =
  let paddr = Z.to_int (vaddr_to_paddr vaddr sections) in
  zenc_word_xword s paddr value elf.hdr.e_ident


let make_mapped_mem filepath entrypoint =
  let mapped_file = map_file filepath in
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
            mapped_file = mapped_file ;
            mapped_file_name = filepath ;
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
  let base_address_from_sections sections =
    match sections with
    | [] -> L.abort (fun p -> p "No loadable section in ELF. Cannot compute base address")
    | head::tail -> List.fold_left (fun m s -> min m (s.virt_addr))  head.virt_addr tail in
  let sections_from_elfobj ()  =
    let stat = Unix.stat !Config.binary in
    let file_length = Z.of_int stat.Unix.st_size in
    [ {
        mapped_file_name = filepath ;
        mapped_file = mapped_file ;
        virt_addr = Data.Address.global_of_int Z.zero;
        virt_addr_end = Data.Address.global_of_int file_length;
        virt_size = file_length ;
        raw_addr = Z.zero ;
        raw_addr_end = file_length ;
        raw_size = file_length ;
        name = Filename.basename !Config.binary
    } ] in
  let sections = if !Config.format = Config.ELFOBJ
                 then sections_from_elfobj ()
                 else sections_from_ph elf.ph in
  let base_address = Data.Address.to_int (base_address_from_sections sections) in
  let max_addr = List.fold_left (fun mx sec -> Z.max mx (Data.Address.to_int sec.virt_addr_end)) Z.zero sections in
  let max_addr' = Hashtbl.fold (fun _k v mx -> Z.max mx v) Config.import_tbl_rev Z.zero in
  let min_addr' = Hashtbl.fold (fun _k v mx -> Z.min mx v) Config.import_tbl_rev max_addr in
  reloc_external_addr := Z.max max_addr (Z.add max_addr' (Z.of_int !Config.address_sz));

  let choose_address_for_import sym_name sym_size =
    try
      Hashtbl.find Config.import_tbl_rev sym_name
    with
    | Not_found ->
       let v = !reloc_external_addr in
       begin
         Hashtbl.replace Config.import_tbl v ("all", sym_name) ;
         reloc_external_addr := Z.add !reloc_external_addr sym_size;
         v
       end in

  let reloc_jump_slot symsize sym offset _addend =
    let sym_name = sym.Elf_core.p_st_name in
    let addr = offset in
    let value = choose_address_for_import sym_name symsize in
    L.debug (fun p -> p "REL JUMP_SLOT: write %s at %s to relocate %s"
      (Log.zaddr_to_string value) (Log.zaddr_to_string addr) sym_name);
    patch_elf elf mapped_file sections addr value in

  let reloc_glob_dat symsize sym offset addend =
    let sym_name = sym.Elf_core.p_st_name in
    let addr = offset in
    let sym_value = sym.Elf_core.st_value in
    let value =
      if sym_value = Z.zero then
        choose_address_for_import sym_name symsize
      else Z.(sym_value + addend) in
    L.debug (fun p -> p "REL GLOB_DAT: write %s at %s to relocate %s"
      (Log.zaddr_to_string value) (Log.zaddr_to_string offset) sym_name);
    patch_elf elf mapped_file sections addr value in

  let reloc_obj symsize sym offset _addend =
    let sym_name = sym.Elf_core.p_st_name in
    let addr = offset in
    let value = choose_address_for_import sym_name symsize in
    L.debug (fun p -> p "REL 32: write %s at %s to relocate %s"
                        (Log.zaddr_to_string value) (Log.zaddr_to_string addr) sym_name);
    patch_elf elf mapped_file sections addr value in

  let reloc_obj_rel symsize sym offset _addend =
    let sym_name = sym.Elf_core.p_st_name in
    let addr = offset in
    let pre_val = choose_address_for_import sym_name symsize in
    let value = Z.(pre_val - offset) in
    L.debug (fun p -> p "RELA 32: write %s at %s to relocate %s"
                        (Log.zaddr_to_string value) (Log.zaddr_to_string addr) sym_name);
    patch_elf elf mapped_file sections addr value in

  let reloc_relative _symsize _sym offset addend =
    let addr = offset in
    let value = Z.add base_address addend in
    L.debug (fun p -> p "RELA RELATIVE: write %s at %s (base address = %s)"
                        (Log.zaddr_to_string value) (Log.zaddr_to_string addr) (Log.zaddr_to_string base_address));
    patch_elf elf mapped_file sections addr value in

  let reloc_copy _symsize sym _offset _addend =
    (* we do not have the lib to copy the value from, so we do not write any value *)
    let sym_name = sym.Elf_core.p_st_name in
    L.analysis (fun p -> p "REL COPY: %s: no lib to copy value from => ignored" sym_name) in

  let get_reloc_func = function
    | R_ARM_JUMP_SLOT | R_386_JUMP_SLOT | R_AARCH64_JUMP_SLOT | R_X86_64_JUMP_SLOT
      -> reloc_jump_slot (Z.of_int (!Config.address_sz/8))
    | R_ARM_GLOB_DAT | R_386_GLOB_DAT | R_AARCH64_GLOB_DAT | R_X86_64_GLOB_DAT
      | R_PPC_GLOB_DAT -> reloc_glob_dat (Z.of_int (!Config.address_sz/8))
    | R_386_TLS_TPOFF
    | R_386_32 -> reloc_obj (Z.of_int (!Config.address_sz))
    | R_386_PC32 -> reloc_obj_rel (Z.of_int (!Config.address_sz))
    | R_386_RELATIVE | R_X86_64_RELATIVE | R_PPC_RELATIVE | R_PPC64_RELATIVE -> reloc_relative Z.zero
    | R_ARM_RELATIVE -> fun _ _ _ -> L.debug(fun p -> p "do nothing")
    | R_PPC_ADDR32 | R_PPC64_ADDR64 -> reloc_obj_rel (Z.of_int (!Config.address_sz))
    | R_PPC_JMP_SLOT | R_PPC64_JMP_SLOT -> reloc_jump_slot (Z.of_int (!Config.address_sz/8))
    | R_386_COPY | R_ARM_COPY | R_X86_64_COPY | R_AARCH64_COPY | R_PPC_COPY
      -> reloc_copy (Z.of_int (!Config.address_sz/8))
    | rt ->
       let reltype = reloc_type_to_string rt in
       begin
         if (!Config.ignore_unknown_relocations)
         then
           begin
             L.analysis (fun p-> p "Ignored unsupported relocation type [%s]" reltype);
             fun _ _ _ -> ()
           end
         else
           L.abort (fun p -> p "Unsupported relocation type [%s]" (reloc_type_to_string rt))
       end in

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
    mapped_file_name = filepath ;
    mapped_file = mapped_file ;
    virt_addr = Data.Address.global_of_int min_addr' ;
    virt_addr_end = Data.Address.global_of_int !reloc_external_addr ;
    virt_size = Z.(!reloc_external_addr - min_addr') ;
    raw_addr = Z.zero ;
    raw_addr_end = Z.zero ;
    raw_size = Z.zero ;
    name = "relocations" ;
  } in
  {
    sections  = sections @ [ reloc_sec ] ;
    entrypoint = entrypoint ;
  }
